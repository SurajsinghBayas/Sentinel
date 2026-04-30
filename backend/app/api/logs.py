"""
Logs API — Upload, Stream, Simulate, Narrate
Now persisted to Neon PostgreSQL
ANBU Sentinel
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, UploadFile, File, WebSocket, WebSocketDisconnect, Depends, HTTPException, Form, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user, decode_token
from app.core.parser import parse_log_content, LogFormat
from app.core.detector import engine
from app.core.log_streamer import manager, simulate_log_stream, broadcast_threat
from app.core.narrator import narrate_threat
from app.models.schemas import ParsedLogBatch, DetectionResult, ThreatEvent
from app.db.database import get_db
from app.db import crud

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])

# In-memory mirrors (for WebSocket broadcasts + fast reads during a session)
SESSION_STORE: Dict[str, Dict[str, Any]] = {}
DETECTIONS_STORE: List[ThreatEvent] = []

# Temporary store for uploaded files pending streaming (key → content string)
UPLOAD_STREAM_STORE: Dict[str, Dict[str, str]] = {}

SAMPLE_LOGS_DIR = Path(__file__).parent.parent.parent.parent / "sample_logs"


@router.post("/upload")
async def upload_log(
    request: Request,
    file: UploadFile = File(...),
    log_format: str = Form(default="auto"),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload a log file for parsing and threat detection."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content = await file.read()
    try:
        text_content = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text")

    session_id = str(uuid.uuid4())
    fmt = LogFormat(log_format) if log_format in LogFormat.__members__.values() else LogFormat.AUTO

    # Parse
    batch = parse_log_content(text_content, fmt=fmt, session_id=session_id)

    # Detect
    results = engine.analyze(batch.entries, session_id)

    # Persist session to DB
    await crud.create_session(
        db,
        session_id=session_id,
        user_id=current_user["user_id"],
        filename=file.filename,
        log_format=batch.log_format,
        total_lines=batch.total_lines,
        parsed_count=batch.parsed_count,
        error_count=batch.error_count,
        threats_found=results.threats_found,
        file_size_bytes=len(content),
    )

    # Persist threats + broadcast
    for threat in results.threats:
        DETECTIONS_STORE.append(threat)
        await crud.save_threat(db, threat)
        await broadcast_threat(threat.model_dump())

    # Audit
    await crud.log_action(
        db, action="upload_log",
        user_id=current_user["user_id"],
        resource=file.filename,
        detail={"session_id": session_id, "threats_found": results.threats_found},
        ip_address=request.client.host if request.client else None,
    )

    # Keep in-memory mirror
    SESSION_STORE[session_id] = {
        "session_id": session_id,
        "filename": file.filename,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": current_user["user_id"],
        "total_lines": batch.total_lines,
        "parsed_count": batch.parsed_count,
        "log_format": batch.log_format,
        "threats_found": results.threats_found,
    }

    return {
        "session_id": session_id,
        "filename": file.filename,
        "parsed_count": batch.parsed_count,
        "total_lines": batch.total_lines,
        "error_count": batch.error_count,
        "log_format": batch.log_format,
        "threats_found": results.threats_found,
        "threats": [t.model_dump() for t in results.threats],
    }


@router.get("/sessions")
async def list_sessions(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all log sessions — DB (uploaded) + in-memory (live stream)."""
    # DB sessions for this user
    rows = await crud.get_sessions_by_user(db, current_user["user_id"])
    db_ids = {r.id for r in rows}

    result = [
        {
            "session_id":  r.id,
            "filename":    r.filename,
            "log_format":  r.log_format,
            "total_lines": r.total_lines,
            "parsed_count": r.parsed_count,
            "threats_found": r.threats_found,
            "uploaded_at": r.uploaded_at.isoformat(),
            "source":      "upload",
        }
        for r in rows
    ]

    # In-memory live stream sessions not yet scoped to this user
    for sid, s in SESSION_STORE.items():
        if sid not in db_ids:
            result.append({
                "session_id":  sid,
                "filename":    s.get("filename", "stream"),
                "log_format":  s.get("log_format", "auto"),
                "total_lines": s.get("total_lines", 0),
                "parsed_count": s.get("parsed_count", 0),
                "threats_found": s.get("threats_found", 0),
                "uploaded_at": s.get("uploaded_at", ""),
                "source":      "stream",
            })

    # Sort newest first
    result.sort(key=lambda x: x.get("uploaded_at") or "", reverse=True)
    return result


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    session = SESSION_STORE.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/sample-files")
async def list_sample_files(current_user: dict = Depends(get_current_user)):
    """List available sample log files."""
    if not SAMPLE_LOGS_DIR.exists():
        return []
    return [
        {"name": f.name, "size": f.stat().st_size, "path": str(f)}
        for f in sorted(SAMPLE_LOGS_DIR.iterdir())
        if f.is_file() and not f.name.startswith(".")
    ]


@router.websocket("/stream")
async def websocket_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time log broadcast reception."""
    client_id = await manager.connect(websocket)
    try:
        await websocket.send_text(json.dumps({
            "type": "connected",
            "payload": {"client_id": client_id, "message": "Connected to ANBU Sentinel log stream"}
        }))
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "payload": {}}))
    except WebSocketDisconnect:
        manager.disconnect(client_id)


@router.post("/upload-stream")
async def upload_for_streaming(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload a log file to be streamed via WebSocket.
    Returns a session_key that is used as the WS path:
      ws://host/api/logs/simulate/__upload__{session_key}
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Cannot decode file as text")

    key = str(uuid.uuid4())
    UPLOAD_STREAM_STORE[key] = {
        "filename": file.filename,
        "content":  text,
        "user_id":  current_user["user_id"],
    }
    return {"session_key": key, "filename": file.filename, "lines": len(text.splitlines())}


@router.websocket("/simulate/{log_filename:path}")
async def websocket_simulate(
    websocket: WebSocket,
    log_filename: str,
    speed: float = 0.08,
    token: Optional[str] = None,         # JWT passed as ?token=... (WS can't send headers)
):
    """
    WebSocket: stream a log file line-by-line.
    - Regular filename  → served from SAMPLE_LOGS_DIR
    - __upload__{key}   → served from UPLOAD_STREAM_STORE (user-uploaded file)
    Pass ?token=<access_token> so the stream session is linked to the real user.
    """
    # Resolve user_id from token (best-effort — stream still works without it)
    user_id: Optional[str] = None
    if token:
        try:
            payload = decode_token(token)
            user_id = payload.get("user_id") or payload.get("sub")
        except Exception:
            pass

    if log_filename.startswith("__upload__"):
        key = log_filename[len("__upload__"):]
        stored = UPLOAD_STREAM_STORE.get(key)
        if not stored:
            await websocket.accept()
            await websocket.send_text(json.dumps({
                "type": "error", "payload": {"message": "Uploaded file not found or expired"}
            }))
            await websocket.close()
            return
        # Prefer user_id from token; fall back to who uploaded the file
        resolved_user = user_id or stored.get("user_id")
        await simulate_log_stream(
            websocket,
            log_path=None,
            content=stored["content"],
            filename=stored["filename"],
            delay=speed,
            user_id=resolved_user,
        )
        UPLOAD_STREAM_STORE.pop(key, None)
    else:
        log_path = SAMPLE_LOGS_DIR / log_filename
        await simulate_log_stream(websocket, str(log_path), delay=speed, user_id=user_id)


@router.post("/narrate/{threat_id}")
async def narrate_threat_endpoint(
    threat_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate AI narration for a specific threat."""
    # Check DB first
    db_threat = await crud.get_threat_by_id(db, threat_id)

    # Also check in-memory store (threats from live stream session)
    mem_threat = next((t for t in DETECTIONS_STORE if t.id == threat_id), None)

    if not db_threat and not mem_threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat = mem_threat
    if not threat and db_threat:
        # Reconstruct pydantic model from DB row for narrator
        from app.models.schemas import AttackType, SeverityLevel
        threat = ThreatEvent(
            id=db_threat.id,
            session_id=db_threat.session_id,
            timestamp=db_threat.timestamp,
            attack_type=AttackType(db_threat.attack_type),
            severity=SeverityLevel(db_threat.severity),
            source_ip=db_threat.source_ip,
            target_path=db_threat.target_path,
            request_count=db_threat.request_count,
            confidence=db_threat.confidence,
            rule_name=db_threat.rule_name,
            evidence=db_threat.evidence or [],
            raw_entries=db_threat.raw_entries or [],
        )

    narration = await narrate_threat(threat)

    # Persist narration to DB
    await crud.update_threat_narration(db, threat_id, narration)

    # Update in-memory copy too
    if mem_threat:
        mem_threat.ai_narration = narration.get("executive_summary")
        mem_threat.mitigation_steps = narration.get("mitigation_steps", [])
        mem_threat.is_narrated = True

    await crud.log_action(db, action="narrate_threat", user_id=current_user["user_id"], resource=threat_id)

    return {"threat_id": threat_id, "narration": narration}


@router.post("/threats/{threat_id}/resolve")
async def resolve_threat(
    threat_id: str,
    notes: str = "",
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a threat as resolved."""
    row = await crud.resolve_threat(db, threat_id, current_user["user_id"], notes)
    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")
    await crud.log_action(db, action="resolve_threat", user_id=current_user["user_id"], resource=threat_id)
    return {"message": "Threat resolved", "threat_id": threat_id}
