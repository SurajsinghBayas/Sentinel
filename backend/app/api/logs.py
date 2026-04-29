"""
Logs API — Upload, Stream, Simulate
ANBU Sentinel
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, UploadFile, File, WebSocket, WebSocketDisconnect, Depends, HTTPException, Form
from fastapi.responses import JSONResponse

from app.core.security import get_current_user
from app.core.parser import parse_log_content, LogFormat
from app.core.detector import engine
from app.core.log_streamer import manager, simulate_log_stream, broadcast_threat
from app.core.narrator import narrate_threat
from app.models.schemas import ParsedLogBatch, DetectionResult, ThreatEvent

router = APIRouter(prefix="/logs", tags=["Log Ingestion"])

# In-memory session store
SESSION_STORE: Dict[str, Dict[str, Any]] = {}
DETECTIONS_STORE: List[ThreatEvent] = []

SAMPLE_LOGS_DIR = Path(__file__).parent.parent.parent.parent / "sample_logs"


@router.post("/upload")
async def upload_log(
    file: UploadFile = File(...),
    log_format: str = Form(default="auto"),
    current_user: dict = Depends(get_current_user),
):
    """Upload a log file for parsing and threat detection."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Read file content
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

    # Store threats
    for threat in results.threats:
        DETECTIONS_STORE.append(threat)
        # Broadcast to WebSocket clients
        await broadcast_threat(threat.model_dump())

    # Store session
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
async def list_sessions(current_user: dict = Depends(get_current_user)):
    """List all log upload sessions."""
    return list(SESSION_STORE.values())


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, current_user: dict = Depends(get_current_user)):
    session = SESSION_STORE.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/sample-files")
async def list_sample_files(current_user: dict = Depends(get_current_user)):
    """List available sample log files."""
    if not SAMPLE_LOGS_DIR.exists():
        return []
    files = []
    for f in SAMPLE_LOGS_DIR.iterdir():
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "path": str(f),
            })
    return files


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
            # Keep connection alive, receive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "payload": {}}))
    except WebSocketDisconnect:
        manager.disconnect(client_id)


@router.websocket("/simulate/{log_filename}")
async def websocket_simulate(websocket: WebSocket, log_filename: str, speed: float = 0.08):
    """WebSocket: stream a sample log file line-by-line for demo purposes."""
    log_path = SAMPLE_LOGS_DIR / log_filename
    await simulate_log_stream(websocket, str(log_path), delay=speed)


@router.post("/narrate/{threat_id}")
async def narrate_threat_endpoint(
    threat_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Generate AI narration for a specific threat using AWS Bedrock."""
    threat = next((t for t in DETECTIONS_STORE if t.id == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    narration = await narrate_threat(threat)
    threat.ai_narration = narration.get("executive_summary")
    threat.mitigation_steps = narration.get("mitigation_steps", [])
    threat.is_narrated = True

    return {
        "threat_id": threat_id,
        "narration": narration,
    }
