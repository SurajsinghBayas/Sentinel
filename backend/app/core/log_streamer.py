"""
WebSocket Log Stream Manager
Manages real-time log streaming connections and broadcasts
ANBU Sentinel
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set

from fastapi import WebSocket
from app.models.schemas import WSMessage


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}  # client_id -> ws

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        client_id = str(uuid.uuid4())
        self.active_connections[client_id] = websocket
        return client_id

    def disconnect(self, client_id: str):
        self.active_connections.pop(client_id, None)

    async def send_to_client(self, client_id: str, message: dict):
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(message, default=str))
            except Exception:
                self.disconnect(client_id)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        disconnected = []
        for client_id, ws in self.active_connections.items():
            try:
                await ws.send_text(json.dumps(message, default=str))
            except Exception:
                disconnected.append(client_id)
        for client_id in disconnected:
            self.disconnect(client_id)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


# Singleton manager
manager = ConnectionManager()


async def broadcast_log_line(raw_line: str, session_id: str, severity: str = "NORMAL"):
    """Broadcast a new log line to all connected WebSocket clients."""
    message = WSMessage(
        type="log_line",
        payload={
            "raw_line": raw_line,
            "session_id": session_id,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    await manager.broadcast(message.model_dump())


async def broadcast_threat(threat_data: dict):
    """Broadcast a newly detected threat to all connected clients."""
    message = WSMessage(
        type="threat_detected",
        payload=threat_data,
    )
    await manager.broadcast(message.model_dump())


async def simulate_log_stream(
    websocket: WebSocket,
    log_path: str | None = None,
    content: str | None = None,
    filename: str | None = None,
    delay: float = 0.1,
):
    """
    Stream a log file line-by-line over WebSocket.
    Accepts either:
      - log_path: path to a file on disk (sample files)
      - content + filename: in-memory text (user-uploaded files)
    """
    await websocket.accept()
    session_id = str(uuid.uuid4())

    # Resolve content
    if content is None:
        if not log_path:
            await websocket.send_text(json.dumps({"type": "error", "payload": {"message": "No log source provided"}}))
            await websocket.close()
            return
        path = Path(log_path)
        if not path.exists():
            await websocket.send_text(json.dumps({"type": "error", "payload": {"message": f"Log file not found: {log_path}"}}))
            await websocket.close()
            return
        content  = path.read_text()
        filename = filename or path.name

    lines = content.splitlines()

    # Send start event
    await websocket.send_text(json.dumps({
        "type": "stream_start",
        "payload": {"session_id": session_id, "total_lines": len(lines), "file": filename}
    }))

    # Stream lines
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            await websocket.send_text(json.dumps({
                "type": "log_line",
                "payload": {
                    "raw_line": line,
                    "session_id": session_id,
                    "line_number": i + 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            }))
            await asyncio.sleep(delay)
        except Exception:
            break

    # Run detection on full batch
    from app.core.parser import parse_log_content
    from app.core.detector import engine
    batch   = parse_log_content(content, session_id=session_id)
    results = engine.analyze(batch.entries, session_id)

    # Broadcast individual threat events to this WebSocket client
    for threat in results.threats:
        try:
            await websocket.send_text(json.dumps({
                "type": "threat_detected",
                "payload": threat.model_dump(),
            }, default=str))
        except Exception:
            pass

    # Persist to DB + in-memory store (best-effort)
    try:
        from app.db.database import AsyncSessionLocal
        from app.db import crud
        from app.api.logs import DETECTIONS_STORE, SESSION_STORE
        async with AsyncSessionLocal() as db:
            # Save the log session so it appears in /logs/sessions
            await crud.create_session(
                db,
                session_id=session_id,
                user_id="stream",          # anonymous stream session
                filename=filename or "stream",
                log_format=str(batch.log_format),
                total_lines=len(lines),
                parsed_count=batch.parsed_count,
                error_count=batch.error_count,
                threats_found=results.threats_found,
            )
            # Save each threat + push to in-memory store
            for threat in results.threats:
                await crud.save_threat(db, threat)
                if not any(t.id == threat.id for t in DETECTIONS_STORE):
                    DETECTIONS_STORE.append(threat)
        # Update SESSION_STORE mirror
        SESSION_STORE[session_id] = {
            "session_id":   session_id,
            "filename":     filename or "stream",
            "uploaded_at":  datetime.now(timezone.utc).isoformat(),
            "total_lines":  len(lines),
            "parsed_count": batch.parsed_count,
            "threats_found": results.threats_found,
            "log_format":   str(batch.log_format),
        }
    except Exception as db_err:
        print(f"[streamer] DB persist error: {db_err}")

    # Send completion marker
    await websocket.send_text(json.dumps({
        "type": "stream_complete",
        "payload": {
            "session_id":    session_id,
            "total_lines":   len(lines),
            "threats_found": results.threats_found,
            "filename":      filename or "stream",
        }
    }, default=str))

    # Small delay to ensure the last message is flushed to the client before closing
    await asyncio.sleep(0.5)
    await websocket.close(code=1000, reason="stream_complete")
