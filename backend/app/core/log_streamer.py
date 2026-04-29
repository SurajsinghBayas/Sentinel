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


async def simulate_log_stream(websocket: WebSocket, log_file_path: str, delay: float = 0.1):
    """Stream a sample log file line-by-line to simulate real-time log ingestion."""
    # Accept the WebSocket connection first
    await websocket.accept()

    session_id = str(uuid.uuid4())
    path = Path(log_file_path)

    if not path.exists():
        await websocket.send_text(json.dumps({
            "type": "error",
            "payload": {"message": f"Log file not found: {log_file_path}"}
        }))
        await websocket.close()
        return

    # Import here to avoid circular imports
    from app.core.parser import parse_log_content, LogFormat
    from app.core.detector import engine

    lines = path.read_text().splitlines()
    severity_map = {200: "NORMAL", 201: "NORMAL", 301: "NORMAL", 302: "NORMAL",
                    400: "LOW", 401: "MEDIUM", 403: "MEDIUM", 404: "LOW",
                    500: "HIGH", 503: "HIGH"}

    # Send start message
    await websocket.send_text(json.dumps({
        "type": "stream_start",
        "payload": {"session_id": session_id, "total_lines": len(lines), "file": path.name}
    }))

    batch_entries = []
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
    batch = parse_log_content("\n".join(lines), session_id=session_id)
    results = engine.analyze(batch.entries, session_id)

    # Send threat summary
    await websocket.send_text(json.dumps({
        "type": "stream_complete",
        "payload": {
            "session_id": session_id,
            "total_lines": len(lines),
            "threats_found": results.threats_found,
            "threats": [t.model_dump() for t in results.threats],
        }
    }, default=str))
