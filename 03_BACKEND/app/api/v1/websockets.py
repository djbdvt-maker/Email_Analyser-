from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import jwt, JWTError
import logging

from app.config import get_settings

router = APIRouter()
logger = logging.getLogger("hopzero.websockets")


class ConnectionManager:
    def __init__(self):
        # org_id -> list of active WebSockets
        self.org_connections: Dict[str, List[WebSocket]] = defaultdict(list)
        self.all_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, org_id: Optional[str] = None):
        await websocket.accept()
        self.all_connections.append(websocket)
        if org_id:
            self.org_connections[org_id].append(websocket)
        logger.info("New WebSocket connection (org_id=%s)", org_id or "unscoped")

    def disconnect(self, websocket: WebSocket, org_id: Optional[str] = None):
        if websocket in self.all_connections:
            self.all_connections.remove(websocket)
        if org_id and websocket in self.org_connections[org_id]:
            self.org_connections[org_id].remove(websocket)
        logger.info("WebSocket disconnected (org_id=%s)", org_id or "unscoped")

    async def broadcast(self, message: dict, organization_id: Optional[str] = None):
        target_connections = (
            list(self.org_connections.get(organization_id, []))
            if organization_id
            else list(self.all_connections)
        )
        dead_connections = []
        for connection in target_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead, organization_id)


manager = ConnectionManager()


async def broadcast_event(event_type: str, data: dict, organization_id: Optional[str] = None):
    """Broadcasts events scoped to the relevant organization to prevent cross-tenant leaks."""
    await manager.broadcast({"event": event_type, **data}, organization_id=organization_id)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    settings = get_settings()
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        org_id = payload.get("org_id") or payload.get("organization_id")
        if not org_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket, org_id=org_id)
    try:
        while True:
            # Keep connection alive; discard or ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, org_id=org_id)
