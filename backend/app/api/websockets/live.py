import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ...core.state import global_state
from ...ingestion.sniffer import sniffer_manager

router = APIRouter(tags=["WebSockets"])

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._loop: asyncio.AbstractEventLoop = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def broadcast_threadsafe(self, message: dict):
        """Called from background threads (sniffer_manager) to broadcast to WebSockets."""
        if not self.active_connections or not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)

    async def broadcast(self, message: dict):
        dead_connections = []
        text_data = json.dumps(message)
        for connection in self.active_connections:
            try:
                await connection.send_text(text_data)
            except Exception:
                dead_connections.append(connection)

        for dc in dead_connections:
            self.disconnect(dc)

ws_manager = ConnectionManager()
sniffer_manager.set_broadcast_callback(ws_manager.broadcast_threadsafe)

@router.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial status & stats
        initial_stats = global_state.get_capture_stats()
        await websocket.send_text(json.dumps({
            "type": "stats",
            "data": initial_stats.model_dump()
        }))

        # Send recent buffered packets
        for pkt in list(global_state.packet_buffer)[-20:]:
            await websocket.send_text(json.dumps({
                "type": "packet",
                "data": pkt.model_dump()
            }))

        # Keep alive loop receiving client pings
        while True:
            # Check for client messages (e.g. ping)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
