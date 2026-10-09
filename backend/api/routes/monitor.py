"""AI Shield — Monitor Route (WebSocket stream for live alerts)"""
from fastapi import APIRouter, WebSocket

router = APIRouter()


@router.websocket("/stream")
async def monitor_stream(websocket: WebSocket):
    """
    WebSocket stream for live alert feed.
    Dashboard connects here for real-time detection events.

    Sprint 3 implementation — TwinGuard WebSocket pattern.
    """
    await websocket.accept()
    await websocket.send_json({"status": "connected", "message": "AI Shield monitor active"})
    # TODO Sprint 3: push DetectionResult events as they arrive
    await websocket.close()
