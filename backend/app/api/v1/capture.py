from fastapi import APIRouter, Body
from typing import Optional
from ...schemas.packet import CaptureStats, LivePacket
from ...core.state import global_state
from ...ingestion.sniffer import sniffer_manager

router = APIRouter(prefix="/capture", tags=["Capture"])

@router.post("/start")
def start_capture(payload: Optional[dict] = Body(default=None)):
    iface = "Synthetic Mode"
    force_synthetic = False
    if payload:
        iface = payload.get("interface", global_state.active_interface)
        force_synthetic = payload.get("force_synthetic", False)

    return sniffer_manager.start(interface=iface, force_synthetic=force_synthetic)

@router.post("/stop")
def stop_capture():
    return sniffer_manager.stop()

@router.get("/status", response_model=CaptureStats)
def get_capture_status():
    return global_state.get_capture_stats()

@router.get("/packets", response_model=list[LivePacket])
def get_recent_packets():
    return list(global_state.packet_buffer)

@router.delete("/packets")
def clear_packet_buffer():
    global_state.packet_buffer.clear()
    return {"status": "cleared", "count": 0}
