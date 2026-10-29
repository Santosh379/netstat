from typing import Optional
from pydantic import BaseModel

class SystemStatus(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    backend_available: bool = True
    capture_mode: str = "STOPPED"
    live_capture_supported: bool = False
    npcap_available: bool = False
    has_admin_privileges: bool = False
    active_interface: str = "Synthetic"
    is_monitoring: bool = False
    is_synthetic: bool = True
    message: str = "NetScope AI Engine active"
    capture_error: Optional[str] = None
    packets_captured: int = 0
    packets_processed: int = 0
    flows_count: int = 0
    ml_inferences_count: int = 0
    elapsed_seconds: float = 0.0
    ml_enabled: bool = True
    ml_model_info: Optional[dict] = None

class InterfaceInfo(BaseModel):
    name: str
    description: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    is_up: bool = True
    speed_mbps: Optional[int] = None

class SystemSettings(BaseModel):
    interface: str = "Synthetic Mode"
    packet_capture_enabled: bool = True
    dark_mode: bool = True
    synthetic_mode: bool = True
    ml_enabled: bool = True

class SystemSettingsUpdate(BaseModel):
    interface: Optional[str] = None
    packet_capture_enabled: Optional[bool] = None
    dark_mode: Optional[bool] = None
    synthetic_mode: Optional[bool] = None
    ml_enabled: Optional[bool] = None
