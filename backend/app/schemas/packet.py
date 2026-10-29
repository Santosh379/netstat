from typing import Optional, Literal
from pydantic import BaseModel

class LivePacket(BaseModel):
    id: str
    timestamp: str
    sourceIp: str
    destinationIp: str
    protocol: Literal["TCP", "UDP", "ICMP", "ARP", "DNS", "TLS"]
    sourcePort: int = 0
    destinationPort: int = 0
    size: int
    flags: list[str] = []
    info: str
    isSuspicious: Optional[bool] = False
    hexPreview: Optional[str] = None
    isSynthetic: Optional[bool] = False

class CaptureStats(BaseModel):
    captureMode: Literal["REAL", "SYNTHETIC", "STOPPED"] = "STOPPED"
    interfaceName: str
    ipAddress: str
    packetsPerSec: int
    bytesPerSec: str
    packetsCaptured: int = 0
    packetsProcessed: int = 0
    totalPackets: int = 0  # Mirrors packetsProcessed for backwards compatibility
    flowsCount: int = 0
    mlInferencesCount: int = 0
    droppedPackets: int = 0
    startTime: Optional[str] = None
    elapsedSeconds: float = 0.0
    promiscuousMode: bool = False
    activeConnections: int = 0
    captureError: Optional[str] = None
    npcapAvailable: bool = False
    hasAdminPrivileges: bool = False
