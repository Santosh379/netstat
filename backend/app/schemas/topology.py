from typing import Literal, Optional
from pydantic import BaseModel

RoleType = Literal["Router", "Server", "Workstation", "Attacker", "IoT", "Gateway"]
NodeStatusType = Literal["Normal", "Warning", "Compromised", "Critical"]
RiskLevelType = Literal["Low", "Medium", "High", "Critical"]
LinkStatusType = Literal["normal", "high-traffic", "attack-path"]

class TopologyNode(BaseModel):
    id: str
    ip: str
    hostname: str
    role: RoleType = "Workstation"
    status: NodeStatusType = "Normal"
    classification: Optional[str] = "Normal Observed Host"
    x: int = 400
    y: int = 250
    packetsIn: int = 0
    packetsOut: int = 0
    bytesIn: int = 0
    bytesOut: int = 0
    openPorts: list[int] = []
    protocols: list[str] = []
    alertsCount: int = 0
    associatedAlerts: list[str] = []
    riskLevel: RiskLevelType = "Low"
    mac: str = "00:00:00:00:00:00"
    os: str = "Unknown Host"
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None

class TopologyLink(BaseModel):
    id: Optional[str] = None
    source: str
    target: str
    status: LinkStatusType = "normal"
    protocol: str = "TCP"
    protocols: list[str] = []
    ports: list[int] = []
    packetCount: int = 0
    byteCount: int = 0
    flowCount: int = 1
    evidence: list[str] = []

class TopologyResponse(BaseModel):
    dataSource: str = "PCAP"
    captureName: Optional[str] = None
    totalObservedHosts: int = 0
    totalActiveLinks: int = 0
    nodes: list[TopologyNode]
    links: list[TopologyLink]
