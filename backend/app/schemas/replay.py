from typing import Optional, Literal
from pydantic import BaseModel

class AttackReplayStep(BaseModel):
    id: int
    timestamp: str
    sourceIp: str
    destinationIp: str
    sourcePort: Optional[int] = None
    port: int = 0
    service: str = "Unknown"
    protocol: str = "TCP"
    flags: str = ""
    packetSize: int = 64
    flowId: Optional[str] = None
    relatedAlertId: Optional[str] = None
    detectionSource: Optional[str] = None
    isThreatTrigger: bool = False
    triggerReason: Optional[str] = None
    eventType: str = "RAW_PACKET"
    status: str = "SYN_SENT"
    detail: str = ""
    evidence: Optional[str] = None

class AttackScenario(BaseModel):
    id: str
    name: str
    attackType: str
    sourceIp: str
    targetIp: str
    duration: str
    captureId: Optional[str] = None
    captureName: Optional[str] = None
    totalPacketsInCapture: int = 0
    incidentPacketsCount: int = 0
    packetCount: int
    portsScanned: int
    anomalyScore: float
    description: str
    timeWindow: str = ""
    confidence: Optional[str] = None
    isSummary: bool = False
    triggerStepIndex: Optional[int] = None
    knownFacts: list[str] = []
    uncertainties: list[str] = []
    steps: list[AttackReplayStep]
