from typing import Optional, Literal
from pydantic import BaseModel

SeverityType = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
AttackType = Literal["Port Scan", "SYN Flood", "ICMP Flood", "ARP Spoofing", "Brute Force", "Network Anomaly"]
AlertStatusType = Literal["Active", "Investigating", "Resolved"]
DetectionSourceType = Literal["RULE_ENGINE", "ML_ANOMALY"]

class AlertEvidence(BaseModel):
    packetsCount: int
    responseCount: int
    durationStr: str
    targetCount: int
    rawDetails: list[str]

class SecurityAlert(BaseModel):
    id: str
    title: str
    severity: SeverityType
    attackType: AttackType
    sourceIp: str
    destinationIp: str
    sourcePort: Optional[int] = None
    destinationPort: Optional[int] = None
    timestamp: str
    duration: str
    status: AlertStatusType = "Active"
    threatScore: int = 50
    evidence: AlertEvidence
    aiExplanation: str
    recommendations: list[str]
    interface: Optional[str] = "All"
    detectionSource: Optional[DetectionSourceType] = "RULE_ENGINE"
    modelName: Optional[str] = None
    modelVersion: Optional[str] = None
    anomalyScore: Optional[float] = None
    decisionThreshold: Optional[float] = None
    observedFeatures: Optional[dict[str, float]] = None
    captureId: Optional[str] = None
    captureName: Optional[str] = None
    sourceType: Optional[Literal["PCAP", "LIVE"]] = "PCAP"

class AlertStatusUpdate(BaseModel):
    status: AlertStatusType

class BlockIpRequest(BaseModel):
    ipAddress: str

class BlockIpResponse(BaseModel):
    success: bool
    ruleId: str
    message: str
