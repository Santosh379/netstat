from typing import Optional
from pydantic import BaseModel
from .alert import SecurityAlert

class TopProtocol(BaseModel):
    name: str
    percentage: float

class DetectedSignature(BaseModel):
    signature: str
    severity: str
    count: int

class CaptureSession(BaseModel):
    id: str
    filename: str
    filesize: str
    packetsAnalyzed: int
    uniqueHosts: int
    tcpConnections: int
    potentialThreats: int
    ruleThreats: int = 0
    mlThreats: int = 0
    durationSeconds: float
    status: str = "COMPLETED"
    analyzedAt: str
    observedHosts: list[str] = []
    topProtocols: list[TopProtocol] = []
    detectedSignatures: list[DetectedSignature] = []

class PcapAnalysisResult(BaseModel):
    captureId: Optional[str] = None
    filename: str
    filesize: str
    packetsAnalyzed: int
    uniqueHosts: int
    tcpConnections: int
    potentialThreats: int
    ruleThreats: int = 0
    mlThreats: int = 0
    durationSeconds: float
    analyzedAt: Optional[str] = None
    observedHosts: list[str] = []
    topProtocols: list[TopProtocol]
    detectedSignatures: list[DetectedSignature]
    alerts: list[SecurityAlert] = []

class PcapUploadResponse(BaseModel):
    taskId: str
    filename: str
    filesize: str
    status: str = "completed"
    progress: int = 100
    message: str = "Analysis completed"
    result: Optional[PcapAnalysisResult] = None
