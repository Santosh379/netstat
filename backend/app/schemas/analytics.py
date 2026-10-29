from pydantic import BaseModel
from .alert import SecurityAlert

class TrafficTimelinePoint(BaseModel):
    time: str
    packets: int

class ProtocolDistribution(BaseModel):
    name: str
    value: float
    color: str

class DashboardStats(BaseModel):
    totalPackets: int
    activeHosts: int
    threatsCount: int
    threatScore: int
    networkStatus: str
    trafficTimeline: list[TrafficTimelinePoint]
    protocolDistribution: list[ProtocolDistribution]
    recentAlerts: list[SecurityAlert]
