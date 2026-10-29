from typing import Optional, Literal
from pydantic import BaseModel
from .alert import SeverityType, AttackType, DetectionSourceType

class NotificationItem(BaseModel):
    id: str
    alertId: Optional[str] = None
    title: str
    severity: SeverityType
    attackType: AttackType
    sourceIp: str
    destinationIp: str
    timestamp: str
    detectionSource: DetectionSourceType = "RULE_ENGINE"
    isRead: bool = False
    isDismissed: bool = False
    createdAt: Optional[str] = None

class NotificationCountResponse(BaseModel):
    unreadCount: int
    totalCount: int
