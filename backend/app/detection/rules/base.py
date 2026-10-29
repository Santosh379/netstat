from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime, timezone
from ...ingestion.pcap_parser import ParsedPacket
from ...ingestion.feature_extractor import FeatureExtractionResult
from ...schemas.alert import SecurityAlert

def format_rule_timestamp(ts: float) -> str:
    """
    Format packet timestamp into consistent timezone-aware UTC datetime string.
    Never returns raw integer epochs or invalid dates.
    """
    if not ts or ts <= 0:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

class BaseDetectionRule(ABC):
    def __init__(self, name: str, attack_type: str, severity: str):
        self.name = name
        self.attack_type = attack_type
        self.severity = severity

    @abstractmethod
    def evaluate(
        self,
        features: FeatureExtractionResult,
        packets: list[ParsedPacket]
    ) -> list[SecurityAlert]:
        """
        Evaluates the packets and extracted features to find security anomalies.
        Returns a list of generated SecurityAlert objects.
        """
        pass
