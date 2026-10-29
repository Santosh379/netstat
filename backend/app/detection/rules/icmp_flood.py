import uuid
from datetime import datetime
from collections import defaultdict
from .base import BaseDetectionRule, format_rule_timestamp
from ..explainer import generate_ai_explanation
from ...config import settings
from ...schemas.alert import SecurityAlert, AlertEvidence

class IcmpFloodRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            name="High-Volume ICMP Echo Flood",
            attack_type="ICMP Flood",
            severity="HIGH"
        )

    def evaluate(self, features, packets):
        alerts = []
        icmp_counts = defaultdict(int)
        first_seen = {}
        last_seen = {}

        for pkt in packets:
            if pkt.protocol == "ICMP":
                key = (pkt.source_ip, pkt.dest_ip)
                if key not in first_seen:
                    first_seen[key] = pkt.timestamp
                last_seen[key] = pkt.timestamp
                icmp_counts[key] += 1

        for (src, dst), count in icmp_counts.items():
            raw_duration = last_seen[(src, dst)] - first_seen[(src, dst)]
            duration_sec = max(0.01, raw_duration)
            pps = count / duration_sec

            if count >= settings.ICMP_FLOOD_COUNT_THRESHOLD and pps >= settings.ICMP_FLOOD_RATE_THRESHOLD:
                severity = "CRITICAL" if pps > 600 or count > 1000 else "HIGH"
                threat_score = min(96, 80 + int(pps / 40))
                duration_str = f"{duration_sec:.2f} seconds"

                raw_details = [
                    f"Massive volume of {count:,} ICMP Echo Requests (ping)",
                    f"Peak rate reached {pps:.1f} packets/second",
                    f"Target host {dst} buffer under risk of degradation"
                ]

                evidence = AlertEvidence(
                    packetsCount=count,
                    responseCount=0,
                    durationStr=duration_str,
                    targetCount=1,
                    rawDetails=raw_details
                )

                explanation, recs = generate_ai_explanation(
                    "ICMP Flood",
                    src,
                    dst,
                    {"icmp_count": count, "pps": int(pps)}
                )

                ts_str = format_rule_timestamp(first_seen[(src, dst)])

                alert = SecurityAlert(
                    id=f"ALT-ICMP-{uuid.uuid4().hex[:6].upper()}",
                    title="ICMP Echo Flood Anomaly",
                    severity=severity,
                    attackType="ICMP Flood",
                    sourceIp=src,
                    destinationIp=dst,
                    sourcePort=0,
                    destinationPort=0,
                    timestamp=ts_str,
                    duration=duration_str,
                    status="Active",
                    threatScore=threat_score,
                    evidence=evidence,
                    aiExplanation=explanation,
                    recommendations=recs,
                    interface="Network Tap",
                    detectionSource="RULE_ENGINE"
                )
                alerts.append(alert)

        return alerts
