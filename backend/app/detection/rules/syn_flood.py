import uuid
from datetime import datetime
from collections import defaultdict
from .base import BaseDetectionRule, format_rule_timestamp
from ..explainer import generate_ai_explanation
from ...config import settings
from ...schemas.alert import SecurityAlert, AlertEvidence

class SynFloodRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            name="TCP SYN Half-Open Connection Flood",
            attack_type="SYN Flood",
            severity="HIGH"
        )

    def evaluate(self, features, packets):
        alerts = []
        # Group by (source_ip, dest_ip, dest_port)
        syn_counts = defaultdict(int)
        ack_counts = defaultdict(int)
        first_seen = {}
        last_seen = {}

        for pkt in packets:
            if pkt.protocol in ["TCP", "TLS"]:
                key = (pkt.source_ip, pkt.dest_ip, pkt.dest_port)
                if key not in first_seen:
                    first_seen[key] = pkt.timestamp
                last_seen[key] = pkt.timestamp

                if "SYN" in pkt.flags and "ACK" not in pkt.flags:
                    syn_counts[key] += 1
                elif "ACK" in pkt.flags:
                    ack_counts[key] += 1

        for key, syn_count in syn_counts.items():
            src, dst, dport = key
            ack_count = ack_counts[key]
            duration_sec = max(0.5, last_seen[key] - first_seen[key])
            rate = syn_count / duration_sec

            # Criteria: At least 30 SYN packets AND (rate >= threshold OR (syn_count >= 50 and ack_count / syn_count <= 0.1))
            ack_ratio = (ack_count / syn_count) if syn_count > 0 else 1.0
            
            if (syn_count >= 30 and rate >= settings.SYN_FLOOD_RATE_THRESHOLD) or (syn_count >= 50 and ack_ratio <= settings.SYN_FLOOD_ACK_RATIO_MAX):
                severity = "CRITICAL" if syn_count > 200 or rate > 300 else "HIGH"
                threat_score = min(99, 85 + int(rate / 50))
                duration_str = f"{duration_sec:.1f} seconds"

                raw_details = [
                    f"{syn_count:,} SYN packets sent without completing TCP handshake",
                    f"Only {ack_count:,} ACK responses returned by target server (ratio: {ack_ratio*100:.1f}%)",
                    f"Observed peak burst rate: {rate:.1f} SYN/sec targeting port :{dport}"
                ]

                evidence = AlertEvidence(
                    packetsCount=syn_count,
                    responseCount=ack_count,
                    durationStr=duration_str,
                    targetCount=1,
                    rawDetails=raw_details
                )

                explanation, recs = generate_ai_explanation(
                    "SYN Flood",
                    src,
                    dst,
                    {"syn_count": syn_count, "ack_count": ack_count, "dest_port": dport}
                )

                ts_str = format_rule_timestamp(first_seen[key])

                alert = SecurityAlert(
                    id=f"ALT-SF-{uuid.uuid4().hex[:6].upper()}",
                    title="TCP SYN Flood Denial-of-Service",
                    severity=severity,
                    attackType="SYN Flood",
                    sourceIp=src,
                    destinationIp=dst,
                    sourcePort=0,
                    destinationPort=dport,
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
