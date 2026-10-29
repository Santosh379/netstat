import uuid
from collections import defaultdict
from .base import BaseDetectionRule, format_rule_timestamp
from ..explainer import generate_ai_explanation
from ...config import settings
from ...schemas.alert import SecurityAlert, AlertEvidence

AUTH_PORTS = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 8080: "HTTP-Auth"}

class BruteForceRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            name="Repeated Authentication Connection Attempts",
            attack_type="Brute Force",
            severity="MEDIUM"
        )

    def evaluate(self, features, packets):
        alerts = []
        # Track connections per (source_ip, dest_ip, port)
        auth_attempts = defaultdict(list)

        for pkt in packets:
            if pkt.protocol == "TCP" and pkt.dest_port in AUTH_PORTS:
                # Count SYN connections or RST responses
                if "SYN" in pkt.flags or "RST" in pkt.flags:
                    auth_attempts[(pkt.source_ip, pkt.dest_ip, pkt.dest_port)].append(pkt)

        for (src, dst, port), pkts in auth_attempts.items():
            if len(pkts) >= settings.BRUTE_FORCE_ATTEMPTS_THRESHOLD:
                service_name = AUTH_PORTS.get(port, f"Port {port}")
                start_ts = pkts[0].timestamp
                end_ts = pkts[-1].timestamp
                duration_sec = max(1.0, end_ts - start_ts)
                duration_str = f"{duration_sec:.1f} seconds"

                raw_details = [
                    f"{len(pkts)} sequential connection attempts to {service_name} (port :{port})",
                    "Rapid connection reset / handshake spray pattern observed",
                    "Header-level indicators suggest automated dictionary password guessing"
                ]

                evidence = AlertEvidence(
                    packetsCount=len(pkts),
                    responseCount=len([p for p in pkts if "RST" in p.flags]),
                    durationStr=duration_str,
                    targetCount=1,
                    rawDetails=raw_details
                )

                explanation, recs = generate_ai_explanation(
                    "Brute Force",
                    src,
                    dst,
                    {"attempts": len(pkts), "port": port}
                )

                alert = SecurityAlert(
                    id=f"ALT-BF-{uuid.uuid4().hex[:6].upper()}",
                    title=f"Brute-Force Indicator ({service_name})",
                    severity="MEDIUM" if len(pkts) < 20 else "HIGH",
                    attackType="Brute Force",
                    sourceIp=src,
                    destinationIp=dst,
                    sourcePort=pkts[0].source_port if pkts else 0,
                    destinationPort=port,
                    timestamp=format_rule_timestamp(pkts[0].timestamp if pkts else 0.0),
                    duration=duration_str,
                    status="Active",
                    threatScore=70,
                    evidence=evidence,
                    aiExplanation=explanation,
                    recommendations=recs,
                    interface="Network Tap",
                    detectionSource="RULE_ENGINE"
                )
                alerts.append(alert)

        return alerts
