import uuid
from datetime import datetime
from collections import defaultdict
from .base import BaseDetectionRule, format_rule_timestamp
from ..explainer import generate_ai_explanation
from ...config import settings
from ...schemas.alert import SecurityAlert, AlertEvidence

class PortScanRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            name="Horizontal & Vertical Port Probe Detection",
            attack_type="Port Scan",
            severity="MEDIUM"
        )

    def evaluate(self, features, packets):
        alerts = []
        # Group by (source_ip, dest_ip) -> distinct destination ports and packet counts
        pair_ports = defaultdict(set)
        pair_packets = defaultdict(list)

        for pkt in packets:
            if pkt.protocol in ["TCP", "UDP", "TLS", "DNS"] and pkt.dest_port:
                pair_ports[(pkt.source_ip, pkt.dest_ip)].add(pkt.dest_port)
                pair_packets[(pkt.source_ip, pkt.dest_ip)].append(pkt)

        for (src, dst), ports in pair_ports.items():
            if len(ports) >= settings.PORT_SCAN_THRESHOLD:
                pkts = pair_packets[(src, dst)]
                start_ts = min(p.timestamp for p in pkts)
                end_ts = max(p.timestamp for p in pkts)
                duration_sec = max(0.1, end_ts - start_ts)
                
                # Check probe velocity
                severity = "CRITICAL" if len(ports) >= 30 else ("HIGH" if len(ports) >= 15 else "MEDIUM")
                threat_score = min(98, 65 + len(ports))

                duration_str = f"{duration_sec:.1f} seconds"
                
                # Format raw details
                raw_details = [
                    f"Observed probes across {len(ports)} distinct destination ports",
                    f"Target service ports include: {', '.join(str(p) for p in sorted(ports)[:6])}",
                    f"Probe rate: {len(pkts) / duration_sec:.1f} packets/sec from {src}"
                ]

                evidence = AlertEvidence(
                    packetsCount=len(pkts),
                    responseCount=len([p for p in pkts if "RST" in p.flags or "ACK" in p.flags]),
                    durationStr=duration_str,
                    targetCount=1,
                    rawDetails=raw_details
                )

                explanation, recs = generate_ai_explanation(
                    "Port Scan",
                    src,
                    dst,
                    {"ports": list(ports), "duration_str": duration_str}
                )

                ts_str = format_rule_timestamp(start_ts)

                alert = SecurityAlert(
                    id=f"ALT-PS-{uuid.uuid4().hex[:6].upper()}",
                    title="TCP/UDP Port Scan Sweep",
                    severity=severity,
                    attackType="Port Scan",
                    sourceIp=src,
                    destinationIp=dst,
                    sourcePort=pkts[0].source_port if pkts else 0,
                    destinationPort=list(ports)[0],
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
