import uuid
from datetime import datetime
from collections import defaultdict
from .base import BaseDetectionRule, format_rule_timestamp
from ..explainer import generate_ai_explanation
from ...schemas.alert import SecurityAlert, AlertEvidence

class ArpSpoofRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            name="ARP Cache Poisoning & Conflict Detection",
            attack_type="ARP Spoofing",
            severity="CRITICAL"
        )

    def evaluate(self, features, packets):
        alerts = []
        # Track IP -> observed MAC addresses
        ip_macs = defaultdict(set)
        arp_replies_count = defaultdict(int)
        first_seen = {}
        last_seen = {}

        for pkt in packets:
            if pkt.protocol == "ARP":
                src_ip = pkt.source_ip
                mac = pkt.mac_src
                if src_ip and mac and src_ip != "0.0.0.0":
                    ip_macs[src_ip].add(mac)
                    arp_replies_count[src_ip] += 1
                    if src_ip not in first_seen:
                        first_seen[src_ip] = pkt.timestamp
                    last_seen[src_ip] = pkt.timestamp

        for ip, macs in ip_macs.items():
            # If a single IP is claimed by 2 or more distinct MAC addresses:
            if len(macs) >= 2:
                mac_list = list(macs)
                duration_sec = max(1.0, last_seen[ip] - first_seen[ip])
                duration_str = f"{duration_sec:.1f} seconds"

                raw_details = [
                    f"Conflicting MAC addresses detected for IP {ip}: {', '.join(mac_list)}",
                    f"Unsolicited or repeated ARP announcements observed ({arp_replies_count[ip]} packets)",
                    "Potential Man-in-the-Middle (MitM) gateway redirection in progress"
                ]

                evidence = AlertEvidence(
                    packetsCount=arp_replies_count[ip],
                    responseCount=0,
                    durationStr=duration_str,
                    targetCount=2,
                    rawDetails=raw_details
                )

                explanation, recs = generate_ai_explanation(
                    "ARP Spoofing",
                    ip,
                    "LAN Broadcast",
                    {"target_ip": ip, "attacker_mac": mac_list[1] if len(mac_list) > 1 else mac_list[0]}
                )

                ts_str = format_rule_timestamp(first_seen[ip])

                alert = SecurityAlert(
                    id=f"ALT-ARP-{uuid.uuid4().hex[:6].upper()}",
                    title="Gratuitous ARP Cache Poisoning",
                    severity="CRITICAL",
                    attackType="ARP Spoofing",
                    sourceIp=ip,
                    destinationIp="255.255.255.255",
                    sourcePort=0,
                    destinationPort=0,
                    timestamp=ts_str,
                    duration=duration_str,
                    status="Active",
                    threatScore=95,
                    evidence=evidence,
                    aiExplanation=explanation,
                    recommendations=recs,
                    interface="Network Tap",
                    detectionSource="RULE_ENGINE"
                )
                alerts.append(alert)

        return alerts
