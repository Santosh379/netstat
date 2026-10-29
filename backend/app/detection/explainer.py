from typing import Any

MITRE_ATTACK_MAPPINGS = {
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Reconnaissance / Discovery",
        "default_recommendations": [
            "Block scanning source IP on external/internal perimeter firewall",
            "Disable unnecessary exposed services and management ports",
            "Implement port knocking or VPN tunneling for sensitive administration ports",
            "Enable rate-limiting for embryonic TCP connections on network switches"
        ]
    },
    "SYN Flood": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Denial of Service (SYN Flood)",
        "tactic": "Impact",
        "default_recommendations": [
            "Enable TCP SYN cookies on the destination server (`sysctl -w net.ipv4.tcp_syncookies=1`)",
            "Reduce TCP half-open connection timeout (`net.ipv4.tcp_synack_retries`)",
            "Deploy upstream firewall rate-limiting for inbound SYN packets",
            "Isolate target server to high-capacity mitigation VLAN"
        ]
    },
    "ICMP Flood": {
        "technique_id": "T1499.001",
        "technique_name": "Endpoint Denial of Service (OS or Service Exhaustion)",
        "tactic": "Impact",
        "default_recommendations": [
            "Rate-limit ICMP Echo Request packets on border routers",
            "Configure host firewalls to drop broadcast ICMP ping packets",
            "Inspect the source host for malware or automated bot infection"
        ]
    },
    "ARP Spoofing": {
        "technique_id": "T1557.002",
        "technique_name": "Adversary-in-the-Middle (ARP Cache Poisoning)",
        "tactic": "Credential Access / Collection",
        "default_recommendations": [
            "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on managed switches",
            "Configure static ARP mappings for critical gateway routers and DNS servers",
            "Quarantine offending host MAC from switch port via 802.1X isolation"
        ]
    },
    "Brute Force": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "default_recommendations": [
            "Enforce public-key authentication only; disable password authentication",
            "Implement Fail2ban or automated IP ban after repeated failed authentications",
            "Change default administration port and apply strict IP whitelist filters"
        ]
    }
}

def generate_ai_explanation(
    attack_type: str,
    source_ip: str,
    dest_ip: str,
    metrics: dict[str, Any]
) -> tuple[str, list[str]]:
    """
    Returns: (aiExplanation, recommendations)
    """
    mapping = MITRE_ATTACK_MAPPINGS.get(attack_type, {})
    mitre_info = f"MITRE ATT&CK {mapping.get('technique_id', 'T1000')} ({mapping.get('technique_name', attack_type)})"
    recs = mapping.get("default_recommendations", ["Investigate suspicious network endpoint", "Review firewall access logs"])

    if attack_type == "Port Scan":
        ports = metrics.get("ports", [])
        ports_str = ", ".join(f":{p}" for p in sorted(ports)[:8])
        if len(ports) > 8:
            ports_str += f" (+{len(ports)-8} more)"
        explanation = (
            f"Automated probe activity detected under {mitre_info}. Host {source_ip} sent systematic "
            f"connection requests across {len(ports)} distinct ports ({ports_str}) on target {dest_ip} within "
            f"{metrics.get('duration_str', 'a short window')}, indicating active reconnaissance before exploitation."
        )
    elif attack_type == "SYN Flood":
        syn_count = metrics.get("syn_count", 0)
        ack_count = metrics.get("ack_count", 0)
        explanation = (
            f"Anomalous TCP handshake exhaustion observed under {mitre_info}. Source {source_ip} generated "
            f"{syn_count:,} SYN connection requests against {dest_ip}:{metrics.get('dest_port', 80)} while only "
            f"{ack_count:,} ACK acknowledgments were observed, indicating deliberate half-open socket queue saturation."
        )
    elif attack_type == "ICMP Flood":
        icmp_count = metrics.get("icmp_count", 0)
        pps = metrics.get("pps", 0)
        explanation = (
            f"High-frequency ping storm detected under {mitre_info}. Source {source_ip} overwhelmed {dest_ip} "
            f"with {icmp_count:,} ICMP echo requests at {pps} packets/sec, causing interface buffer congestion."
        )
    elif attack_type == "ARP Spoofing":
        explanation = (
            f"Layer 2 cache poisoning anomaly identified under {mitre_info}. Multiple conflicting ARP responses "
            f"were observed linking IP {metrics.get('target_ip', dest_ip)} to attacker hardware MAC {metrics.get('attacker_mac', 'unknown')}, "
            f"attempting an unauthorized Adversary-in-the-Middle traffic intercept."
        )
    elif attack_type == "Brute Force":
        attempts = metrics.get("attempts", 0)
        explanation = (
            f"Repeated authentication failure sequence detected under {mitre_info}. Source {source_ip} executed "
            f"{attempts} consecutive failed handshake/connection attempts against port {metrics.get('port', 22)} on {dest_ip}, "
            f"characteristic of dictionary-based credential spraying."
        )
    else:
        explanation = f"Security anomaly detected from {source_ip} targeting {dest_ip}."

    return explanation, recs
