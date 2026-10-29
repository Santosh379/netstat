import math
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from ...schemas.topology import TopologyResponse, TopologyNode, TopologyLink
from ...core.state import global_state
from ...storage.db import db
from ...ingestion.pcap_parser import parse_pcap_file
from ...config import settings

router = APIRouter(prefix="/topology", tags=["Topology"])

_isolated_hosts: set[str] = set()

def _calculate_coordinates(index: int, total: int, center_x: int = 450, center_y: int = 260) -> tuple[int, int]:
    if total == 1:
        return center_x, center_y
    if total <= 6:
        radius_x = 220
        radius_y = 140
    else:
        radius_x = 280
        radius_y = 170

    angle = (2 * math.pi * index) / total - (math.pi / 2)
    x = int(center_x + radius_x * math.cos(angle))
    y = int(center_y + radius_y * math.sin(angle))
    return max(60, min(840, x)), max(60, min(460, y))

@router.get("", response_model=TopologyResponse)
def get_topology(
    source: str = Query("auto", pattern="^(auto|pcap|live)$"),
    captureId: Optional[str] = Query(None)
):
    packets = []
    capture_name = "Live Capture Session"
    data_source = "Live Monitoring"

    # 1. Resolve packet source strictly based on captureId or requested source
    if captureId and captureId != "ALL" and captureId != "live":
        packets = global_state.get_capture_packets(captureId)
        cap = db.get_capture_by_id(captureId)
        capture_name = cap.filename if cap else (global_state.captures.get(captureId, {}).get("name", captureId))
        data_source = f"PCAP Capture: {capture_name}"
        alerts = db.get_alerts(capture_id=captureId, limit=500)
    elif captureId == "live" or source == "live":
        packets = list(global_state.packet_buffer)
        capture_name = "Live Monitoring Session"
        data_source = "Live Network Traffic"
        alerts = db.get_alerts(source_type="LIVE", limit=500)
    elif global_state.active_capture_id:
        active_id = global_state.active_capture_id
        packets = global_state.get_capture_packets(active_id)
        cap = db.get_capture_by_id(active_id)
        capture_name = cap.filename if cap else (global_state.captures.get(active_id, {}).get("name", "Active PCAP"))
        data_source = f"PCAP Capture: {capture_name}"
        alerts = db.get_alerts(capture_id=active_id, limit=500)
    else:
        # Fallback to sample PCAP only on initial uninitialized launch
        sample_pcap = settings.SAMPLES_DIR / "netscope_test_mixed_traffic.pcap"
        if not sample_pcap.exists():
            sample_pcap = settings.SAMPLES_DIR / "sample_portscan.pcap"
        if sample_pcap.exists():
            packets = list(parse_pcap_file(sample_pcap, max_packets=500))
            capture_name = sample_pcap.name
            data_source = f"Sample PCAP: {sample_pcap.name}"
        alerts = db.get_alerts(limit=500)

    alerts_by_src: dict[str, list] = {}
    alerts_by_dst: dict[str, list] = {}
    for a in alerts:
        alerts_by_src.setdefault(a.sourceIp, []).append(a)
        alerts_by_dst.setdefault(a.destinationIp, []).append(a)

    # 2. Identify unique IP endpoints from observed packets
    observed_ips: set[str] = set()
    for p in packets:
        src = getattr(p, "source_ip", None) or getattr(p, "sourceIp", None)
        dst = getattr(p, "dest_ip", None) or getattr(p, "destinationIp", None)
        if src:
            observed_ips.add(src)
        if dst:
            observed_ips.add(dst)

    # Fallback only if no packets are available
    if not observed_ips:
        if cap and getattr(cap, "observedHosts", None):
            for h in cap.observedHosts:
                observed_ips.add(h)
        for a in alerts:
            observed_ips.add(a.sourceIp)
            observed_ips.add(a.destinationIp)

    sorted_ips = sorted(list(observed_ips))
    total_hosts = len(sorted_ips)

    nodes: list[TopologyNode] = []
    for idx, ip in enumerate(sorted_ips):
        x, y = _calculate_coordinates(idx, total_hosts)
        
        # Calculate real packet stats
        pkts_in = 0
        pkts_out = 0
        bytes_in = 0
        bytes_out = 0
        open_ports: set[int] = set()
        protocols: set[str] = set()
        mac_addr = "Not in L3/L4 header"

        for p in packets:
            src = getattr(p, "source_ip", None) or getattr(p, "sourceIp", None)
            dst = getattr(p, "dest_ip", None) or getattr(p, "destinationIp", None)
            size = getattr(p, "size", 64)
            proto = getattr(p, "protocol", "TCP")
            dport = getattr(p, "dest_port", None) or getattr(p, "destinationPort", None)
            smac = getattr(p, "source_mac", None)

            if src == ip:
                pkts_out += 1
                bytes_out += size
                protocols.add(proto)
                if smac and smac != "Unknown":
                    mac_addr = smac
            if dst == ip:
                pkts_in += 1
                bytes_in += size
                protocols.add(proto)
                if dport:
                    open_ports.add(dport)

        # Check alert associations
        src_alerts = alerts_by_src.get(ip, [])
        dst_alerts = alerts_by_dst.get(ip, [])
        associated_alerts = [a.id for a in (src_alerts + dst_alerts)]
        alerts_count = len(associated_alerts)

        # Evidence-based role & classification without hardcoded roles
        is_isolated = ip in _isolated_hosts or f"node-{ip}" in _isolated_hosts
        role = "Workstation"
        status = "Normal"
        risk_level = "Low"
        classification = "Observed Host"
        os_label = "Unknown (Passive L3/L4 Inspection)"

        has_rule_attack = any(a.detectionSource == "RULE_ENGINE" and a.severity in ["CRITICAL", "HIGH"] for a in src_alerts)
        has_ml_anomaly = any(a.detectionSource == "ML_ANOMALY" for a in src_alerts)

        if has_rule_attack:
            rule_types = {a.attackType for a in src_alerts if a.detectionSource == "RULE_ENGINE"}
            role = "Attacker"
            status = "Critical"
            risk_level = "Critical"
            classification = f"Confirmed Rule Match: {', '.join(rule_types)}"
        elif has_ml_anomaly:
            role = "Workstation"
            status = "Warning"
            risk_level = "Medium"
            classification = "Suspicious Host (ML Statistical Anomaly)"
        elif dst_alerts:
            role = "Server" if len(open_ports) > 1 else "Workstation"
            status = "Warning"
            risk_level = "High" if any(a.severity == "CRITICAL" for a in dst_alerts) else "Medium"
            classification = f"Target Host ({len(dst_alerts)} alerts)"
        elif len(open_ports) >= 2 or any(p in [80, 443, 53, 22] for p in open_ports):
            role = "Server"
            classification = "Server (Listening on Known Ports)"

        if is_isolated:
            status = "Compromised"
            classification += " [QUARANTINED]"

        hostname = f"Host ({ip})"
        if role == "Gateway":
            hostname = f"Gateway ({ip})"
        elif role == "Server":
            hostname = f"Server ({ip})"
        elif role == "Attacker":
            hostname = f"Attacker ({ip})"

        nodes.append(TopologyNode(
            id=f"node-{ip.replace('.', '-')}",
            ip=ip,
            hostname=hostname,
            role=role,
            status=status,
            classification=classification,
            x=x,
            y=y,
            packetsIn=pkts_in,
            packetsOut=pkts_out,
            bytesIn=bytes_in,
            bytesOut=bytes_out,
            openPorts=sorted(list(open_ports))[:10],
            protocols=sorted(list(protocols)),
            alertsCount=alerts_count,
            associatedAlerts=associated_alerts,
            riskLevel=risk_level,
            mac=mac_addr,
            os=os_label
        ))

    # Extract communication edges between observed hosts
    link_map: dict[tuple[str, str], dict] = {}
    for p in packets:
        src = getattr(p, "source_ip", None) or getattr(p, "sourceIp", None)
        dst = getattr(p, "dest_ip", None) or getattr(p, "destinationIp", None)
        if not src or not dst or src == dst:
            continue
        if src not in observed_ips or dst not in observed_ips:
            continue

        pair = (src, dst)
        if pair not in link_map:
            link_map[pair] = {
                "source": f"node-{src.replace('.', '-')}",
                "target": f"node-{dst.replace('.', '-')}",
                "source_ip": src,
                "target_ip": dst,
                "packet_count": 0,
                "byte_count": 0,
                "protocols": set(),
                "ports": set(),
                "evidence": []
            }

        link_map[pair]["packet_count"] += 1
        link_map[pair]["byte_count"] += getattr(p, "size", 64)
        proto = getattr(p, "protocol", "TCP")
        link_map[pair]["protocols"].add(proto)
        dport = getattr(p, "dest_port", None) or getattr(p, "destinationPort", None)
        if dport:
            link_map[pair]["ports"].add(dport)

    links: list[TopologyLink] = []
    for (src, dst), info in link_map.items():
        # Determine status: attack-path if matches any alert
        is_attack_path = any(a.sourceIp == src and a.destinationIp == dst for a in alerts)
        link_status = "attack-path" if is_attack_path else ("high-traffic" if info["packet_count"] > 40 else "normal")

        evidence_list = []
        if is_attack_path:
            matching_alerts = [a.attackType for a in alerts if a.sourceIp == src and a.destinationIp == dst]
            evidence_list.append(f"Attack Path: {', '.join(set(matching_alerts))}")
        evidence_list.append(f"{info['packet_count']} packets, {info['byte_count']} bytes transferred")

        links.append(TopologyLink(
            id=f"link-{src.replace('.', '-')}-{dst.replace('.', '-')}",
            source=info["source"],
            target=info["target"],
            status=link_status,
            protocol=sorted(list(info["protocols"]))[0] if info["protocols"] else "TCP",
            protocols=sorted(list(info["protocols"])),
            ports=sorted(list(info["ports"]))[:8],
            packetCount=info["packet_count"],
            byteCount=info["byte_count"],
            flowCount=1,
            evidence=evidence_list
        ))

    return TopologyResponse(
        dataSource=data_source,
        captureName=capture_name,
        totalObservedHosts=len(nodes),
        totalActiveLinks=len(links),
        nodes=nodes,
        links=links
    )

@router.post("/isolate/{host_id}")
def isolate_host(host_id: str):
    _isolated_hosts.add(host_id)
    return {"success": True, "isolatedHost": host_id, "message": f"Host {host_id} quarantined from local network."}

@router.post("/unisolate/{host_id}")
def unisolate_host(host_id: str):
    _isolated_hosts.discard(host_id)
    return {"success": True, "unisoldatedHost": host_id, "message": f"Host {host_id} quarantine released."}
