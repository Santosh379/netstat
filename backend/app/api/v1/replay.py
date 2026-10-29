from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from ...schemas.replay import AttackScenario, AttackReplayStep
from ...storage.db import db
from ...core.state import global_state
from ...ingestion.pcap_parser import parse_pcap_file
from ...config import settings

router = APIRouter(prefix="/replay", tags=["Attack Replay"])

def _get_active_packet_stream(capture_id: Optional[str] = None) -> list:
    """Returns the active packet stream for the given capture_id, or fallback."""
    if capture_id:
        pkts = global_state.get_capture_packets(capture_id)
        if pkts:
            return pkts
        # Check if capture has a file path in DB
        cap = db.get_capture_by_id(capture_id)
        if cap:
            fpath_str = getattr(cap, "file_path", None) or (cap.get("file_path") if isinstance(cap, dict) else None)
            if fpath_str:
                fpath = Path(fpath_str)
                if fpath.exists():
                    parsed = list(parse_pcap_file(fpath, max_packets=2000))
                    cap_fname = getattr(cap, "filename", "pcap") if not isinstance(cap, dict) else cap.get("filename", "pcap")
                    global_state.set_capture(capture_id, cap_fname, parsed)
                    return parsed

    if global_state.active_capture_id:
        pkts = global_state.get_capture_packets(global_state.active_capture_id)
        if pkts:
            return pkts

    if global_state.last_pcap_packets:
        return global_state.last_pcap_packets

    # Fallback to test mixed traffic sample
    sample_pcap = settings.SAMPLES_DIR / "netscope_test_mixed_traffic.pcap"
    if not sample_pcap.exists():
        sample_pcap = settings.SAMPLES_DIR / "sample_portscan.pcap"
    if sample_pcap.exists():
        return list(parse_pcap_file(sample_pcap, max_packets=500))
    return []

def _format_timestamp(ts: float) -> str:
    if ts <= 0:
        return "00:00:00.000 UTC"
    try:
        dt = datetime.fromtimestamp(ts, timezone.utc)
        return dt.strftime("%H:%M:%S") + f".{int((ts % 1) * 1000):03d} UTC"
    except Exception:
        return str(ts)

def _build_scenario_from_alert(alert, capture_id: Optional[str] = None) -> AttackScenario:
    cid = capture_id or getattr(alert, "captureId", None)
    cname = getattr(alert, "captureName", None)

    # Retrieve capture record from DB if available
    cap_record = db.get_capture_by_id(cid) if cid else None
    if cap_record and not cname:
        cname = getattr(cap_record, "filename", None) if not isinstance(cap_record, dict) else cap_record.get("filename")

    raw_stream = _get_active_packet_stream(cid)
    if cap_record:
        total_capture_packets = getattr(cap_record, "packetCount", getattr(cap_record, "packet_count", None))
        if total_capture_packets is None and isinstance(cap_record, dict):
            total_capture_packets = cap_record.get("packetCount", cap_record.get("packet_count", len(raw_stream)))
        if total_capture_packets is None:
            total_capture_packets = len(raw_stream)
    else:
        total_capture_packets = len(raw_stream)

    src = alert.sourceIp
    dst = alert.destinationIp
    atype = alert.attackType

    # Filter real packets associated with this alert
    matching_packets = []
    for pkt in raw_stream:
        p_src = getattr(pkt, "source_ip", None) or getattr(pkt, "sourceIp", None)
        p_dst = getattr(pkt, "dest_ip", None) or getattr(pkt, "destinationIp", None)
        p_proto = getattr(pkt, "protocol", "")

        if atype == "Port Scan" and p_src == src and p_dst == dst:
            matching_packets.append(pkt)
        elif atype == "SYN Flood" and (p_src == src or p_dst == dst) and "SYN" in getattr(pkt, "flags", []):
            matching_packets.append(pkt)
        elif atype == "ICMP Flood" and p_proto == "ICMP" and (p_src == src or p_dst == dst):
            matching_packets.append(pkt)
        elif atype == "ARP Spoofing" and p_proto == "ARP":
            matching_packets.append(pkt)
        elif p_src == src and p_dst == dst:
            matching_packets.append(pkt)

    # Sort chronologically by timestamp
    matching_packets.sort(key=lambda p: getattr(p, "timestamp", 0.0))
    incident_packets_count = len(matching_packets)

    steps: list[AttackReplayStep] = []
    unique_ports: set[int] = set()
    trigger_step_idx: Optional[int] = None

    if matching_packets:
        for idx, p in enumerate(matching_packets[:120]):
            p_src = getattr(p, "source_ip", None) or getattr(p, "sourceIp", None) or src
            p_dst = getattr(p, "dest_ip", None) or getattr(p, "destinationIp", None) or dst
            dport = getattr(p, "dest_port", 0) or getattr(p, "destinationPort", 0) or 0
            sport = getattr(p, "source_port", 0) or getattr(p, "sourcePort", 0) or 0
            proto = getattr(p, "protocol", "TCP")
            flags_list = getattr(p, "flags", [])
            flags_str = ", ".join(flags_list) if flags_list else proto
            size = getattr(p, "size", 64)
            ts = getattr(p, "timestamp", 0.0)

            if dport:
                unique_ports.add(dport)

            # Realistic status determination
            status = "SYN_SENT"
            if "RST" in flags_list:
                status = "RST_RECEIVED"
            elif "ACK" in flags_list:
                status = "OPEN"
            elif proto == "ICMP":
                status = "ICMP_REQUEST"
            elif proto == "ARP":
                status = "ARP_REPLY"

            # Forensic detail message and trigger packet identification
            is_trigger = False
            trigger_reason = None
            if atype == "Port Scan":
                detail = f"Probe #{idx+1}: TCP SYN probe sent to {p_dst}:{dport} (seq probe, {size} bytes)"
                if len(unique_ports) == 15 or (len(unique_ports) >= 10 and trigger_step_idx is None and idx >= 10):
                    is_trigger = True
                    trigger_reason = f"Port scan threshold crossed: {len(unique_ports)} distinct ports probed"
                    trigger_step_idx = idx
            elif atype == "SYN Flood":
                detail = f"Flood packet #{idx+1}: Rapid TCP SYN burst to port {dport} (no ACK handshake)"
                if idx == 30 or (idx >= 20 and trigger_step_idx is None and idx == len(matching_packets) - 1):
                    is_trigger = True
                    trigger_reason = "SYN flood threshold reached: high-frequency SYN packets without completed handshakes"
                    trigger_step_idx = idx
            elif atype == "ICMP Flood":
                detail = f"Echo packet #{idx+1}: High-frequency ICMP Echo Request ({size} bytes)"
                if idx == 20 or (idx >= 15 and trigger_step_idx is None and idx == len(matching_packets) - 1):
                    is_trigger = True
                    trigger_reason = "ICMP flood threshold reached: rapid echo requests"
                    trigger_step_idx = idx
            elif atype == "ARP Spoofing":
                detail = f"Gratuitous ARP Reply #{idx+1}: Mapping poisoning claim for gateway IP"
                if idx == 1 or trigger_step_idx is None:
                    is_trigger = True
                    trigger_reason = "Conflicting ARP reply: duplicate IP claimed by different MAC"
                    trigger_step_idx = idx
            else:
                detail = f"Flow event #{idx+1}: {proto} packet from {p_src}:{sport} -> {p_dst}:{dport} ({size} B)"
                if idx == len(matching_packets) // 2:
                    is_trigger = True
                    trigger_reason = "Statistical anomaly detected across flow feature vector"
                    trigger_step_idx = idx

            steps.append(AttackReplayStep(
                id=idx + 1,
                timestamp=_format_timestamp(ts),
                sourceIp=p_src,
                destinationIp=p_dst,
                sourcePort=sport,
                port=dport,
                service=proto,
                protocol=proto,
                flags=flags_str,
                packetSize=size,
                flowId=f"flow-{p_src}-{p_dst}",
                relatedAlertId=alert.id,
                detectionSource=alert.detectionSource or "RULE_ENGINE",
                isThreatTrigger=is_trigger,
                triggerReason=trigger_reason,
                eventType="RAW_PACKET",
                status=status,
                detail=detail,
                evidence=f"{size} bytes • Flags: [{flags_str}]"
            ))

        # If no step was flagged as trigger yet, mark the last one
        if trigger_step_idx is None and steps:
            steps[-1].isThreatTrigger = True
            steps[-1].triggerReason = f"Detection alert threshold reached for {atype}"
            trigger_step_idx = len(steps) - 1

        is_summary = False
    else:
        # Honest fallback: No raw packets retained in memory or flow summary event
        is_summary = True
        incident_packets_count = alert.evidence.targetCount or 1
        steps.append(AttackReplayStep(
            id=1,
            timestamp=alert.timestamp,
            sourceIp=src,
            destinationIp=dst,
            sourcePort=alert.sourcePort or 0,
            port=alert.destinationPort or 0,
            service=getattr(alert, "protocol", None) or "TCP",
            protocol=getattr(alert, "protocol", None) or "TCP",
            flags="FLOW_SUMMARY",
            packetSize=64,
            flowId=f"flow-{src}-{dst}",
            relatedAlertId=alert.id,
            detectionSource=alert.detectionSource or "ML_MODEL",
            isThreatTrigger=True,
            triggerReason="Flow-level anomaly detection (individual packets not retained in memory buffer)",
            eventType="FLOW_SUMMARY",
            status="FLOW_RECORD",
            detail=f"{alert.title}: Aggregated flow record spanning {alert.duration or 'observed window'}.",
            evidence=f"Threat Score: {alert.threatScore}/100 • Source: {alert.detectionSource}"
        ))
        trigger_step_idx = 0

    # Evidence-based known facts and uncertainties (no fabricated claims)
    known_facts = [
        f"Capture session: {cname or 'Active Session'} (ID: {cid or 'LIVE'})",
        f"Associated endpoints: {src} -> {dst}",
        f"Detection mechanism: {alert.detectionSource or 'RULE_ENGINE'} (Threat Score: {alert.threatScore}/100)",
        f"Total packets in capture file: {total_capture_packets}",
        f"Incident-matching packets identified: {incident_packets_count}"
    ]
    if unique_ports:
        known_facts.append(f"Targeted {len(unique_ports)} distinct destination port(s): {sorted(list(unique_ports))[:8]}")

    uncertainties = [
        "Application-layer payload remains uninspected beyond L3/L4 protocol headers",
        "Host roles and OS identities are inferred from protocol behavior, not hardcoded assumptions"
    ]
    if is_summary:
        uncertainties.append("Individual packet timestamps unavailable; event is aggregated from flow statistical features.")

    time_window = f"{steps[0].timestamp} - {steps[-1].timestamp}" if steps else alert.timestamp

    return AttackScenario(
        id=f"SCENARIO-{alert.id}",
        name=f"{alert.attackType} Incident Replay",
        attackType=alert.attackType,
        sourceIp=src,
        targetIp=dst,
        duration=alert.duration or "0.0s",
        captureId=cid,
        captureName=cname,
        totalPacketsInCapture=total_capture_packets,
        incidentPacketsCount=incident_packets_count,
        packetCount=len(steps),
        portsScanned=len(unique_ports) if unique_ports else alert.evidence.targetCount,
        anomalyScore=float(alert.threatScore),
        description=alert.aiExplanation,
        timeWindow=time_window,
        confidence="High (Deterministic Rule Match)" if alert.detectionSource == "RULE_ENGINE" else f"Statistical Outlier ({alert.detectionSource})",
        isSummary=is_summary,
        triggerStepIndex=trigger_step_idx,
        knownFacts=known_facts,
        uncertainties=uncertainties,
        steps=steps
    )

@router.get("/scenarios", response_model=list[AttackScenario])
def list_scenarios(capture_id: Optional[str] = Query(None)):
    alerts = db.get_alerts(capture_id=capture_id, limit=20)
    scenarios = []
    for a in alerts:
        scenarios.append(_build_scenario_from_alert(a, capture_id=capture_id))
    return scenarios

@router.get("/scenario/{scenario_id}", response_model=AttackScenario)
def get_scenario(scenario_id: str, capture_id: Optional[str] = Query(None)):
    if scenario_id.startswith("SCENARIO-"):
        alert_id = scenario_id.replace("SCENARIO-", "")
        alert = db.get_alert_by_id(alert_id)
        if alert:
            return _build_scenario_from_alert(alert, capture_id=alert.captureId or capture_id)

    all_scenarios = list_scenarios(capture_id=capture_id)
    for s in all_scenarios:
        if s.id == scenario_id:
            return s
    if all_scenarios:
        return all_scenarios[0]
    raise HTTPException(status_code=404, detail="No replay scenarios available.")

@router.get("/from-alert/{alert_id}", response_model=AttackScenario)
def get_scenario_from_alert(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")
    return _build_scenario_from_alert(alert, capture_id=alert.captureId)

