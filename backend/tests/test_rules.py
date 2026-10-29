import pytest
from pathlib import Path
from app.config import settings
from app.ingestion.pcap_parser import ParsedPacket, parse_pcap_file
from app.ingestion.feature_extractor import extract_features
from app.detection.rules.syn_flood import SynFloodRule
from app.detection.rules.port_scan import PortScanRule
from app.detection.rules.icmp_flood import IcmpFloodRule
from app.detection.rules.arp_spoof import ArpSpoofRule
from app.detection.rules.brute_force import BruteForceRule
from app.detection.engine import detection_engine
from app.storage.sample_generator import ensure_sample_pcaps

def test_syn_flood_rule():
    ensure_sample_pcaps()
    pcap_path = settings.SAMPLES_DIR / "sample_syn_flood.pcap"
    packets = list(parse_pcap_file(pcap_path))
    features, _ = extract_features(packets)

    rule = SynFloodRule()
    alerts = rule.evaluate(features, packets)

    assert len(alerts) > 0, "SYN Flood rule should detect the flood"
    alert = alerts[0]
    assert alert.attackType == "SYN Flood"
    assert alert.sourceIp == "192.168.1.15"
    assert alert.destinationIp == "192.168.1.20"
    assert alert.destinationPort == 80
    assert alert.severity in ["CRITICAL", "HIGH"]
    assert alert.evidence.packetsCount >= 50
    assert alert.detectionSource == "RULE_ENGINE"

def test_port_scan_rule():
    ensure_sample_pcaps()
    pcap_path = settings.SAMPLES_DIR / "sample_portscan.pcap"
    packets = list(parse_pcap_file(pcap_path))
    features, _ = extract_features(packets)

    rule = PortScanRule()
    alerts = rule.evaluate(features, packets)

    assert len(alerts) > 0, "Port scan rule should detect sequential port probes"
    alert = alerts[0]
    assert alert.attackType == "Port Scan"
    assert alert.sourceIp == "192.168.1.31"
    assert alert.destinationIp == "192.168.1.20"
    assert alert.evidence.targetCount >= 1
    assert alert.detectionSource == "RULE_ENGINE"

def test_arp_spoof_rule():
    ensure_sample_pcaps()
    pcap_path = settings.SAMPLES_DIR / "sample_arp_spoof.pcap"
    packets = list(parse_pcap_file(pcap_path))
    features, _ = extract_features(packets)

    rule = ArpSpoofRule()
    alerts = rule.evaluate(features, packets)

    assert len(alerts) > 0, "ARP spoof rule should detect conflicting MACs"
    alert = alerts[0]
    assert alert.attackType == "ARP Spoofing"
    assert alert.severity == "CRITICAL"
    assert alert.detectionSource == "RULE_ENGINE"

def test_icmp_flood_rule():
    """Unit-level packet fixture for high-rate ICMP flood (30 packets in 0.06s = 500 pps)."""
    base_ts = 1700000000.0
    packets = []
    for i in range(25):
        packets.append(ParsedPacket(
            id_str=f"PKT-ICMP-{i:03d}",
            timestamp=base_ts + (i * 0.002),  # 2ms intervals -> 500 pps
            source_ip="192.168.1.77",
            dest_ip="192.168.1.50",
            protocol="ICMP",
            source_port=0,
            dest_port=0,
            size=64,
            flags=[],
            info="ICMP Echo (ping) Request",
            mac_src="02:00:00:00:07:77",
            mac_dst="02:00:00:00:05:50"
        ))

    features, packet_list = extract_features(packets)
    rule = IcmpFloodRule()
    alerts = rule.evaluate(features, packet_list)

    assert len(alerts) == 1, "ICMP flood rule should detect high-rate burst"
    alert = alerts[0]
    assert alert.attackType == "ICMP Flood"
    assert alert.sourceIp == "192.168.1.77"
    assert alert.destinationIp == "192.168.1.50"
    assert alert.evidence.packetsCount == 25
    assert alert.detectionSource == "RULE_ENGINE"

def test_brute_force_rule():
    """Unit-level packet fixture for repeated SSH credential probes (8 attempts to port 22)."""
    base_ts = 1700000100.0
    packets = []
    for i in range(8):
        packets.append(ParsedPacket(
            id_str=f"PKT-BF-{i:03d}",
            timestamp=base_ts + (i * 0.5),
            source_ip="192.168.1.99",
            dest_ip="192.168.1.10",
            protocol="TCP",
            source_port=50000 + i,
            dest_port=22,
            size=60,
            flags=["SYN"],
            info="50000 -> 22 [SYN]"
        ))

    features, packet_list = extract_features(packets)
    rule = BruteForceRule()
    alerts = rule.evaluate(features, packet_list)

    assert len(alerts) == 1, "Brute force rule should detect repeated authentication probes"
    alert = alerts[0]
    assert alert.attackType == "Brute Force"
    assert alert.sourceIp == "192.168.1.99"
    assert alert.destinationIp == "192.168.1.10"
    assert alert.destinationPort == 22
    assert alert.detectionSource == "RULE_ENGINE"

def test_benign_control_traffic():
    """
    Benign control fixture:
    Normal HTTP traffic, normal DNS lookups, normal 4-packet ping, and legitimate ARP.
    Verifies that NO rule-based alerts are triggered (zero false positives).
    """
    base_ts = 1700000200.0
    packets = []

    # 1. Normal HTTP session (SYN, SYN-ACK, ACK, GET, Response, FIN, ACK)
    packets.extend([
        ParsedPacket("P01", base_ts + 0.00, "192.168.1.10", "93.184.216.34", "TCP", 51514, 80, 60, ["SYN"], "SYN"),
        ParsedPacket("P02", base_ts + 0.02, "93.184.216.34", "192.168.1.10", "TCP", 80, 51514, 60, ["SYN", "ACK"], "SYN-ACK"),
        ParsedPacket("P03", base_ts + 0.03, "192.168.1.10", "93.184.216.34", "TCP", 51514, 80, 54, ["ACK"], "ACK"),
        ParsedPacket("P04", base_ts + 0.05, "192.168.1.10", "93.184.216.34", "TCP", 51514, 80, 250, ["ACK", "PSH"], "GET /"),
        ParsedPacket("P05", base_ts + 0.08, "93.184.216.34", "192.168.1.10", "TCP", 80, 51514, 800, ["ACK", "PSH"], "200 OK"),
        ParsedPacket("P06", base_ts + 0.10, "192.168.1.10", "93.184.216.34", "TCP", 51514, 80, 54, ["ACK", "FIN"], "FIN"),
        ParsedPacket("P07", base_ts + 0.11, "93.184.216.34", "192.168.1.10", "TCP", 80, 51514, 54, ["ACK", "FIN"], "FIN-ACK")
    ])

    # 2. Normal DNS queries (2 lookups at normal intervals)
    packets.extend([
        ParsedPacket("P08", base_ts + 0.20, "192.168.1.10", "8.8.8.8", "DNS", 53001, 53, 72, [], "DNS Query example.com"),
        ParsedPacket("P09", base_ts + 0.23, "8.8.8.8", "192.168.1.10", "DNS", 53, 53001, 88, [], "DNS Response 93.184.216.34"),
        ParsedPacket("P10", base_ts + 1.20, "192.168.1.10", "8.8.8.8", "DNS", 53002, 53, 72, [], "DNS Query api.example.com"),
        ParsedPacket("P11", base_ts + 1.24, "8.8.8.8", "192.168.1.10", "DNS", 53, 53002, 88, [], "DNS Response 93.184.216.35")
    ])

    # 3. Normal ping (4 ICMP echo requests spaced at 1 second intervals = 1 pps)
    for p_idx in range(4):
        t = base_ts + 2.0 + float(p_idx)
        packets.append(ParsedPacket(f"P_ICMP_REQ_{p_idx}", t, "192.168.1.10", "192.168.1.1", "ICMP", 0, 0, 64, [], "ICMP Echo Request"))
        packets.append(ParsedPacket(f"P_ICMP_RSP_{p_idx}", t + 0.005, "192.168.1.1", "192.168.1.10", "ICMP", 0, 0, 64, [], "ICMP Echo Reply"))

    # 4. Normal ARP (single MAC for gateway)
    packets.extend([
        ParsedPacket("P_ARP1", base_ts + 7.0, "192.168.1.10", "192.168.1.1", "ARP", 0, 0, 42, [], "who-has 192.168.1.1 tell 192.168.1.10", mac_src="00:11:22:33:44:55", mac_dst="ff:ff:ff:ff:ff:ff"),
        ParsedPacket("P_ARP2", base_ts + 7.001, "192.168.1.1", "192.168.1.10", "ARP", 0, 0, 42, [], "192.168.1.1 is-at 00:AA:BB:CC:DD:EE", mac_src="00:AA:BB:CC:DD:EE", mac_dst="00:11:22:33:44:55")
    ])

    features, packet_list = extract_features(packets)

    # Evaluate all 5 rules individually
    for rule in detection_engine.rules:
        rule_alerts = rule.evaluate(features, packet_list)
        assert len(rule_alerts) == 0, f"Benign traffic should NOT trigger {rule.name}, got: {rule_alerts}"

    # Evaluate full detection engine
    all_alerts = detection_engine.analyze(features, packet_list, persist_to_db=False)
    assert len(all_alerts) == 0, f"Benign traffic should produce 0 alerts, got: {all_alerts}"

def test_mixed_traffic_pcap_detection():
    """
    Test the actual netscope_test_mixed_traffic.pcap:
    Must detect all 4 distinct attack types present in the file:
    1. Port Scan (probes to 18 ports)
    2. SYN Flood (90 SYN packets to port 443 with 0 ACK)
    3. ICMP Flood (24 ICMP packets in 0.069s = 348 pps)
    4. ARP Spoofing (Conflicting MACs claiming 192.168.1.1)
    All must have detectionSource == 'RULE_ENGINE'.
    """
    pcap_path = settings.SAMPLES_DIR / "netscope_test_mixed_traffic.pcap"
    if not pcap_path.exists():
        fallback = Path(r"C:\Users\Jagadeesh\Downloads\netscope_test_mixed_traffic.pcap")
        if fallback.exists():
            pcap_path = fallback

    assert pcap_path.exists(), "netscope_test_mixed_traffic.pcap must exist for testing"

    packets = list(parse_pcap_file(pcap_path))
    assert len(packets) == 165, f"Expected 165 packets, got {len(packets)}"

    features, packet_list = extract_features(packets)
    alerts = detection_engine.analyze(features, packet_list, persist_to_db=False)

    attack_types = {a.attackType: a for a in alerts}
    assert "Port Scan" in attack_types, "Must detect Port Scan from 192.168.1.99"
    assert "SYN Flood" in attack_types, "Must detect SYN Flood from 192.168.1.77"
    assert "ICMP Flood" in attack_types, "Must detect ICMP Flood from 192.168.1.77"
    assert "ARP Spoofing" in attack_types, "Must detect ARP Spoofing claiming 192.168.1.1"

    # Verify detection source is RULE_ENGINE
    for a in alerts:
        if a.attackType in ["Port Scan", "SYN Flood", "ICMP Flood", "ARP Spoofing"]:
            assert a.detectionSource == "RULE_ENGINE"

    # Verify specific details of the alerts
    ps_alert = attack_types["Port Scan"]
    assert ps_alert.sourceIp == "192.168.1.99"
    assert ps_alert.destinationIp == "192.168.1.20"

    sf_alert = attack_types["SYN Flood"]
    assert sf_alert.sourceIp == "192.168.1.77"
    assert sf_alert.destinationIp == "192.168.1.50"
    assert sf_alert.destinationPort == 443

    icmp_alert = attack_types["ICMP Flood"]
    assert icmp_alert.sourceIp == "192.168.1.77"
    assert icmp_alert.destinationIp == "192.168.1.50"
    assert icmp_alert.evidence.packetsCount == 24

    arp_alert = attack_types["ARP Spoofing"]
    assert arp_alert.sourceIp == "192.168.1.1"
    assert arp_alert.severity == "CRITICAL"
