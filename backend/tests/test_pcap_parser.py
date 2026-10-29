import pytest
from pathlib import Path
from app.config import settings
from app.ingestion.pcap_parser import parse_pcap_file
from app.ingestion.feature_extractor import extract_features

def test_parse_sample_syn_flood():
    pcap_path = settings.SAMPLES_DIR / "sample_syn_flood.pcap"
    assert pcap_path.exists(), "Sample SYN flood PCAP must exist"
    
    packets = list(parse_pcap_file(pcap_path))
    assert len(packets) >= 100, f"Expected at least 100 packets, got {len(packets)}"
    
    first = packets[0]
    assert first.source_ip == "192.168.1.15"
    assert first.dest_ip == "192.168.1.20"
    assert first.dest_port == 80
    assert "SYN" in first.flags

    features, packet_list = extract_features(packets)
    assert features.total_packets == len(packets)
    assert "192.168.1.15" in features.unique_hosts
    assert "192.168.1.20" in features.unique_hosts
    assert features.protocol_counts["TCP"] > 0

def test_parse_sample_portscan():
    pcap_path = settings.SAMPLES_DIR / "sample_portscan.pcap"
    assert pcap_path.exists(), "Sample portscan PCAP must exist"
    
    packets = list(parse_pcap_file(pcap_path))
    assert len(packets) >= 20
    
    features, _ = extract_features(packets)
    ports = features.host_stats["192.168.1.31"]["dest_ports_contacted"]
    assert len(ports) >= 20, f"Expected >= 20 contacted ports, got {len(ports)}"
