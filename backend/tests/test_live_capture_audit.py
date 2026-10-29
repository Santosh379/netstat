"""
Tests for Live Packet Capture Pipeline Audit, Mode Labeling, Counter Separation,
Stop Cleanup, and Diagnostic Verification.
"""

import time
import pytest
from unittest.mock import patch

from backend.app.core.state import global_state
from backend.app.schemas.packet import LivePacket
from backend.app.ingestion.sniffer import sniffer_manager
from backend.app.detection.engine import detection_engine
from backend.app.ingestion.pcap_parser import ParsedPacket
from backend.app.ingestion.feature_extractor import extract_features


def test_capture_mode_transitions_and_clean_stop():
    """Verify that start/stop transitions set explicit capture_mode and clean up threads."""
    # Ensure starting in synthetic mode sets SYNTHETIC
    res = sniffer_manager.start(interface="Synthetic Mode", force_synthetic=True)
    assert res["status"] in ["started", "already_running"]
    assert global_state.capture_mode == "SYNTHETIC"
    assert global_state.is_monitoring is True

    time.sleep(0.3)
    stats = global_state.get_capture_stats()
    assert stats.captureMode == "SYNTHETIC"
    assert stats.elapsedSeconds >= 0.0

    # Stop monitoring
    stop_res = sniffer_manager.stop()
    assert stop_res["status"] == "stopped"
    assert stop_res["capture_mode"] == "STOPPED"
    assert global_state.is_monitoring is False
    assert global_state.capture_mode == "STOPPED"

    # Verify rates reset to 0 when stopped
    pps, bps = global_state.get_rates()
    assert pps == 0
    assert bps == "0 B/s"

    stopped_stats = global_state.get_capture_stats()
    assert stopped_stats.captureMode == "STOPPED"
    assert stopped_stats.packetsPerSec == 0


def test_counter_accuracy_and_separation():
    """Verify that packets captured, processed, flows, and ML inferences are tracked separately."""
    initial_processed = global_state.packets_processed_count
    initial_flows = global_state.total_flows_count

    # Ingest 3 distinct packets
    pkt1 = LivePacket(
        id="PKT-TEST-001",
        timestamp="12:00:01",
        sourceIp="10.1.1.1",
        destinationIp="10.1.1.2",
        protocol="TCP",
        sourcePort=12345,
        destinationPort=80,
        size=200,
        flags=["SYN"],
        info="SYN test"
    )
    pkt2 = LivePacket(
        id="PKT-TEST-002",
        timestamp="12:00:02",
        sourceIp="10.1.1.1",
        destinationIp="10.1.1.2",
        protocol="TCP",
        sourcePort=12345,
        destinationPort=80,
        size=500,
        flags=["ACK"],
        info="ACK test (same flow)"
    )
    pkt3 = LivePacket(
        id="PKT-TEST-003",
        timestamp="12:00:03",
        sourceIp="10.1.1.5",
        destinationIp="10.1.1.9",
        protocol="TCP",
        sourcePort=54321,
        destinationPort=443,
        size=350,
        flags=["SYN"],
        info="Different flow"
    )

    global_state.add_packet(pkt1, 200)
    global_state.add_packet(pkt2, 500)
    global_state.add_packet(pkt3, 350)

    # Packets processed should increment by 3
    assert global_state.packets_processed_count == initial_processed + 3
    assert global_state.total_packets_count == global_state.packets_processed_count

    # Flows should have incremented by 2 (pkt1 and pkt2 share same 4-tuple; pkt3 is new)
    assert global_state.total_flows_count >= initial_flows + 2


def test_ml_unchanged_flow_caching():
    """Verify that scoring identical unchanged flows uses cache and does not repeat ML inference."""
    initial_inferences = global_state.ml_inferences_count

    # Create dummy parsed packets representing a single conversation
    packets = [
        ParsedPacket(
            id_str=f"P-{i}",
            timestamp=100.0 + i * 0.1,
            source_ip="192.168.10.5",
            dest_ip="192.168.10.20",
            protocol="TCP",
            source_port=40000,
            dest_port=80,
            size=100,
            flags=["ACK"],
            info="Flow test"
        )
        for i in range(5)
    ]
    features, _ = extract_features(packets)

    # First analysis pass: should evaluate ML and populate cache
    detection_engine.analyze(features, packets, persist_to_db=False)
    inferences_after_pass1 = global_state.ml_inferences_count
    assert inferences_after_pass1 > initial_inferences

    # Second analysis pass with identical packets and flow duration:
    detection_engine.analyze(features, packets, persist_to_db=False)
    inferences_after_pass2 = global_state.ml_inferences_count

    # Unchanged flow must be retrieved from cache without repeating score_flow
    assert inferences_after_pass2 == inferences_after_pass1


def test_real_capture_diagnostics_when_npcap_missing():
    """Verify that requesting physical capture when Npcap is missing generates an explicit diagnostic and labels mode as SYNTHETIC."""
    with patch("backend.app.ingestion.sniffer.is_npcap_available", return_value=False):
        sniffer_manager.stop()
        res = sniffer_manager.start(interface="Ethernet", force_synthetic=False)

        assert res["capture_mode"] == "SYNTHETIC"
        assert res["is_synthetic"] is True
        assert global_state.capture_mode == "SYNTHETIC"
        assert global_state.capture_error is not None
        assert "Npcap driver not detected" in global_state.capture_error

        # Ensure capture stats also expose the diagnostic
        stats = global_state.get_capture_stats()
        assert stats.captureMode == "SYNTHETIC"
        assert stats.captureError is not None

        sniffer_manager.stop()


def test_packet_rate_calculation_over_interval():
    """Verify that packet rate is computed over a 1.0s window from counter differences."""
    global_state.recent_packet_times.clear()
    global_state.is_monitoring = True
    global_state.capture_mode = "SYNTHETIC"

    now = time.time()
    # Add 10 packets within the last 0.5s
    for i in range(10):
        global_state.recent_packet_times.append((now - 0.2 + (i * 0.01), 100))

    # Add 5 packets older than 1.5s (should be pruned)
    global_state.recent_packet_times.appendleft((now - 2.0, 100))
    global_state.recent_packet_times.appendleft((now - 2.5, 100))

    pps, bps = global_state.get_rates()
    # Should accurately count only the 10 recent packets
    assert pps == 10
    assert "KB/s" in bps or "B/s" in bps

    sniffer_manager.stop()
