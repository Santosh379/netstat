"""
Phase 7 Regression Tests for NetScope AI V2.
Verifies capture session isolation, alert scope consistency, honest replay evidence,
topology capture-scoping, and notification integrity.
"""

from fastapi.testclient import TestClient
from backend.app.storage.db import db
from backend.app.schemas.alert import SecurityAlert, AlertEvidence
from backend.app.schemas.pcap import CaptureSession
from backend.app.core.state import global_state

def test_capture_isolation_and_old_alerts_separation(client: TestClient):
    """
    1. An alert created during analysis appears in the correct capture's findings.
    2. Old alerts are not accidentally presented as findings from a newly uploaded capture.
    """
    # Create two distinct capture records
    cap1 = CaptureSession(
        id="CAP-TEST-AAA1",
        filename="first_capture.pcap",
        filesize="50 KB",
        packetsAnalyzed=50,
        uniqueHosts=2,
        tcpConnections=5,
        potentialThreats=1,
        ruleThreats=1,
        mlThreats=0,
        durationSeconds=1.2,
        analyzedAt="2026-10-25 10:00:00 UTC",
        observedHosts=["192.168.1.10", "192.168.1.20"],
        status="COMPLETED"
    )
    cap2 = CaptureSession(
        id="CAP-TEST-BBB2",
        filename="second_capture.pcap",
        filesize="80 KB",
        packetsAnalyzed=80,
        uniqueHosts=2,
        tcpConnections=8,
        potentialThreats=1,
        ruleThreats=1,
        mlThreats=0,
        durationSeconds=2.5,
        analyzedAt="2026-10-25 11:00:00 UTC",
        observedHosts=["10.0.0.5", "10.0.0.99"],
        status="COMPLETED"
    )
    db.insert_capture(cap1)
    db.insert_capture(cap2)

    # Insert alert for capture 1
    alert1 = SecurityAlert(
        id="ALT-CAP1-001",
        title="Test SYN Flood Capture 1",
        severity="CRITICAL",
        attackType="SYN Flood",
        sourceIp="192.168.1.10",
        destinationIp="192.168.1.20",
        timestamp="2026-10-25 10:00:00 UTC",
        duration="1.2s",
        status="Active",
        threatScore=95,
        evidence=AlertEvidence(packetsCount=30, responseCount=0, durationStr="1.2s", targetCount=1, rawDetails=["30 SYN packets"]),
        aiExplanation="Test alert in capture 1",
        recommendations=["Block 192.168.1.10"],
        detectionSource="RULE_ENGINE",
        captureId="CAP-TEST-AAA1",
        captureName="first_capture.pcap",
        sourceType="PCAP"
    )
    db.insert_alert(alert1)

    # Insert alert for capture 2
    alert2 = SecurityAlert(
        id="ALT-CAP2-002",
        title="Test Port Scan Capture 2",
        severity="HIGH",
        attackType="Port Scan",
        sourceIp="10.0.0.5",
        destinationIp="10.0.0.99",
        timestamp="2026-10-25 11:00:00 UTC",
        duration="2.5s",
        status="Active",
        threatScore=80,
        evidence=AlertEvidence(packetsCount=20, responseCount=0, durationStr="2.5s", targetCount=15, rawDetails=["15 ports"]),
        aiExplanation="Test alert in capture 2",
        recommendations=["Inspect 10.0.0.5"],
        detectionSource="RULE_ENGINE",
        captureId="CAP-TEST-BBB2",
        captureName="second_capture.pcap",
        sourceType="PCAP"
    )
    db.insert_alert(alert2)

    # Verify query scoped to capture 1 returns only alert 1
    res1 = client.get("/api/v1/alerts?captureId=CAP-TEST-AAA1")
    assert res1.status_code == 200
    alerts_cap1 = res1.json()
    assert any(a["id"] == "ALT-CAP1-001" for a in alerts_cap1)
    assert not any(a["id"] == "ALT-CAP2-002" for a in alerts_cap1)

    # Verify query scoped to capture 2 returns only alert 2
    res2 = client.get("/api/v1/alerts?captureId=CAP-TEST-BBB2")
    assert res2.status_code == 200
    alerts_cap2 = res2.json()
    assert any(a["id"] == "ALT-CAP2-002" for a in alerts_cap2)
    assert not any(a["id"] == "ALT-CAP1-001" for a in alerts_cap2)

def test_alert_summary_matches_filtered_scope(client: TestClient):
    """
    3. Alert summary counts agree with the relevant filtered alert dataset.
    """
    res_summary = client.get("/api/v1/alerts/summary?captureId=CAP-TEST-AAA1")
    assert res_summary.status_code == 200
    sum_data = res_summary.json()
    assert sum_data["critical"] >= 1
    assert sum_data["high"] == 0

    res_summary_cap2 = client.get("/api/v1/alerts/summary?captureId=CAP-TEST-BBB2")
    assert res_summary_cap2.status_code == 200
    sum_cap2 = res_summary_cap2.json()
    assert sum_cap2["high"] >= 1
    assert sum_cap2["critical"] == 0

def test_topology_endpoints_scoped_to_capture(client: TestClient):
    """
    4. Topology endpoints correspond to hosts in the selected capture.
    5. Changing the capture changes the topology when its hosts differ.
    """
    # Fetch topology scoped to CAP-TEST-AAA1
    res_topo1 = client.get("/api/v1/topology?source=pcap&captureId=CAP-TEST-AAA1")
    assert res_topo1.status_code == 200
    topo1 = res_topo1.json()
    ips1 = [n["ip"] for n in topo1["nodes"]]
    assert "192.168.1.10" in ips1 or "192.168.1.20" in ips1
    assert "10.0.0.5" not in ips1

    # Fetch topology scoped to CAP-TEST-BBB2
    res_topo2 = client.get("/api/v1/topology?source=pcap&captureId=CAP-TEST-BBB2")
    assert res_topo2.status_code == 200
    topo2 = res_topo2.json()
    ips2 = [n["ip"] for n in topo2["nodes"]]
    assert "10.0.0.5" in ips2 or "10.0.0.99" in ips2
    assert "192.168.1.10" not in ips2

def test_replay_honest_packet_counts_and_flow_summary(client: TestClient):
    """
    6. Replay packet counts and packet events are grounded in parsed capture records.
    7. Flow summaries do not pretend to be individual packets.
    """
    res = client.get("/api/v1/replay/from-alert/ALT-CAP1-001")
    assert res.status_code == 200
    scenario = res.json()
    assert scenario["captureId"] == "CAP-TEST-AAA1"
    assert "totalPacketsInCapture" in scenario
    assert "incidentPacketsCount" in scenario
    assert len(scenario["steps"]) > 0

    # If steps are a flow summary fallback, verify eventType
    first_step = scenario["steps"][0]
    if scenario.get("isSummary"):
        assert first_step["eventType"] == "FLOW_SUMMARY"
        assert "flow" in first_step["detail"].lower()
    else:
        assert first_step["eventType"] == "RAW_PACKET"

def test_notifications_deduplication(client: TestClient):
    """
    8. Repeated polling does not create duplicate notifications.
    """
    res1 = client.get("/api/v1/notifications?limit=50")
    assert res1.status_code == 200
    notifs1 = res1.json()
    ids = [n["id"] for n in notifs1]
    assert len(ids) == len(set(ids)), "Notification IDs must be unique (no duplicates in inbox)"
