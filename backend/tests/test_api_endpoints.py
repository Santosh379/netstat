import io
from pathlib import Path
from backend.app.config import settings

def test_capture_endpoints(client):
    res_status = client.get("/api/v1/capture/status")
    assert res_status.status_code == 200
    data = res_status.json()
    assert "packetsPerSec" in data
    assert "bytesPerSec" in data

    res_pkts = client.get("/api/v1/capture/packets")
    assert res_pkts.status_code == 200
    assert isinstance(res_pkts.json(), list)

def test_pcap_samples_and_analysis(client):
    res_samples = client.get("/api/v1/pcap/samples")
    assert res_samples.status_code == 200
    samples = res_samples.json()
    assert len(samples) > 0
    sample_names = [s["name"] for s in samples]
    assert "sample_syn_flood.pcap" in sample_names

    res_analysis = client.post("/api/v1/pcap/analyze-sample/sample_syn_flood.pcap")
    assert res_analysis.status_code == 200
    analysis = res_analysis.json()
    assert analysis["filename"] == "sample_syn_flood.pcap"
    assert analysis["packetsAnalyzed"] >= 100
    assert analysis["potentialThreats"] > 0
    assert len(analysis["topProtocols"]) > 0

def test_alerts_endpoints(client):
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert isinstance(alerts, list)

    res_summary = client.get("/api/v1/alerts/summary")
    assert res_summary.status_code == 200
    summary = res_summary.json()
    assert "critical" in summary
    assert "high" in summary

def test_notifications_endpoints(client):
    # Fetch notifications
    res = client.get("/api/v1/notifications")
    assert res.status_code == 200
    notifs = res.json()
    assert isinstance(notifs, list)

    # Unread count
    res_count = client.get("/api/v1/notifications/unread-count")
    assert res_count.status_code == 200
    cnt_data = res_count.json()
    assert "unreadCount" in cnt_data
    assert "totalCount" in cnt_data

    # Mark all read
    res_all = client.post("/api/v1/notifications/mark-all-read")
    assert res_all.status_code == 200
    assert res_all.json()["success"] is True

    # Check unread count is 0 after mark all read
    res_count2 = client.get("/api/v1/notifications/unread-count")
    assert res_count2.json()["unreadCount"] == 0

    # Dismiss first notification if available
    if notifs:
        first_id = notifs[0]["id"]
        res_dis = client.delete(f"/api/v1/notifications/{first_id}")
        assert res_dis.status_code == 200
        assert res_dis.json()["dismissed"] is True

def test_dynamic_topology_endpoint(client):
    res_topo = client.get("/api/v1/topology?source=auto")
    assert res_topo.status_code == 200
    topo = res_topo.json()
    assert "dataSource" in topo
    assert "totalObservedHosts" in topo
    assert isinstance(topo["nodes"], list)
    assert len(topo["nodes"]) > 0
    assert isinstance(topo["links"], list)

    # Verify node fields are evidence-based
    first_node = topo["nodes"][0]
    assert "ip" in first_node
    assert "role" in first_node
    assert "status" in first_node
    assert "classification" in first_node
    assert "packetsIn" in first_node
    assert "packetsOut" in first_node

def test_replay_and_scenario_ordering(client):
    res_scenarios = client.get("/api/v1/replay/scenarios")
    assert res_scenarios.status_code == 200
    scenarios = res_scenarios.json()
    assert len(scenarios) > 0
    first = scenarios[0]
    assert len(first["steps"]) > 0
    assert "knownFacts" in first
    assert "uncertainties" in first

    # Verify chronological ordering of steps
    steps = first["steps"]
    for i in range(len(steps) - 1):
        assert steps[i]["id"] < steps[i+1]["id"]
        assert "timestamp" in steps[i]
        assert "sourceIp" in steps[i]
        assert "destinationIp" in steps[i]

def test_ml_performance_and_switching(client):
    res_perf = client.get("/api/v1/system/ml/performance")
    assert res_perf.status_code == 200
    data = res_perf.json()
    assert "active_model" in data
    assert "comparison" in data
    assert "baseline" in data["comparison"]
    assert "candidate" in data["comparison"]

    # Switch to HistGradientBoosting
    res_switch = client.post("/api/v1/system/ml/switch", json={"model_name": "HistGradientBoosting"})
    assert res_switch.status_code == 200
    assert res_switch.json()["success"] is True

    # Switch back to IsolationForest
    res_switch_back = client.post("/api/v1/system/ml/switch", json={"model_name": "IsolationForest"})
    assert res_switch_back.status_code == 200
    assert res_switch_back.json()["success"] is True

def test_empty_and_malformed_pcap(client):
    # Empty file
    res_empty = client.post(
        "/api/v1/pcap/upload",
        files={"file": ("empty.pcap", io.BytesIO(b""), "application/vnd.tcpdump.pcap")}
    )
    assert res_empty.status_code == 400

    # Corrupt header
    res_bad = client.post(
        "/api/v1/pcap/upload",
        files={"file": ("corrupt.pcap", io.BytesIO(b"GARBAGE_BYTES_NOT_A_PCAP"), "application/vnd.tcpdump.pcap")}
    )
    assert res_bad.status_code == 400

def test_reports_and_dashboard_stats(client):
    res_dash = client.get("/api/v1/dashboard/stats?timeRange=1H")
    assert res_dash.status_code == 200
    dash = res_dash.json()
    assert "totalPackets" in dash
    assert "trafficTimeline" in dash

    res_reports = client.get("/api/v1/reports")
    assert res_reports.status_code == 200
    reports = res_reports.json()
    assert len(reports) > 0
