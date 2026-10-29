"""
Automated Unit and Integration Tests for NetScope AI ML Anomaly Detection Pipeline.
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings
from backend.app.ml.schema import FlowFeatures, FEATURE_NAMES, SCHEMA_VERSION
from backend.app.ml.preprocessor import MLPreprocessor
from backend.app.ml.model_manager import ModelManager, model_manager
from backend.app.ml.inference import score_flow, flow_to_security_alert
from backend.app.ml.flow_aggregator import aggregate_flows
from backend.app.ingestion.pcap_parser import ParsedPacket, parse_pcap_file
from backend.app.detection.engine import detection_engine
from backend.app.ingestion.feature_extractor import extract_features
from backend.app.storage.sample_generator import ensure_sample_pcaps

client = TestClient(app)

def test_feature_schema_definition():
    """Verify feature schema matches expected 17 attributes in exact order."""
    assert len(FEATURE_NAMES) == 17
    assert FEATURE_NAMES[0] == "Flow Duration"
    assert FEATURE_NAMES[1] == "Total Fwd Packets"
    assert FEATURE_NAMES[-1] == "Average Packet Size"
    assert SCHEMA_VERSION == "1.0.0"

def test_flow_features_validation_and_array_conversion():
    """Test FlowFeatures dataclass validation and array transformations."""
    # Valid flow
    flow = FlowFeatures(
        flow_duration=1000.0,
        total_fwd_packets=5.0,
        total_bwd_packets=3.0,
        total_fwd_bytes=500.0,
        total_bwd_bytes=300.0,
        flow_bytes_per_sec=800.0,
        flow_packets_per_sec=8.0,
        flow_iat_mean=125.0,
        flow_iat_std=20.0,
        min_packet_length=60.0,
        max_packet_length=150.0,
        packet_length_mean=100.0,
        packet_length_std=30.0,
        syn_flag_count=1.0,
        rst_flag_count=0.0,
        ack_flag_count=7.0,
        average_packet_size=100.0,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20"
    )
    valid, err = flow.validate()
    assert valid is True
    assert err is None

    arr = flow.to_feature_array()
    assert arr.shape == (17,)
    assert arr[0] == 1000.0

    d = flow.to_feature_dict()
    assert len(d) == 17
    assert d["Total Fwd Packets"] == 5.0

    # Invalid flow (0 packets)
    invalid_flow = FlowFeatures(total_fwd_packets=0, total_bwd_packets=0)
    valid_inv, err_inv = invalid_flow.validate()
    assert valid_inv is False
    assert "0 packets" in err_inv

def test_preprocessor_handles_nans_and_infinities():
    """Verify MLPreprocessor handles extreme values, infinities, and missing features."""
    pre = MLPreprocessor()
    df = pd.DataFrame({
        feat: [10.0, np.inf, np.nan, -5.0] for feat in FEATURE_NAMES
    })
    pre.fit(df)
    arr = pre.transform_df(df)
    assert arr.shape == (4, 17)
    assert not np.any(np.isnan(arr))
    assert not np.any(np.isinf(arr))
    assert np.all(arr >= 0.0)

    # Rejection of invalid column count
    with pytest.raises(ValueError):
        pre.transform_array(np.array([1.0, 2.0]))

def test_model_manager_loading_and_status():
    """Verify model manager loads the trained artifact and reports status."""
    assert model_manager.is_available() is True
    status = model_manager.get_status()
    assert status["available"] is True
    assert status["model_name"] == "IsolationForest"
    assert status["features_count"] == 17
    assert status["decision_threshold"] == 0.50

def test_inference_scoring_and_alert_generation():
    """Test score_flow and flow_to_security_alert on an anomalous flow."""
    # Construct an extreme outlier flow (massive byte rate and packet length)
    outlier_flow = FlowFeatures(
        flow_duration=50000.0,
        total_fwd_packets=500.0,
        total_bwd_packets=10.0,
        total_fwd_bytes=700000.0,
        total_bwd_bytes=600.0,
        flow_bytes_per_sec=14000000.0,
        flow_packets_per_sec=10200.0,
        flow_iat_mean=98.0,
        flow_iat_std=12.0,
        min_packet_length=1400.0,
        max_packet_length=1500.0,
        packet_length_mean=1400.0,
        packet_length_std=10.0,
        syn_flag_count=0.0,
        rst_flag_count=0.0,
        ack_flag_count=510.0,
        average_packet_size=1400.0,
        source_ip="10.99.99.99",
        destination_ip="10.0.0.1",
        source_port=4444,
        destination_port=80
    )

    inference = score_flow(outlier_flow)
    assert inference is not None
    assert inference.anomaly_score > 0.40
    assert len(inference.contributing_features) > 0
    assert "IsolationForest" in inference.model_name

    alert = flow_to_security_alert(outlier_flow, inference)
    assert alert.attackType == "Network Anomaly"
    assert alert.detectionSource == "ML_ANOMALY"
    assert alert.modelName == "IsolationForest"
    assert alert.anomalyScore == inference.anomaly_score
    assert len(alert.recommendations) > 0

def test_unavailable_or_corrupted_model_handling(tmp_path):
    """Verify ModelManager fails gracefully on nonexistent or corrupted model files."""
    missing_manager = ModelManager(model_path=tmp_path / "missing.joblib")
    assert missing_manager.is_available() is False
    status = missing_manager.get_status()
    assert status["available"] is False
    assert "not found" in status["error"].lower()

def test_flow_aggregation_from_packets():
    """Verify aggregate_flows correctly groups packets into bidirectional conversations."""
    pkts = [
        ParsedPacket(
            id_str="P1", timestamp=100.0, source_ip="192.168.1.10", dest_ip="192.168.1.20",
            protocol="TCP", source_port=50000, dest_port=80, size=60, flags=["SYN"], info=""
        ),
        ParsedPacket(
            id_str="P2", timestamp=100.01, source_ip="192.168.1.20", dest_ip="192.168.1.10",
            protocol="TCP", source_port=80, dest_port=50000, size=60, flags=["SYN", "ACK"], info=""
        ),
        ParsedPacket(
            id_str="P3", timestamp=100.02, source_ip="192.168.1.10", dest_ip="192.168.1.20",
            protocol="TCP", source_port=50000, dest_port=80, size=500, flags=["ACK"], info=""
        )
    ]
    flows = aggregate_flows(pkts)
    assert len(flows) == 1
    f = flows[0]
    assert f.total_fwd_packets == 2.0
    assert f.total_bwd_packets == 1.0
    assert f.total_fwd_bytes == 560.0
    assert f.total_bwd_bytes == 60.0
    assert f.syn_flag_count >= 1.0

def test_pcap_analysis_with_ml_anomaly():
    """Verify that analyzing sample_ml_anomaly.pcap triggers ML anomaly findings."""
    ensure_sample_pcaps()
    res = client.post("/api/v1/pcap/analyze-sample/sample_ml_anomaly.pcap")
    assert res.status_code == 200
    data = res.json()
    assert data["packetsAnalyzed"] > 0
    assert data["potentialThreats"] >= 1
    ml_alerts = [a for a in data["alerts"] if a.get("detectionSource") == "ML_ANOMALY"]
    assert len(ml_alerts) >= 1
    assert ml_alerts[0]["attackType"] == "Network Anomaly"

def test_ml_disabled_graceful_fallback():
    """Verify that when ML_ENABLED is False, rule-based detection continues normally."""
    original = settings.ML_ENABLED
    try:
        settings.ML_ENABLED = False
        ensure_sample_pcaps()
        res = client.post("/api/v1/pcap/analyze-sample/sample_portscan.pcap")
        assert res.status_code == 200
        data = res.json()
        # Rule-based portscan rule still functions
        assert data["potentialThreats"] >= 1
        assert any("Port Scan" in s["signature"] for s in data["detectedSignatures"])
        # No ML anomalies generated when disabled
        ml_alerts = [a for a in data["alerts"] if a.get("detectionSource") == "ML_ANOMALY"]
        assert len(ml_alerts) == 0
    finally:
        settings.ML_ENABLED = original

def test_system_ml_endpoints():
    """Verify GET /system/status, GET /system/ml, and POST /system/ml/toggle endpoints."""
    # Check status endpoint
    st_res = client.get("/api/v1/system/status")
    assert st_res.status_code == 200
    st_data = st_res.json()
    assert "ml_enabled" in st_data
    assert "ml_model_info" in st_data
    assert st_data["ml_model_info"]["available"] is True

    # Check dedicated ML endpoint
    ml_res = client.get("/api/v1/system/ml")
    assert ml_res.status_code == 200
    ml_data = ml_res.json()
    assert ml_data["enabled"] is True
    assert ml_data["details"]["model_name"] == "IsolationForest"

    # Toggle ML
    tog_res = client.post("/api/v1/system/ml/toggle")
    assert tog_res.status_code == 200
    assert tog_res.json()["enabled"] is False

    # Restore ML
    tog_back = client.post("/api/v1/system/ml/toggle")
    assert tog_back.status_code == 200
    assert tog_back.json()["enabled"] is True
