"""
Inference engine for NetScope AI ML Anomaly Detection.
Evaluates flow feature vectors against trained Isolation Forest model,
generates normalized anomaly scores, and produces evidence-backed SOC alerts.
"""

from typing import Optional, NamedTuple
from datetime import datetime, timezone
import numpy as np

from .schema import FlowFeatures, FEATURE_NAMES
from .model_manager import model_manager
from ..schemas.alert import SecurityAlert, AlertEvidence

class AnomalyInferenceResult(NamedTuple):
    is_anomaly: bool
    anomaly_score: float
    decision_threshold: float
    model_name: str
    model_version: str
    contributing_features: dict[str, float]
    explanation: str

def score_flow(flow: FlowFeatures) -> Optional[AnomalyInferenceResult]:
    """
    Evaluates a single FlowFeatures object.
    Returns AnomalyInferenceResult if model is available, None otherwise.
    """
    artifact = model_manager.get_artifact()
    if artifact is None:
        return None

    # Transform feature vector
    feat_array = flow.to_feature_array()
    transformed = artifact.preprocessor.transform_array(feat_array)

    # Compute anomaly score
    if hasattr(artifact.model, "predict_proba"):
        normalized_score = float(artifact.model.predict_proba(transformed)[0, 1])
    else:
        raw_score = float(artifact.model.score_samples(transformed)[0])
        span = artifact.max_score - artifact.min_score
        if span <= 0:
            span = 1.0
        normalized_score = float(np.clip((artifact.max_score - raw_score) / span, 0.0, 1.0))

    threshold = float(artifact.threshold)
    is_anomaly = normalized_score > threshold

    # Determine which features show greatest deviation from the normal baseline
    contributing: dict[str, float] = {}
    feat_dict = flow.to_feature_dict()
    medians = artifact.preprocessor.feature_medians

    deviation_ratios: list[tuple[str, float, float, float]] = []
    for name, val in feat_dict.items():
        med = medians.get(name, 0.0)
        # Avoid division by zero
        denom = max(abs(med), 1.0)
        ratio = abs(val - med) / denom
        deviation_ratios.append((name, ratio, val, med))

    # Sort by ratio of deviation from normal median
    deviation_ratios.sort(key=lambda x: x[1], reverse=True)
    top_deviations = deviation_ratios[:4]

    for name, _, val, _ in top_deviations:
        contributing[name] = round(float(val), 2)

    # Formulate cautious SOC explanation
    top_reasons = []
    for name, ratio, val, med in top_deviations:
        if ratio > 2.0:
            if "Rate" in name or "Bytes/s" in name or "Packets/s" in name:
                top_reasons.append(f"{name} ({val:,.1f}) significantly exceeds normal baseline ({med:,.1f})")
            elif "SYN" in name:
                top_reasons.append(f"Unusually elevated SYN flag count ({int(val)})")
            elif "Duration" in name:
                top_reasons.append(f"Abnormal flow duration ({val / 1e6:.2f}s vs normal {med / 1e6:.2f}s)")
            else:
                top_reasons.append(f"{name} ({val:.1f}) deviates from standard pattern")

    if not top_reasons:
        explanation = (
            f"The flow between {flow.source_ip} and {flow.destination_ip} exhibited statistical multivariate "
            f"outlier characteristics (score {normalized_score:.2f} vs threshold {threshold:.2f}) across "
            f"packet timing, byte distribution, and transmission symmetry."
        )
    else:
        explanation = (
            f"Isolation Forest identified statistical flow anomalies: "
            + "; ".join(top_reasons)
            + f". Model anomaly score: {normalized_score:.2f} (decision threshold: {threshold:.2f})."
        )

    return AnomalyInferenceResult(
        is_anomaly=is_anomaly,
        anomaly_score=round(normalized_score, 3),
        decision_threshold=threshold,
        model_name=artifact.metadata.get("model_name", "IsolationForest"),
        model_version=artifact.metadata.get("model_version", "1.0.0"),
        contributing_features=contributing,
        explanation=explanation
    )

def flow_to_security_alert(flow: FlowFeatures, result: AnomalyInferenceResult) -> SecurityAlert:
    """
    Transforms an anomalous flow inference result into a persistent SecurityAlert.
    """
    # Determine severity based on calibrated anomaly score
    if result.anomaly_score >= 0.85:
        severity = "CRITICAL"
        threat_score = 90
    elif result.anomaly_score >= 0.65:
        severity = "HIGH"
        threat_score = 75
    else:
        severity = "MEDIUM"
        threat_score = 60

    # Stable identifier based on endpoints and timestamp
    stable_id = f"ALT-ML-{abs(hash((flow.source_ip, flow.destination_ip, flow.protocol, int(flow.start_timestamp)))) % 100000:05d}"
    
    duration_sec = (flow.end_timestamp - flow.start_timestamp)
    duration_str = f"{max(0.0, duration_sec):.2f}s"
    start_ts = flow.start_timestamp or datetime.now(timezone.utc).timestamp()
    try:
        ts_str = datetime.fromtimestamp(start_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    evidence = AlertEvidence(
        packetsCount=int(flow.total_fwd_packets + flow.total_bwd_packets),
        responseCount=int(flow.total_bwd_packets),
        durationStr=duration_str,
        targetCount=1,
        rawDetails=[
            f"ML Anomaly Score: {result.anomaly_score:.3f} (Threshold: {result.decision_threshold:.2f})",
            f"Model: {result.model_name} v{result.model_version}",
            f"Flow Bytes/s: {flow.flow_bytes_per_sec:,.1f} B/s | Packets/s: {flow.flow_packets_per_sec:,.1f} pps",
            f"Forward Packets: {int(flow.total_fwd_packets)} | Backward Packets: {int(flow.total_bwd_packets)}",
            f"SYN: {int(flow.syn_flag_count)} | RST: {int(flow.rst_flag_count)} | ACK: {int(flow.ack_flag_count)}"
        ]
    )

    recommendations = [
        f"Inspect host {flow.source_ip} for unexpected outbound connections or unauthorized process activity.",
        f"Verify destination {flow.destination_ip}:{flow.destination_port or 0} service logs for volumetric spikes or unauthenticated sessions.",
        "Check adjacent packet captures for correlated lateral movement or port scanning.",
        "Correlate with endpoint detection (EDR) telemetry to confirm whether this flow represents legitimate burst traffic or anomalous exfiltration."
    ]

    return SecurityAlert(
        id=stable_id,
        title=f"Statistical Network Anomaly: {flow.source_ip} -> {flow.destination_ip}",
        severity=severity,
        attackType="Network Anomaly",
        sourceIp=flow.source_ip,
        destinationIp=flow.destination_ip,
        sourcePort=flow.source_port,
        destinationPort=flow.destination_port,
        timestamp=ts_str,
        duration=duration_str,
        status="Active",
        threatScore=threat_score,
        evidence=evidence,
        aiExplanation=result.explanation,
        recommendations=recommendations,
        interface="All",
        detectionSource="ML_ANOMALY",
        modelName=result.model_name,
        modelVersion=result.model_version,
        anomalyScore=result.anomaly_score,
        decisionThreshold=result.decision_threshold,
        observedFeatures=result.contributing_features
    )
