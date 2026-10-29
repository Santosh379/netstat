"""
NetScope AI Machine Learning Anomaly Detection Package.
"""

from .schema import FlowFeatures, FEATURE_NAMES, SCHEMA_VERSION
from .model_manager import model_manager, ModelManager
from .inference import score_flow, flow_to_security_alert, AnomalyInferenceResult
from .flow_aggregator import aggregate_flows

__all__ = [
    "FlowFeatures",
    "FEATURE_NAMES",
    "SCHEMA_VERSION",
    "model_manager",
    "ModelManager",
    "score_flow",
    "flow_to_security_alert",
    "AnomalyInferenceResult",
    "aggregate_flows"
]
