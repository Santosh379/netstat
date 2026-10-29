"""
Multi-strategy Detection Engine for NetScope AI.
Combines deterministic rule-based threat detection with unsupervised ML flow anomaly detection.
"""

import time
import logging
from typing import Optional
from .rules.port_scan import PortScanRule
from .rules.syn_flood import SynFloodRule
from .rules.icmp_flood import IcmpFloodRule
from .rules.arp_spoof import ArpSpoofRule
from .rules.brute_force import BruteForceRule
from ..ingestion.pcap_parser import ParsedPacket
from ..ingestion.feature_extractor import FeatureExtractionResult
from ..schemas.alert import SecurityAlert
from ..storage.db import db
from ..config import settings
from ..core.state import global_state
from ..ml import model_manager, aggregate_flows, score_flow, flow_to_security_alert

logger = logging.getLogger("netscope.detection_engine")

class DetectionEngine:
    def __init__(self):
        self.rules = [
            PortScanRule(),
            SynFloodRule(),
            IcmpFloodRule(),
            ArpSpoofRule(),
            BruteForceRule(),
        ]
        self._last_alert_time: dict[tuple[str, str, str], float] = {}
        self._flow_score_cache: dict[tuple, any] = {}

    def analyze(
        self,
        features: FeatureExtractionResult,
        packets: list[ParsedPacket],
        persist_to_db: bool = True,
        apply_cooldown: bool = False,
        capture_id: Optional[str] = None,
        capture_name: Optional[str] = None,
        source_type: str = "PCAP"
    ) -> list[SecurityAlert]:
        all_alerts: list[SecurityAlert] = []
        now = time.time()
        saved_count = 0
        rule_matches_count = 0

        logger.info(
            "[DetectionEngine] Starting analysis: %d packets, %d unique hosts, %d flows (captureId: %s)",
            len(packets), len(features.unique_hosts), len(features.flows), capture_id or "live"
        )

        # Phase 1: Rule-Based Deterministic Detection
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(features, packets)
                logger.info(
                    "[DetectionEngine] Rule evaluated: '%s' (%s) -> %d matches",
                    rule.name, rule.attack_type, len(rule_alerts)
                )
                for alert in rule_alerts:
                    rule_matches_count += 1
                    alert.captureId = capture_id
                    alert.captureName = capture_name
                    alert.sourceType = source_type

                    dedup_key = (alert.attackType, alert.sourceIp, alert.destinationIp)
                    last_time = self._last_alert_time.get(dedup_key, 0.0)
                    
                    if not apply_cooldown or (now - last_time) >= settings.ALERT_COOLDOWN_SEC:
                        self._last_alert_time[dedup_key] = now
                        all_alerts.append(alert)
                        if persist_to_db:
                            db.insert_alert(alert)
                            saved_count += 1
                        logger.info(
                            "   -> Accepted rule alert: %s (%s) %s -> %s (threatScore: %d)",
                            alert.title, alert.attackType, alert.sourceIp, alert.destinationIp, alert.threatScore
                        )
                    else:
                        logger.debug("   -> Suppressed alert due to cooldown: %s", dedup_key)
            except Exception as e:
                logger.error("[DetectionEngine] Error executing rule %s: %s", rule.name, e, exc_info=True)

        # Phase 2: Unsupervised Machine Learning Flow Anomaly Detection
        ml_alerts_count = 0
        if settings.ML_ENABLED and model_manager.is_available() and packets:
            try:
                flows = aggregate_flows(packets)
                logger.info("[DetectionEngine] ML flow aggregation: generated %d flows from %d packets", len(flows), len(packets))
                for flow in flows:
                    # Fingerprint to avoid redundant re-scoring of identical unchanged flows in sliding windows
                    flow_fp = (
                        flow.source_ip, getattr(flow, "destination_ip", ""), getattr(flow, "protocol", "TCP"),
                        getattr(flow, "source_port", 0), getattr(flow, "destination_port", 0),
                        flow.total_fwd_packets, flow.total_bwd_packets,
                        round(flow.flow_duration, 4)
                    )
                    if flow_fp in self._flow_score_cache:
                        inference = self._flow_score_cache[flow_fp]
                    else:
                        inference = score_flow(flow)
                        global_state.ml_inferences_count += 1
                        if inference is not None:
                            self._flow_score_cache[flow_fp] = inference
                            if len(self._flow_score_cache) > 5000:
                                self._flow_score_cache.clear()

                    if inference and inference.is_anomaly:
                        ml_alert = flow_to_security_alert(flow, inference)
                        ml_alerts_count += 1
                        ml_alert.captureId = capture_id
                        ml_alert.captureName = capture_name
                        ml_alert.sourceType = source_type

                        dedup_key = (ml_alert.attackType, ml_alert.sourceIp, ml_alert.destinationIp)
                        last_time = self._last_alert_time.get(dedup_key, 0.0)

                        if not apply_cooldown or (now - last_time) >= settings.ALERT_COOLDOWN_SEC:
                            self._last_alert_time[dedup_key] = now
                            all_alerts.append(ml_alert)
                            if persist_to_db:
                                db.insert_alert(ml_alert)
                                saved_count += 1
                            logger.info(
                                "   -> ML anomaly alert: %s (%s) %s -> %s (anomalyScore: %.3f)",
                                ml_alert.title, ml_alert.attackType, ml_alert.sourceIp, ml_alert.destinationIp, inference.anomaly_score
                            )
                logger.info("[DetectionEngine] ML anomaly evaluation generated %d alerts", ml_alerts_count)
            except Exception as e:
                logger.error("[DetectionEngine] Error executing ML anomaly detection: %s", e, exc_info=True)
        else:
            if not settings.ML_ENABLED:
                logger.info("[DetectionEngine] ML anomaly detection is disabled via settings")
            elif not model_manager.is_available():
                logger.warning("[DetectionEngine] ML anomaly detection skipped: model artifact unavailable")

        logger.info(
            "[DetectionEngine] Analysis complete: %d rule matches, %d ML alerts, %d total alerts returned, %d alerts saved to DB",
            rule_matches_count, ml_alerts_count, len(all_alerts), saved_count
        )
        return all_alerts

detection_engine = DetectionEngine()
