import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from fastapi import APIRouter, UploadFile, File, HTTPException
from ...schemas.pcap import PcapAnalysisResult, DetectedSignature, CaptureSession
from ...core.security import validate_and_save_pcap, safe_remove_file
from ...ingestion.pcap_parser import parse_pcap_file
from ...ingestion.feature_extractor import extract_features
from ...detection.engine import detection_engine
from ...storage.sample_generator import ensure_sample_pcaps
from ...storage.db import db
from ...config import settings
from ...core.state import global_state

logger = logging.getLogger("netscope.api.pcap")

router = APIRouter(prefix="/pcap", tags=["PCAP Analyzer"])

def _analyze_file_path(file_path: Path, display_name: str, file_size_bytes: int) -> PcapAnalysisResult:
    logger.info("[PCAP] Ingesting file '%s' (%d bytes)", display_name, file_size_bytes)
    # 1. Parse packets
    raw_packets = list(parse_pcap_file(file_path, max_packets=settings.MAX_PACKETS_TO_PROCESS))
    if not raw_packets:
        logger.warning("[PCAP] File '%s' contains no valid frames", display_name)
        raise HTTPException(status_code=400, detail="The PCAP file does not contain any valid IP/Ethernet frames.")

    capture_id = f"CAP-{uuid.uuid4().hex[:8].upper()}"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    logger.info("[PCAP] Successfully parsed %d packets from '%s' (Assigned ID: %s)", len(raw_packets), display_name, capture_id)

    # 2. Extract features
    features, packet_list = extract_features(raw_packets)
    unique_hosts_list = sorted(list(features.unique_hosts))
    logger.info("[PCAP] Extracted features: %d unique hosts, %d active flows", len(unique_hosts_list), len(features.flows))

    # 3. Evaluate detection rules with capture session isolation
    alerts = detection_engine.analyze(
        features,
        packet_list,
        persist_to_db=True,
        capture_id=capture_id,
        capture_name=display_name,
        source_type="PCAP"
    )
    logger.info("[PCAP] Detection completed for '%s': %d threats identified", display_name, len(alerts))

    # 4. Signature & Threat breakdown
    sig_counter = Counter(a.title for a in alerts)
    detected_sigs = []
    for a in alerts:
        if any(s.signature == a.title for s in detected_sigs):
            continue
        detected_sigs.append(DetectedSignature(
            signature=a.title,
            severity=a.severity,
            count=sig_counter[a.title]
        ))

    rule_threats = sum(1 for a in alerts if a.detectionSource == "RULE_ENGINE")
    ml_threats = sum(1 for a in alerts if a.detectionSource == "ML_ANOMALY")
    size_mb = f"{file_size_bytes / (1024 * 1024):.2f} MB" if file_size_bytes >= 1024 * 1024 else f"{file_size_bytes / 1024:.1f} KB"

    # 5. Persist capture session metadata to database & memory cache
    cap_session = CaptureSession(
        id=capture_id,
        filename=display_name,
        filesize=size_mb,
        packetsAnalyzed=features.total_packets,
        uniqueHosts=len(unique_hosts_list),
        tcpConnections=len(features.flows),
        potentialThreats=len(alerts),
        ruleThreats=rule_threats,
        mlThreats=ml_threats,
        durationSeconds=features.duration_seconds,
        status="COMPLETED",
        analyzedAt=now_utc,
        observedHosts=unique_hosts_list,
        topProtocols=features.get_top_protocols(),
        detectedSignatures=detected_sigs
    )
    db.insert_capture(cap_session)

    # Cache packets & session in global state for topology and attack replay
    global_state.set_capture(
        capture_id=capture_id,
        name=display_name,
        packets=raw_packets,
        alerts=alerts,
        features=features,
        hosts=unique_hosts_list
    )

    return PcapAnalysisResult(
        captureId=capture_id,
        filename=display_name,
        filesize=size_mb,
        packetsAnalyzed=features.total_packets,
        uniqueHosts=len(unique_hosts_list),
        tcpConnections=len(features.flows),
        potentialThreats=len(alerts),
        ruleThreats=rule_threats,
        mlThreats=ml_threats,
        durationSeconds=features.duration_seconds,
        analyzedAt=now_utc,
        observedHosts=unique_hosts_list,
        topProtocols=features.get_top_protocols(),
        detectedSignatures=detected_sigs,
        alerts=alerts
    )

@router.post("/upload", response_model=PcapAnalysisResult)
async def upload_pcap(file: UploadFile = File(...)):
    saved_path, original_name, total_bytes = await validate_and_save_pcap(file)
    try:
        result = _analyze_file_path(saved_path, original_name, total_bytes)
        return result
    finally:
        safe_remove_file(saved_path)

@router.get("/samples")
def list_sample_pcaps():
    ensure_sample_pcaps()
    samples = []
    for p in settings.SAMPLES_DIR.glob("*.pcap"):
        samples.append({
            "name": p.name,
            "size": p.stat().st_size
        })
    return samples

@router.post("/analyze-sample/{name}", response_model=PcapAnalysisResult)
def analyze_sample(name: str):
    ensure_sample_pcaps()
    clean_name = Path(name).name
    sample_path = settings.SAMPLES_DIR / clean_name
    
    if not sample_path.exists():
        # Match without .pcap extension if omitted
        sample_path = settings.SAMPLES_DIR / f"{clean_name}.pcap"
        if not sample_path.exists():
            raise HTTPException(status_code=404, detail=f"Sample PCAP '{name}' not found")

    return _analyze_file_path(sample_path, sample_path.name, sample_path.stat().st_size)

@router.get("/captures", response_model=list[CaptureSession])
def list_captures():
    """Returns historical analyzed capture sessions with individual IDs and metrics."""
    return db.get_captures(limit=50)

@router.get("/captures/{capture_id}", response_model=CaptureSession)
def get_capture(capture_id: str):
    cap = db.get_capture_by_id(capture_id)
    if not cap:
        raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found.")
    return cap
