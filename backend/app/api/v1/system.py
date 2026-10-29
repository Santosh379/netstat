import json
from typing import Optional, Dict, Any
from fastapi import APIRouter
from ...schemas.system import SystemStatus, InterfaceInfo, SystemSettings, SystemSettingsUpdate
from ...ingestion.interface_manager import is_admin, is_npcap_available, get_network_interfaces
from ...core.state import global_state
from ...storage.db import db
from ...config import settings
from ...ml import model_manager

router = APIRouter(prefix="/system", tags=["System"])

@router.get("/status", response_model=SystemStatus)
def get_system_status():
    npcap = is_npcap_available()
    admin = is_admin()
    can_live_capture = npcap

    msg = "NetScope AI Engine active"
    if not npcap:
        msg = "Npcap driver not detected on Windows; running in offline PCAP & synthetic demonstration mode."
    else:
        msg = "Npcap packet capture driver active. Real physical network capture is available."

    ml_info = model_manager.get_status()

    return SystemStatus(
        status="ok",
        version="1.0.0",
        backend_available=True,
        capture_mode=global_state.capture_mode,
        live_capture_supported=can_live_capture,
        npcap_available=npcap,
        has_admin_privileges=admin,
        active_interface=global_state.active_interface,
        is_monitoring=global_state.is_monitoring,
        is_synthetic=global_state.is_synthetic,
        message=msg,
        capture_error=global_state.capture_error,
        packets_captured=global_state.packets_captured_count,
        packets_processed=global_state.packets_processed_count,
        flows_count=global_state.total_flows_count,
        ml_inferences_count=global_state.ml_inferences_count,
        elapsed_seconds=global_state.get_elapsed_seconds(),
        ml_enabled=settings.ML_ENABLED,
        ml_model_info=ml_info
    )

@router.get("/interfaces", response_model=list[InterfaceInfo])
def list_interfaces():
    return get_network_interfaces()

@router.get("/ml")
def get_ml_status():
    return {
        "enabled": settings.ML_ENABLED,
        "details": model_manager.get_status()
    }

@router.get("/ml/performance")
def get_ml_performance():
    from ...ml.trainer import compare_candidate_models
    status = model_manager.get_status()
    comparison = compare_candidate_models(settings.DATA_DIR / "datasets" / "cicids2017_sample.csv")
    return {
        "active_model": status,
        "comparison": comparison
    }

@router.post("/ml/switch")
def switch_ml_model(payload: dict):
    model_name = payload.get("model_name", "HistGradientBoosting")
    success = model_manager.switch_model(model_name)
    if not success:
        return {"success": False, "message": f"Failed to switch to model '{model_name}'. Artifact may be missing."}
    return {
        "success": True,
        "message": f"Successfully switched active ML model to {model_name}.",
        "active_model": model_manager.get_status()
    }

_training_state = {
    "is_training": False,
    "last_result": None,
    "error": None
}

def _run_training_job(model_type: str):
    global _training_state
    _training_state["is_training"] = True
    _training_state["error"] = None
    try:
        from ...ml.trainer import train_hist_gradient_boosting, train_isolation_forest
        dataset_path = settings.DATA_DIR / "datasets" / "cicids2017_sample.csv"
        if "hist" in model_type.lower():
            out_path = settings.DATA_DIR / "models" / "hist_gradient_boosting_v2.joblib"
            _, _, eval_res = train_hist_gradient_boosting(dataset_path, out_path)
            model_manager.switch_model("HistGradientBoosting")
        else:
            out_path = settings.DATA_DIR / "models" / "isolation_forest_v1.joblib"
            _, meta = train_isolation_forest(dataset_path, out_path)
            eval_res = meta
            model_manager.switch_model("IsolationForest")

        _training_state["last_result"] = eval_res
    except Exception as e:
        _training_state["error"] = str(e)
    finally:
        _training_state["is_training"] = False

@router.post("/ml/train")
def trigger_training(payload: Optional[dict] = None):
    import threading
    global _training_state
    if _training_state["is_training"]:
        return {"status": "in_progress", "message": "Training job already running in background."}

    model_type = (payload or {}).get("model_type", "HistGradientBoosting")
    t = threading.Thread(target=_run_training_job, args=(model_type,), daemon=True)
    t.start()
    return {
        "status": "started",
        "message": f"Started background training for {model_type}. Progress can be monitored asynchronously."
    }

@router.get("/ml/train/status")
def get_training_status():
    return _training_state

@router.post("/ml/toggle")
def toggle_ml():
    settings.ML_ENABLED = not settings.ML_ENABLED
    db.set_setting("ml_enabled", "true" if settings.ML_ENABLED else "false")
    return {
        "enabled": settings.ML_ENABLED,
        "message": f"Machine learning anomaly detection {'enabled' if settings.ML_ENABLED else 'disabled'}."
    }

@router.get("/settings", response_model=SystemSettings)
def get_settings():
    saved_iface = db.get_setting("interface", global_state.active_interface)
    saved_cap = db.get_setting("packet_capture_enabled", "true") == "true"
    saved_dark = db.get_setting("dark_mode", "true") == "true"
    saved_synth = db.get_setting("synthetic_mode", "true" if global_state.is_synthetic else "false") == "true"
    saved_ml = db.get_setting("ml_enabled", "true" if settings.ML_ENABLED else "false") == "true"
    settings.ML_ENABLED = saved_ml

    return SystemSettings(
        interface=saved_iface,
        packet_capture_enabled=saved_cap,
        dark_mode=saved_dark,
        synthetic_mode=saved_synth,
        ml_enabled=saved_ml
    )

@router.put("/settings", response_model=SystemSettings)
def update_settings(update: SystemSettingsUpdate):
    if update.interface is not None:
        db.set_setting("interface", update.interface)
        global_state.active_interface = update.interface
    if update.packet_capture_enabled is not None:
        db.set_setting("packet_capture_enabled", "true" if update.packet_capture_enabled else "false")
    if update.dark_mode is not None:
        db.set_setting("dark_mode", "true" if update.dark_mode else "false")
    if update.synthetic_mode is not None:
        db.set_setting("synthetic_mode", "true" if update.synthetic_mode else "false")
        global_state.is_synthetic = update.synthetic_mode
    if update.ml_enabled is not None:
        db.set_setting("ml_enabled", "true" if update.ml_enabled else "false")
        settings.ML_ENABLED = update.ml_enabled

    return get_settings()
