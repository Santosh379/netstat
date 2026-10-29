"""
Thread-safe Model Manager for NetScope AI Runtime ML Inference.
Loads model artifact lazily and handles fallback gracefully.
"""

from pathlib import Path
from typing import Optional, Any
import threading
import joblib

from ..config import settings
from .trainer import ModelArtifact

DEFAULT_MODEL_PATH = settings.DATA_DIR / "models" / "isolation_forest_v1.joblib"

class ModelManager:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self._artifact: Optional[ModelArtifact] = None
        self._load_error: Optional[str] = None
        self._load_lock = threading.RLock()
        self._attempted_load: bool = False

    @classmethod
    def get_instance(cls, model_path: Path = DEFAULT_MODEL_PATH) -> "ModelManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(model_path)
            return cls._instance

    def load_model(self, force_reload: bool = False) -> bool:
        """
        Loads the model artifact into memory.
        Returns True if model is loaded and ready, False otherwise.
        """
        with self._load_lock:
            if self._artifact is not None and not force_reload:
                return True

            self._attempted_load = True
            if not self.model_path.exists():
                self._load_error = f"Model artifact not found at {self.model_path}"
                self._artifact = None
                return False

            try:
                artifact = joblib.load(self.model_path)
                if not hasattr(artifact, "model") or not hasattr(artifact, "preprocessor"):
                    raise ValueError("Loaded object is not a valid NetScope ModelArtifact.")

                self._artifact = artifact
                self._load_error = None
                print(f"[ModelManager] Loaded ML model '{artifact.metadata.get('model_name')}' v{artifact.metadata.get('model_version')} successfully.")
                return True
            except Exception as e:
                self._load_error = f"Error loading model artifact: {str(e)}"
                self._artifact = None
                print(f"[ModelManager] {self._load_error}")
                return False

    def is_available(self) -> bool:
        if self._artifact is None and not self._attempted_load:
            self.load_model()
        return self._artifact is not None

    def get_artifact(self) -> Optional[ModelArtifact]:
        if self._artifact is None and not self._attempted_load:
            self.load_model()
        return self._artifact

    def switch_model(self, model_name: str) -> bool:
        """
        Switches between baseline IsolationForest and candidate HistGradientBoosting model.
        """
        with self._load_lock:
            if "hist" in model_name.lower() or "gradient" in model_name.lower():
                target_path = settings.DATA_DIR / "models" / "hist_gradient_boosting_v2.joblib"
            else:
                target_path = settings.DATA_DIR / "models" / "isolation_forest_v1.joblib"

            if not target_path.exists():
                return False

            self.model_path = target_path
            self._artifact = None
            self._attempted_load = False
            return self.load_model(force_reload=True)

    def get_status(self) -> dict[str, Any]:
        """
        Returns model status metadata for system diagnostic endpoints.
        """
        loaded = self.is_available()
        if not loaded:
            return {
                "available": False,
                "model_name": None,
                "model_version": None,
                "error": self._load_error or "Model not loaded",
                "model_path": str(self.model_path),
                "features_count": 0
            }

        meta = self._artifact.metadata if self._artifact else {}
        
        # Load evaluation report json if present
        eval_data = {}
        eval_json_path = self.model_path.with_suffix(".eval.json")
        if eval_json_path.exists():
            try:
                import json
                with open(eval_json_path, "r", encoding="utf-8") as f:
                    eval_data = json.load(f)
            except Exception:
                pass

        return {
            "available": True,
            "model_name": meta.get("model_name", "IsolationForest"),
            "model_version": meta.get("model_version", "1.0.0"),
            "model_type": meta.get("model_type", "Anomaly Detection Model"),
            "schema_version": meta.get("schema_version", "1.0.0"),
            "trained_at": meta.get("trained_at"),
            "training_samples": meta.get("training_samples"),
            "decision_threshold": self._artifact.threshold if self._artifact else 0.50,
            "features_count": len(self._artifact.feature_names) if self._artifact else 0,
            "features": self._artifact.feature_names if self._artifact else [],
            "model_path": str(self.model_path),
            "evaluation": eval_data
        }

model_manager = ModelManager.get_instance()
