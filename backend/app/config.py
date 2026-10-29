import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "NetScope AI Backend"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOAD_DIR: Path = DATA_DIR / "uploads"
    SAMPLES_DIR: Path = BASE_DIR / "samples"
    DB_PATH: Path = DATA_DIR / "netscope.db"
    
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    MAX_PACKETS_TO_PROCESS: int = 100_000
    PACKET_BUFFER_LIMIT: int = 200
    
    # Detection Rule Thresholds
    PORT_SCAN_THRESHOLD: int = 10
    PORT_SCAN_WINDOW_SEC: float = 3.0
    
    SYN_FLOOD_RATE_THRESHOLD: int = 150  # SYN packets/sec
    SYN_FLOOD_ACK_RATIO_MAX: float = 0.08  # ACK to SYN ratio
    
    ICMP_FLOOD_RATE_THRESHOLD: int = 300  # ICMP packets/sec
    ICMP_FLOOD_COUNT_THRESHOLD: int = 20  # Minimum ICMP packets to qualify as flood
    
    BRUTE_FORCE_ATTEMPTS_THRESHOLD: int = 6
    BRUTE_FORCE_WINDOW_SEC: float = 30.0
    
    ALERT_COOLDOWN_SEC: float = 5.0

    # Machine Learning Settings
    ML_ENABLED: bool = True
    ML_DECISION_THRESHOLD: float = 0.50
    MODELS_DIR: Path = DATA_DIR / "models"
    DATASETS_DIR: Path = DATA_DIR / "datasets"
    ML_MODEL_PATH: Path = DATA_DIR / "models" / "isolation_forest_v1.joblib"

    model_config = SettingsConfigDict(env_file=".env", extra="allow")

settings = Settings()

# Ensure directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
settings.DATASETS_DIR.mkdir(parents=True, exist_ok=True)
