import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.main import app
from app.storage.sample_generator import ensure_sample_pcaps

@pytest.fixture(scope="session", autouse=True)
def setup_samples():
    ensure_sample_pcaps()

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
