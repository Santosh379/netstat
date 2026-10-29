import sys
from pathlib import Path
import uvicorn

backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent

# Ensure both project root and backend package are in pythonpath
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from backend.app.config import settings

if __name__ == "__main__":
    print(f"Starting NetScope AI Backend on http://{settings.HOST}:{settings.PORT} ...")
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=False)
