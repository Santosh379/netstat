import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
from .config import settings
from .api.v1.system import router as system_router
from .api.v1.capture import router as capture_router
from .api.v1.pcap import router as pcap_router
from .api.v1.alerts import router as alerts_router
from .api.v1.replay import router as replay_router
from .api.v1.topology import router as topology_router
from .api.v1.analytics import router as analytics_router
from .api.v1.reports import router as reports_router
from .api.v1.notifications import router as notifications_router
from .api.websockets.live import router as ws_router, ws_manager
from .storage.sample_generator import ensure_sample_pcaps
from .ingestion.sniffer import sniffer_manager
from .ingestion.interface_manager import is_npcap_available, get_network_interfaces, get_default_interface_name
from .core.state import global_state

async def periodic_stats_broadcaster():
    """Broadcasts dynamic capture statistics and rate telemetry every second."""
    while True:
        await asyncio.sleep(1.0)
        if ws_manager.active_connections:
            stats = global_state.get_capture_stats()
            await ws_manager.broadcast({
                "type": "stats",
                "data": stats.model_dump()
            })

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    loop = asyncio.get_running_loop()
    ws_manager.set_loop(loop)
    ensure_sample_pcaps()
    
    # Start live capture (defaults to real physical interface if Npcap is installed)
    if is_npcap_available():
        default_iface = get_default_interface_name()
        global_state.active_interface = default_iface
        sniffer_manager.start(interface=default_iface, force_synthetic=False)
    else:
        sniffer_manager.start(interface="Synthetic Mode", force_synthetic=True)
    
    stats_task = asyncio.create_task(periodic_stats_broadcaster())
    yield
    # Shutdown
    stats_task.cancel()
    sniffer_manager.stop()

app = FastAPI(
    title="NetScope AI Backend",
    version=settings.VERSION,
    description="Network Traffic Monitoring & Intrusion Detection System API",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 Routers
api_v1_prefix = settings.API_V1_STR
app.include_router(system_router, prefix=api_v1_prefix)
app.include_router(capture_router, prefix=api_v1_prefix)
app.include_router(pcap_router, prefix=api_v1_prefix)
app.include_router(alerts_router, prefix=api_v1_prefix)
app.include_router(replay_router, prefix=api_v1_prefix)
app.include_router(topology_router, prefix=api_v1_prefix)
app.include_router(analytics_router, prefix=api_v1_prefix)
app.include_router(reports_router, prefix=api_v1_prefix)
app.include_router(notifications_router, prefix=api_v1_prefix)

# Mount WebSocket live feed router
app.include_router(ws_router)

@app.get("/")
def root():
    return {
        "name": "NetScope AI Backend",
        "version": settings.VERSION,
        "status": "online",
        "docs_url": "/docs",
        "api_v1": api_v1_prefix
    }
