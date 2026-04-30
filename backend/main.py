"""
ANBU Sentinel — FastAPI Application Entry Point
AI-Powered Network Anomaly Detection & Incident Intelligence
"""
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Import routers
from app.api.auth import router as auth_router
from app.api.logs import router as logs_router
from app.api.routes import detections_router, dashboard_router, reports_router
from app.db.database import init_db

# Ensure data directory exists
DATA_DIR = Path(__file__).parent / "app" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    print("🛡️  ANBU Sentinel starting up...")
    print(f"   AWS Region: {os.getenv('AWS_REGION', 'us-east-1')}")
    print(f"   Bedrock Model: {os.getenv('BEDROCK_MODEL_ID', 'claude-3-5-sonnet')}")
    print(f"   Environment: {os.getenv('APP_ENV', 'development')}")
    try:
        await init_db()
        print("   ✅ Database tables ready (Neon PostgreSQL)")
    except Exception as e:
        print(f"   ⚠️  DB init warning: {e}")
    yield
    print("🛡️  ANBU Sentinel shutting down...")


app = FastAPI(
    title="ANBU Sentinel API",
    description="AI-Powered Network Anomaly Detection & Incident Intelligence System",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(detections_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(reports_router, prefix="/api")


# ── Health & Root ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "name": "ANBU Sentinel",
        "version": "2.0.0",
        "status": "operational",
        "uptime_seconds": round(time.time() - START_TIME, 2),
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}
