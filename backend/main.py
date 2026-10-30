import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.api import scanners
from backend.database.database import init_db

ROOT = Path(__file__).resolve().parents[1]


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    scanners.scanner_service.get_predictor()  # load model once at startup
    yield


app = FastAPI(title="AI-SOC", description="AI-powered URL threat detection", version="0.1.0", lifespan=lifespan)

origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

app.include_router(scanners.router)
app.mount("/", StaticFiles(directory=ROOT / "frontend", html=True), name="frontend")
