from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ai.url_detection.features import InvalidURLError
from backend.database.database import get_db
from backend.services import scanner_service

router = APIRouter(prefix="/api/v1", tags=["scanner"])


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, examples=["https://example.com"])


@router.get("/health")
def health():
    return {"status": "ok", "detector_mode": scanner_service.get_predictor().mode}


@router.post("/scan")
def scan(body: ScanRequest, db: Session = Depends(get_db)):
    try:
        return scanner_service.scan_url(db, body.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/history")
def history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verdict: Literal["Safe", "Suspicious", "Malicious"] | None = None,
    db: Session = Depends(get_db),
):
    return scanner_service.get_history(db, limit, offset, verdict)


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    return scanner_service.get_stats(db)
