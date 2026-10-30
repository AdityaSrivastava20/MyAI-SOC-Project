import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai.url_detection.features import normalize_url
from ai.url_detection.predictor import URLPredictor
from backend.database.models import Scan

CACHE_HOURS = float(os.getenv("SCAN_CACHE_HOURS", "24"))


@lru_cache(maxsize=1)
def get_predictor() -> URLPredictor:
    return URLPredictor()


def _iso_utc(value: datetime | None) -> str | None:
    """SQLite returns naive datetimes; they are stored as UTC, so label them as such for the browser."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def scan_to_dict(scan: Scan, cached: bool = False) -> dict:
    return {
        "id": scan.id,
        "url": scan.url,
        "score": scan.score,
        "severity": scan.severity,
        "verdict": scan.verdict,
        "confidence": scan.confidence,
        "source": scan.source,
        "reasons": scan.reasons or [],
        "ml_probability": scan.ml_probability,
        "scan_count": scan.scan_count,
        "first_scanned_at": _iso_utc(scan.first_scanned_at),
        "last_scanned_at": _iso_utc(scan.last_scanned_at),
        "cached": cached,
    }


def scan_url(db: Session, raw_url: str, user_id: int | None = None, org_id: int | None = None) -> dict:
    """Scan a URL. Raises InvalidURLError for bad input.

    Same URL within CACHE_HOURS -> reuse the stored verdict and bump scan_count (no duplicate rows).
    """
    normalized = normalize_url(raw_url)
    now = datetime.now(timezone.utc)
    existing = db.scalar(select(Scan).where(Scan.normalized_url == normalized))

    if existing is not None:
        rescanned = existing.rescanned_at
        if rescanned.tzinfo is None:
            rescanned = rescanned.replace(tzinfo=timezone.utc)
        fresh = now - rescanned < timedelta(hours=CACHE_HOURS)
        existing.scan_count += 1
        existing.last_scanned_at = now
        if not fresh:  # verdict is stale (new model / new blocklist) -> re-evaluate in place
            _apply(existing, get_predictor().predict(normalized))
            existing.rescanned_at = now
        db.commit()
        db.refresh(existing)
        return scan_to_dict(existing, cached=fresh)

    result = get_predictor().predict(normalized)
    scan = Scan(
        url=raw_url.strip(),
        normalized_url=normalized,
        first_scanned_at=now,
        last_scanned_at=now,
        rescanned_at=now,
        user_id=user_id,
        org_id=org_id,
        scan_count=1,
    )
    _apply(scan, result)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan_to_dict(scan)


def _apply(scan: Scan, result: dict) -> None:
    scan.score = result["score"]
    scan.severity = result["severity"]
    scan.verdict = result["verdict"]
    scan.confidence = result["confidence"]
    scan.source = result["source"]
    scan.ml_probability = result["ml_probability"]
    scan.reasons = result["reasons"]


def get_history(db: Session, limit: int = 50, offset: int = 0, verdict: str | None = None) -> dict:
    query = select(Scan)
    count_q = select(func.count()).select_from(Scan)
    if verdict:
        query = query.where(Scan.verdict == verdict)
        count_q = count_q.where(Scan.verdict == verdict)
    rows = db.scalars(query.order_by(Scan.last_scanned_at.desc()).limit(limit).offset(offset)).all()
    return {"total": db.scalar(count_q) or 0, "items": [scan_to_dict(r) for r in rows]}


def get_stats(db: Session) -> dict:
    """All counters come from one grouped query, so categories can never double count."""
    verdicts = {"Safe": 0, "Suspicious": 0, "Malicious": 0}
    for verdict, n in db.execute(select(Scan.verdict, func.count()).group_by(Scan.verdict)):
        verdicts[verdict] = n
    severities = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for severity, n in db.execute(select(Scan.severity, func.count()).group_by(Scan.severity)):
        severities[severity] = n
    total_scans = db.scalar(select(func.coalesce(func.sum(Scan.scan_count), 0))) or 0
    return {
        "total_scans": int(total_scans),
        "unique_urls": sum(verdicts.values()),
        "verdicts": verdicts,
        "severities": severities,
        "mode": get_predictor().mode,
    }
