from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    """One row per unique URL. Repeat scans bump scan_count instead of adding rows."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[str] = mapped_column(String(2048), unique=True)
    score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(10))
    verdict: Mapped[str] = mapped_column(String(12))
    confidence: Mapped[float] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(20))
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    scan_count: Mapped[int] = mapped_column(Integer, default=1)
    first_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rescanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Multi-tenant hooks for the major project (unused in the minor project).
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    org_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_scans_verdict", "verdict"), Index("ix_scans_last", "last_scanned_at"))
