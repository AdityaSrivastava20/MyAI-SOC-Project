"""Turns a raw 0-100 risk score into severity / verdict labels.

One place defines the thresholds so the API, dashboard and tests always agree.
"""
from __future__ import annotations

SEVERITY_BANDS = [
    (30, "LOW"),
    (60, "MEDIUM"),
    (85, "HIGH"),
    (100, "CRITICAL"),
]


def clamp_score(score: float) -> int:
    return max(0, min(100, int(round(score))))


def severity_from_score(score: int) -> str:
    for upper, label in SEVERITY_BANDS:
        if score <= upper:
            return label
    return "CRITICAL"


def verdict_from_severity(severity: str) -> str:
    """Three mutually exclusive verdicts, so dashboard counters always add up."""
    if severity == "LOW":
        return "Safe"
    if severity == "MEDIUM":
        return "Suspicious"
    return "Malicious"


def confidence_from_score(score: int) -> float:
    """How far the score is from the 50/50 point, as a percentage (50-100).

    A score of 5 or 95 means the system is very sure about its verdict;
    a score near 50 means it is unsure.
    """
    return round(max(score, 100 - score), 1)
