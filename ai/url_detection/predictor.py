"""Hybrid URL predictor: blocklist -> whitelist -> (ML model + rules).

The returned dict is what the API stores and the dashboard renders:
    score, severity, verdict, confidence, source, reasons[], ml_probability
"""
from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np

from ai.risk_engine.scoring import clamp_score, confidence_from_score, severity_from_score, verdict_from_severity
from threat_intelligence.feeds.feed_manager import ThreatIntel

from .features import (
    FEATURE_NAMES,
    RISKY_TLDS,
    brand_findings,
    extract_features,
    keyword_hits,
    normalize_url,
    parse_url,
)

log = logging.getLogger(__name__)
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "url_model.pkl"

ML_WEIGHT = 0.65
RULE_WEIGHT = 0.35
TRUSTED_MAX_SCORE = 12


def rule_assessment(feats: dict[str, float], parts: dict, url: str) -> tuple[int, list[tuple[int, str]]]:
    """Transparent rule score (0-100) plus a human-readable reason for every point added."""
    pts: list[tuple[int, str]] = []
    brand = brand_findings(parts, url)

    if feats["has_ip_host"]:
        pts.append((30, "Uses a raw IP address instead of a domain name"))
    if feats["has_at"]:
        pts.append((25, "Contains '@' in the address, which can hide the real destination"))
    if brand["typosquat_of"]:
        pts.append((35, f"Domain looks like a misspelling of '{brand['typosquat_of']}' (typosquatting)"))
    elif brand["misused_brand"]:
        pts.append((30, f"Mentions '{brand['misused_brand']}' but the domain is not an official {brand['misused_brand']} domain"))
    if feats["has_punycode"]:
        pts.append((20, "Domain uses punycode (xn--), often used for look-alike characters"))
    if feats["risky_tld"]:
        pts.append((15, f"Uses a high-risk top-level domain (.{parts['suffix'].split('.')[-1]})"))
    if not feats["is_https"]:
        pts.append((10, "Does not use HTTPS"))
    if feats["subdomain_count"] >= 3:
        pts.append((12, f"Unusually deep subdomain chain ({int(feats['subdomain_count'])} levels)"))
    kws = keyword_hits(parts)
    if len(kws) >= 3:
        pts.append((20, "Several credential/phishing keywords in the URL: " + ", ".join(kws[:4])))
    elif len(kws) == 2:
        pts.append((12, "Credential-related keywords in the URL: " + ", ".join(kws)))
    elif len(kws) == 1:
        pts.append((5, f"Contains the keyword '{kws[0]}'"))
    if feats["num_hyphens_host"] >= 2:
        pts.append((10, "Domain name contains several hyphens"))
    if feats["url_length"] > 120:
        pts.append((12, "Very long URL"))
    elif feats["url_length"] > 75:
        pts.append((8, "Long URL"))
    if feats["is_shortener"]:
        pts.append((15, "URL shortener hides the real destination"))
    if feats["port_nonstandard"]:
        pts.append((10, "Uses a non-standard port"))
    if feats["label_entropy"] > 3.3 and feats["longest_label_len"] >= 10 and "-" not in parts["label"]:
        pts.append((12, "Domain name looks randomly generated"))

    return min(100, sum(p for p, _ in pts)), sorted(pts, key=lambda x: -x[0])


class URLPredictor:
    def __init__(self, model_path: Path = MODEL_PATH, threat_intel: ThreatIntel | None = None):
        self.threat_intel = threat_intel or ThreatIntel()
        self.model = None
        self.model_path = Path(model_path)
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
        else:
            log.warning("ML model not found at %s - running in rules-only mode. Run scripts/train_models.py", self.model_path)

    @property
    def mode(self) -> str:
        return "hybrid" if self.model is not None else "rules-only"

    def _ml_probability(self, feats: dict[str, float]) -> float | None:
        if self.model is None:
            return None
        x = np.array([[feats[name] for name in FEATURE_NAMES]])
        return float(self.model.predict_proba(x)[0][1])

    def predict(self, raw_url: str) -> dict:
        url = normalize_url(raw_url)
        parts = parse_url(url)

        # 1. Known-bad: decided by threat intelligence, not by the model.
        hit = self.threat_intel.check_blocklist(url, parts["host"])
        if hit:
            return self._result(url, 100, "blocklist", [f"Listed in threat-intelligence blocklist (source: {hit.source}, category: {hit.category})"], None, confidence=99.0)

        feats = extract_features(url, parts)
        rule_score, rule_reasons = rule_assessment(feats, parts, url)
        ml_prob = self._ml_probability(feats)

        if ml_prob is None:
            blended = float(rule_score)
        else:
            blended = ML_WEIGHT * ml_prob * 100 + RULE_WEIGHT * rule_score

        reasons = [text for _, text in rule_reasons[:5]]
        if ml_prob is not None and ml_prob >= 0.8 and not reasons:
            reasons.append("The ML model found the URL structure very similar to known phishing URLs")
        elif ml_prob is not None and ml_prob >= 0.6:
            reasons.append(f"ML model estimates {ml_prob * 100:.0f}% probability that this URL is malicious")

        # 2. Known-good: trusted domains are capped, never fully ignored.
        if self.threat_intel.is_trusted(parts["registered_domain"]) and not parts["is_ip"] and not feats["has_at"]:
            score = min(clamp_score(blended), TRUSTED_MAX_SCORE)
            return self._result(url, score, "whitelist", ["Domain is on the trusted-domain list"], ml_prob)

        score = clamp_score(blended)
        if not reasons:
            reasons.append("No suspicious indicators found in the URL")
        return self._result(url, score, "ml+rules" if ml_prob is not None else "rules", reasons, ml_prob)

    @staticmethod
    def _result(url: str, score: int, source: str, reasons: list[str], ml_prob: float | None, confidence: float | None = None) -> dict:
        severity = severity_from_score(score)
        return {
            "url": url,
            "score": score,
            "severity": severity,
            "verdict": verdict_from_severity(severity),
            "confidence": confidence if confidence is not None else confidence_from_score(score),
            "source": source,
            "reasons": reasons,
            "ml_probability": None if ml_prob is None else round(ml_prob, 4),
        }
