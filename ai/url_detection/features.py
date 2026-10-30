"""Lexical + domain feature extraction for URL threat detection.

Everything here works offline and on the URL string only, so a result can be
produced *before* the user's browser ever loads the page.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# Offline extractor: uses the bundled public-suffix snapshot, never hits the network.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

MAX_URL_LENGTH = 2048

# brand -> official registered domains
BRAND_DOMAINS: dict[str, set[str]] = {
    "google": {"google.com", "google.co.in", "gstatic.com", "googleapis.com"},
    "youtube": {"youtube.com", "youtu.be"},
    "gmail": {"gmail.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com"},
    "outlook": {"outlook.com", "office.com", "live.com"},
    "office365": {"office365.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "github": {"github.com", "githubusercontent.com"},
    "dropbox": {"dropbox.com"},
    "spotify": {"spotify.com"},
    "adobe": {"adobe.com"},
    "ebay": {"ebay.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "zoom": {"zoom.us"},
    "yahoo": {"yahoo.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
}
BRANDS = sorted(BRAND_DOMAINS)

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "log-in", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "wallet", "billing", "suspend", "unlock",
    "alert", "support", "authenticate", "invoice", "bonus", "claim", "recover",
    "banking", "webscr", "validate",
]

RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "zip",
    "mov", "icu", "buzz", "country", "kim", "loan", "men", "party", "review",
    "support", "rest", "monster", "cyou", "sbs", "cfd",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens_host", "num_digits_host", "digit_ratio_url",
    "num_special_chars", "has_at", "has_ip_host", "is_https",
    "subdomain_count", "risky_tld", "suspicious_kw_count",
    "host_entropy", "label_entropy", "url_entropy", "has_punycode",
    "is_shortener", "path_depth", "port_nonstandard", "brand_misuse",
    "typosquat", "longest_label_len", "max_digit_run",
]


class InvalidURLError(ValueError):
    """Raised when the input cannot be treated as an http(s) URL."""


def normalize_url(raw: str) -> str:
    """Return a clean absolute http(s) URL or raise InvalidURLError."""
    if raw is None:
        raise InvalidURLError("URL is empty")
    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is empty")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is longer than {MAX_URL_LENGTH} characters")
    if re.search(r"[\s\x00-\x1f]", url):
        raise InvalidURLError("URL contains spaces or control characters")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidURLError("Only http and https URLs can be scanned")
    try:
        host = parsed.hostname
        parsed.port  # noqa: B018  (validates the port)
    except ValueError as exc:
        raise InvalidURLError("URL has an invalid host or port") from exc
    if not host or "." not in host and not _is_ip(host):
        raise InvalidURLError("URL has no valid host name")
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        netloc = f"{userinfo}@{hostport.lower()}"
    else:
        netloc = netloc.lower()
    path = parsed.path or "/"
    rebuilt = f"{parsed.scheme.lower()}://{netloc}{path}"
    if parsed.query:
        rebuilt += "?" + parsed.query
    return rebuilt


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # decimal (http://3232235777) or hex (http://0xC0A80001) encoded IPs
    return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-fA-F]{6,8}", host))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def parse_url(url: str) -> dict:
    """Split a normalized URL into the pieces the rest of the system needs."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = _extract(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": parsed.port,
        "subdomain": ext.subdomain,
        "label": ext.domain,
        "suffix": ext.suffix,
        "registered_domain": registered if not _is_ip(host) else host,
        "path": parsed.path,
        "query": parsed.query,
        "is_ip": _is_ip(host),
    }


def brand_findings(parts: dict, url: str) -> dict:
    """Detect brand impersonation: brand names used on domains that don't own them."""
    registered = parts["registered_domain"]
    label = parts["label"]
    host_and_path = (parts["host"] + parts["path"]).lower()
    misused = None
    for brand in BRANDS:
        if brand in host_and_path and registered not in BRAND_DOMAINS[brand]:
            misused = brand
            break

    typo = None
    if label and not parts["is_ip"]:
        candidates = {label, label.replace("-", "")}
        candidates |= {c.translate(LEET) for c in list(candidates)}
        candidates |= {c.translate(LEET_I) for c in list(candidates)}
        for brand in BRANDS:
            if registered in BRAND_DOMAINS[brand]:
                continue
            max_dist = 2 if len(brand) >= 8 else 1
            for cand in candidates:
                if cand != brand and len(cand) >= 4 and levenshtein(cand, brand) <= max_dist:
                    # require same rough length to avoid matching unrelated short words
                    if abs(len(cand) - len(brand)) <= 1:
                        typo = brand
                        break
            if typo:
                break
    return {"misused_brand": misused, "typosquat_of": typo}


def keyword_hits(parts: dict) -> list[str]:
    haystack = (parts["host"] + parts["path"] + ("?" + parts["query"] if parts["query"] else "")).lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in haystack]


def extract_features(url: str, parts: dict | None = None) -> dict[str, float]:
    parts = parts or parse_url(url)
    host = parts["host"]
    labels = host.split(".")
    path, query = parts["path"], parts["query"]
    brand = brand_findings(parts, url)
    digits_in_url = sum(ch.isdigit() for ch in url)
    digit_runs = re.findall(r"\d+", host)
    sub_labels = [s for s in parts["subdomain"].split(".") if s] if parts["subdomain"] else []

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(ch.isdigit() for ch in host),
        "digit_ratio_url": digits_in_url / max(len(url), 1),
        "num_special_chars": sum(url.count(c) for c in "@?&=%#~_"),
        "has_at": int("@" in urlparse(url).netloc),
        "has_ip_host": int(parts["is_ip"]),
        "is_https": int(parts["scheme"] == "https"),
        "subdomain_count": len(sub_labels),
        "risky_tld": int(parts["suffix"].split(".")[-1] in RISKY_TLDS) if parts["suffix"] else 0,
        "suspicious_kw_count": len(keyword_hits(parts)),
        "host_entropy": _entropy(host),
        "label_entropy": _entropy(parts["label"]),
        "url_entropy": _entropy(url),
        "has_punycode": int(any(lbl.startswith("xn--") for lbl in labels)),
        "is_shortener": int(parts["registered_domain"] in SHORTENERS),
        "path_depth": len([p for p in path.split("/") if p]),
        "port_nonstandard": int(parts["port"] not in (None, 80, 443)),
        "brand_misuse": int(brand["misused_brand"] is not None),
        "typosquat": int(brand["typosquat_of"] is not None),
        "longest_label_len": max((len(lbl) for lbl in labels), default=0),
        "max_digit_run": max((len(d) for d in digit_runs), default=0),
    }
    return {name: float(features[name]) for name in FEATURE_NAMES}
