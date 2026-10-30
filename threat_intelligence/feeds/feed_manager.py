"""Loads the local threat-intel lists used before the ML model runs.

* blocklist.csv  - known-bad hosts/URLs   (indicator,type,source,category)
* whitelist.csv  - trusted registered domains (domain)

Known-bad and known-good are decided by lists, not by the model: a model should
only be asked about URLs nobody has already classified.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "threat_intelligence"
BLOCKLIST_PATH = DATA_DIR / "blocklist.csv"
WHITELIST_PATH = DATA_DIR / "whitelist.csv"


@dataclass(frozen=True)
class BlockHit:
    indicator: str
    source: str
    category: str


class ThreatIntel:
    def __init__(self, blocklist_path: Path = BLOCKLIST_PATH, whitelist_path: Path = WHITELIST_PATH):
        self.blocked_hosts: dict[str, BlockHit] = {}
        self.blocked_urls: dict[str, BlockHit] = {}
        self.trusted_domains: set[str] = set()
        self._load_blocklist(blocklist_path)
        self._load_whitelist(whitelist_path)

    def _load_blocklist(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                indicator = (row.get("indicator") or "").strip().lower()
                if not indicator or indicator.startswith("#"):
                    continue
                hit = BlockHit(indicator, row.get("source", "unknown"), row.get("category", "malicious"))
                if (row.get("type") or "host").strip() == "url":
                    self.blocked_urls[indicator.rstrip("/")] = hit
                else:
                    self.blocked_hosts[indicator] = hit

    def _load_whitelist(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                domain = (row.get("domain") or "").strip().lower()
                if domain and not domain.startswith("#"):
                    self.trusted_domains.add(domain)

    def check_blocklist(self, url: str, host: str) -> BlockHit | None:
        bare = url.split("://", 1)[-1].rstrip("/").lower()
        for blocked, hit in self.blocked_urls.items():
            if bare == blocked.split("://", 1)[-1] or bare.startswith(blocked.split("://", 1)[-1] + "/"):
                return hit
        parts = host.split(".")
        # exact host, or any parent domain of the host (a.b.evil.com matches evil.com)
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.blocked_hosts:
                return self.blocked_hosts[candidate]
        return None

    def is_trusted(self, registered_domain: str) -> bool:
        return registered_domain in self.trusted_domains
