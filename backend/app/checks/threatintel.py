"""Threat intelligence: local feeds first (self-hosted), optional external APIs only if keys are configured.

- OpenPhish community feed (downloaded locally, refreshed every 6h)
- Tranco top sites (popularity context only, never proof of safety)
- Optional: URLhaus API (URLHAUS_AUTH_KEY), Google Safe Browsing v4 (GSB_API_KEY)
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..ml.url_features import FREE_HOSTING, SHORTENERS, _extract
from ..schemas import Finding, Severity

FEEDS = Path(__file__).resolve().parent.parent / "data" / "feeds"
FEEDS.mkdir(parents=True, exist_ok=True)
OPENPHISH = FEEDS / "openphish.txt"
TRANCO = Path(os.getenv("TRANCO_CSV", FEEDS / "tranco_top200k.csv"))
TRANCO_LIMIT = 200_000

_lock = threading.Lock()
_state = {"op_urls": set(), "op_hosts": {}, "op_loaded": 0.0, "tranco": {}}


def _norm_url(u: str) -> str:
    u = u.strip().lower()
    sp = urlsplit(u if "://" in u else "http://" + u)
    host = (sp.hostname or "").removeprefix("www.")
    return f"{host}{sp.path.rstrip('/')}" + (f"?{sp.query}" if sp.query else "")


def refresh_openphish(force: bool = False) -> None:
    if not force and OPENPHISH.exists() and time.time() - OPENPHISH.stat().st_mtime < 6 * 3600:
        return
    try:
        r = httpx.get("https://openphish.com/feed.txt", timeout=20)
        if r.status_code == 200 and len(r.text) > 100:
            OPENPHISH.write_text(r.text)
    except httpx.HTTPError:
        pass


def load() -> None:
    refresh_openphish()
    urls, hosts = set(), {}
    if OPENPHISH.exists():
        for line in OPENPHISH.read_text().splitlines():
            if line.strip():
                n = _norm_url(line)
                urls.add(n)
                hosts.setdefault(n.split("/")[0], line.strip())
    tranco = {}
    if TRANCO.exists():
        with TRANCO.open() as f:
            for i, line in enumerate(f):
                if i >= TRANCO_LIMIT:
                    break
                rank, dom = line.strip().split(",", 1)
                tranco[dom.lower()] = int(rank)
    with _lock:
        _state.update(op_urls=urls, op_hosts=hosts, op_loaded=time.time(), tranco=tranco)


def tranco_rank(registered_domain: str) -> int | None:
    if registered_domain in FREE_HOSTING or registered_domain in SHORTENERS:
        return None                      # shared platforms: popularity says nothing about the user's page
    return _state["tranco"].get(registered_domain)


def feed_status() -> dict:
    return {"openphish_urls": len(_state["op_urls"]), "openphish_loaded": _state["op_loaded"],
            "tranco_domains": len(_state["tranco"]),
            "urlhaus_api": bool(os.getenv("URLHAUS_AUTH_KEY")), "google_safe_browsing": bool(os.getenv("GSB_API_KEY"))}


def lookup(url: str, host: str) -> tuple[list[Finding], list[str]]:
    """Returns (findings, sources_consulted)."""
    findings: list[Finding] = []
    sources = ["OpenPhish feed (local copy)"]
    n = _norm_url(url)
    h = host.lower().removeprefix("www.")
    reg = _extract(h).top_domain_under_public_suffix or h

    def hit(src, matched, kind):
        findings.append(Finding(
            id="", module="threat_intel", title=f"Listed in {src}", severity=Severity.CRITICAL,
            description=f"This {kind} appears in {src} as a known phishing/malicious destination.",
            evidence={"matched": matched, "match_type": kind}, source=src,
            impact="Previously reported and verified as malicious by an external intelligence source.",
            recommendation="Do not open this link or enter any information."))

    if n in _state["op_urls"]:
        hit("OpenPhish phishing feed", n, "exact URL")
    elif h in _state["op_hosts"] and reg not in FREE_HOSTING and h not in FREE_HOSTING:
        hit("OpenPhish phishing feed", _state["op_hosts"][h], "hostname")
    elif h in _state["op_hosts"]:
        findings.append(Finding(
            id="", module="threat_intel", title="Same hosting subdomain reported for phishing", severity=Severity.HIGH,
            description=f"A different URL on {h} is in the OpenPhish feed.",
            evidence={"reported_url": _state["op_hosts"][h]}, source="OpenPhish phishing feed"))

    key = os.getenv("URLHAUS_AUTH_KEY")
    if key:
        sources.append("URLhaus API")
        try:
            r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key}, timeout=6)
            j = r.json()
            if j.get("query_status") == "ok" and j.get("url_status") in ("online", "offline"):
                hit("URLhaus malware URL database", url, f"exact URL ({j.get('threat', 'malware')})")
        except (httpx.HTTPError, ValueError):
            pass
    gsb = os.getenv("GSB_API_KEY")
    if gsb:
        sources.append("Google Safe Browsing")
        try:
            r = httpx.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb}", timeout=6, json={
                "client": {"clientId": "threatscope", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}})
            if r.json().get("matches"):
                hit("Google Safe Browsing", url, "exact URL")
        except (httpx.HTTPError, ValueError):
            pass
    return findings, sources
