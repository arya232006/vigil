"""System-1: fast, typed, calibrated classifiers trained in-house (milliseconds, CPU only, ~10 MB total)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import joblib

from ..schemas import ModelScore
from .url_features import clean_host, host_features, host_vector

ART = Path(__file__).resolve().parent / "artifacts"


@lru_cache(maxsize=1)
def _url():
    return joblib.load(ART / "url_model.joblib")


@lru_cache(maxsize=1)
def _msg():
    return joblib.load(ART / "msg_model.joblib")


def metrics() -> dict:
    out = {}
    for name in ("url_metrics.json", "msg_metrics.json", "s2_metrics.json"):
        p = ART / name
        if p.exists():
            out[name.replace("_metrics.json", "")] = json.loads(p.read_text())
    return out


def url_score(host: str) -> ModelScore:
    b = _url()
    h = clean_host(host)
    p = float(b["model"].predict_proba([h], [host_vector(h)])[0])
    f = host_features(h)
    drivers = [k for k in ("brand_distance", "brand_substring", "brand_in_subdomain", "free_hosting", "suspicious_tld",
                           "has_punycode", "n_hyphens", "max_digit_run", "kw_count", "has_ip_host")
               if (k == "brand_distance" and 0 < f[k] <= 2) or (k != "brand_distance" and f[k])]
    return ModelScore(model=f"system1-url/{b['version']}", label="phishing" if p >= 0.5 else "benign",
                      probability=round(p, 4), details={"host": h, "active_signals": drivers})


def msg_score(text: str) -> ModelScore:
    b = _msg()
    m = b["model"]
    p = float(m.predict_proba([text])[0])
    return ModelScore(model=f"system1-msg/{b['version']}", label="scam_like_language" if p >= 0.5 else "normal_language",
                      probability=round(p, 4), details={"top_terms": [t for t, _ in m.top_terms(text, 6)]})
