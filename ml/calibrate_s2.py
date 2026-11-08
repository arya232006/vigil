"""Fit System-2 confidence calibration (Platt scaling) and the System-1/System-2 router threshold on the
VALIDATION set, then evaluate both once on the held-out TEST set.

Outputs: backend/app/ml/artifacts/s2_calibration.json (a, b, router_s1_threshold) and adds "calibration" and
"router" sections to s2_metrics.json.
"""
from __future__ import annotations

import json
import math
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app.checks.message import detect_tactics, extract_indicators  # noqa: E402
from app.ml import system1, system2  # noqa: E402
from app.ml.s2_prompt import MSG_SYSTEM  # noqa: E402

ART = ROOT.parent / "backend/app/ml/artifacts"


def logit(p):
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def ece(y, p, bins=10):
    y, p = np.asarray(y, float), np.asarray(p, float)
    idx = np.clip((p * bins).astype(int), 0, bins - 1)
    return float(sum(abs(p[idx == b].mean() - y[idx == b].mean()) * (idx == b).mean() for b in range(bins) if (idx == b).any()))


def signals(text):
    t0 = time.time()
    s2, used, _ = system2.analyze_message(text)
    s2_ms = (time.time() - t0) * 1000
    ind = extract_indicators(text)
    return {"p_raw": (s2 or {}).get("p_unsafe_raw"), "verdict": (s2 or {}).get("verdict"), "s2_ms": s2_ms,
            "s1": system1.msg_score(text).probability, "rules": sorted(detect_tactics(text)),
            "has_ioc": bool(ind.urls or ind.emails or ind.phones or ind.upi_ids)}


def load_val():
    rows = [json.loads(l) for l in (ROOT / "data/s2/valid.jsonl").read_text().splitlines()]
    rows = [r for r in rows if r["messages"][0]["content"] == MSG_SYSTEM]
    return [(re.sub(r"^<message>\n|\n</message>$", "", r["messages"][1]["content"]),
             json.loads(r["messages"][2]["content"])["verdict"] != "legitimate") for r in rows]


def load_test():
    rows = [json.loads(l) for l in (ROOT / "data/s2/test_gt.jsonl").read_text().splitlines()]
    return [(r["text"], r["gt_verdict"] in ("scam", "suspicious", "spam")) for r in rows if r["gt_verdict"]]


def collect(pairs):
    with ThreadPoolExecutor(2) as ex:
        sig = list(ex.map(lambda p: signals(p[0]), pairs))
    return [dict(s, y=int(y)) for s, (_, y) in zip(sig, pairs) if s["p_raw"] is not None]


def skip(s, tau):
    return not s["rules"] and not s["has_ioc"] and s["s1"] < tau


def main():
    val = collect(load_val())
    X = np.array([[logit(s["p_raw"])] for s in val])
    y = np.array([s["y"] for s in val])
    lr = LogisticRegression(C=1.0).fit(X, y)
    a, b = float(lr.coef_[0][0]), float(lr.intercept_[0])

    # Router: largest S1 threshold (capped) that skips no positive validation message.
    pos_skippable = [s["s1"] for s in val if s["y"] and not s["rules"] and not s["has_ioc"]]
    tau = min(0.3, (min(pos_skippable) * 0.5) if pos_skippable else 0.3)
    cal = {"a": round(a, 5), "b": round(b, 5), "router_s1_threshold": round(tau, 4), "fitted_on": "validation",
           "n_validation": len(val)}
    (ART / "s2_calibration.json").write_text(json.dumps(cal, indent=2))

    test = collect(load_test())
    yt = [s["y"] for s in test]
    raw = [s["p_raw"] for s in test]
    calp = [1 / (1 + math.exp(-(a * logit(p) + b))) for p in raw]
    skipped = [s for s in test if skip(s, tau)]
    avg_s2 = sum(s["s2_ms"] for s in test) / len(test)
    result = {
        "calibration": {"method": "Platt scaling on validation", "n_test": len(test),
                        "ece_raw": round(ece(yt, raw), 4), "ece_calibrated": round(ece(yt, calp), 4),
                        "brier_raw": round(float(np.mean((np.array(raw) - yt) ** 2)), 4),
                        "brier_calibrated": round(float(np.mean((np.array(calp) - yt) ** 2)), 4)},
        "router": {"rule": "skip System-2 when no rule tactic, no URL/email/phone/UPI, and System-1 p < threshold",
                   "s1_threshold": round(tau, 4), "test_skip_rate": round(len(skipped) / len(test), 4),
                   "test_positives_skipped": sum(s["y"] for s in skipped),
                   "test_legit_skipped": sum(1 - s["y"] for s in skipped),
                   "avg_system2_ms": int(avg_s2)},
    }
    m = json.loads((ART / "s2_metrics.json").read_text())
    m.update(result)
    (ART / "s2_metrics.json").write_text(json.dumps(m, indent=2))
    print(json.dumps({"fit": cal, **result}, indent=2))


if __name__ == "__main__":
    main()
