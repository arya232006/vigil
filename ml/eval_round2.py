"""Compare the current System-2 adapter with the round-2 adapter on (a) FRESH_HOLDOUT (independent, never trained
on) and (b) the original held-out test set (same 169 rows as eval_s2). Writes artifacts/s2_round2_comparison.json."""
from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
sys.path.insert(0, str(ROOT))
import joblib  # noqa: E402
import eval_s2  # noqa: E402
from app.checks.message import detect_tactics  # noqa: E402
from app.ml.system2 import _consistent  # noqa: E402
from app.risk import classify_message  # noqa: E402
from app.schemas import ModelScore, RiskLevel as R  # noqa: E402
from round2_seeds import FRESH_HOLDOUT  # noqa: E402

ART = ROOT.parent / "backend/app/ml/artifacts"
BASE = str(ROOT / "models/qwen3-1.7b-4bit")


def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def grounded(p, t):
    if not p:
        return None
    nt = norm(t)
    p = dict(p)
    p["evidence"] = [e for e in p.get("evidence", []) or [] if isinstance(e, dict) and e.get("quote")
                     and norm(e["quote"]) in nt and len(e["quote"]) <= 200
                     and not (len(nt) > 80 and len(norm(e["quote"])) > 0.7 * len(nt))
                     and _consistent(e.get("tactic", ""), e["quote"])]
    return p


def hybrid(texts, gts, preds, s1p):
    lv = [classify_message(detect_tactics(t), grounded(p, t), ModelScore(model="s1", label="", probability=float(q)), [], 1.0)[0]
          for t, p, q in zip(texts, preds, s1p)]
    legit = [l for l, g in zip(lv, gts) if g == "legitimate"]
    scam = [l for l, g in zip(lv, gts) if g == "scam"]
    pos = [l for l, g in zip(lv, gts) if g in ("scam", "spam", "suspicious")]
    return {"legit_flagged": round(sum(l != R.LOW for l in legit) / max(len(legit), 1), 3),
            "legit_high": round(sum(l in (R.HIGH, R.CONFIRMED) for l in legit) / max(len(legit), 1), 3),
            "positives_flagged": round(sum(l != R.LOW for l in pos) / max(len(pos), 1), 3),
            "scams_high": round(sum(l in (R.HIGH, R.CONFIRMED) for l in scam) / max(len(scam), 1), 3)}


def main():
    gt_rows = [json.loads(l) for l in (ROOT / "data/s2/test_gt.jsonl").read_text().splitlines()]
    seeds = [r for r in gt_rows if r["source"] in ("seed", "variant")]
    other = [r for r in gt_rows if r["source"] not in ("seed", "variant") and r["gt_verdict"]]
    random.seed(4)
    test = seeds + random.sample(other, min(70, len(other)))
    sets = {"fresh_holdout": ([t for _, t in FRESH_HOLDOUT], [v for v, _ in FRESH_HOLDOUT]),
            "original_test": ([r["text"] for r in test], [r["gt_verdict"] for r in test])}
    s1 = joblib.load(ART / "msg_model.joblib")["model"]
    out = {}
    for name, adapter in (("current", ROOT / "adapters/final"), ("round2", ROOT / "adapters/s2r2")):
        out[name] = {}
        for set_name, (texts, gts) in sets.items():
            preds, lat = eval_s2.run_mlx(BASE, str(adapter), [{"text": t} for t in texts])
            r = eval_s2.score(name, preds, gts, texts, lat)
            r["hybrid"] = hybrid(texts, gts, preds, s1.predict_proba(texts))
            out[name][set_name] = r
            print(name, set_name, json.dumps(r), flush=True)
    (ART / "s2_round2_comparison.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
