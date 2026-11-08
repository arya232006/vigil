"""Evaluate System-2 on held-out data: base model vs fine-tuned student vs teacher vs System-1.

Metrics: verdict accuracy, scam recall, hard-negative false-positive rate, JSON validity, evidence grounding,
latency. Output: backend/app/ml/artifacts/s2_metrics.json
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app.ml.s2_prompt import MSG_SYSTEM, msg_user  # noqa: E402

random.seed(4)
ART = ROOT.parent / "backend" / "app" / "ml" / "artifacts"


def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def parse(raw):
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.S)
    m = re.search(r"\{.*\}", raw, re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None


def positive(v):            # scam/suspicious vs legitimate
    return v in ("scam", "suspicious", "spam")


def score(name, preds, gts, texts, lat):
    n = len(gts)
    valid = [p for p in preds if p and p.get("verdict") in ("scam", "suspicious", "legitimate")]
    correct = sum(1 for p, g in zip(preds, gts) if p and g and positive(p.get("verdict")) == positive(g))
    exact = sum(1 for p, g in zip(preds, gts) if p and g in ("scam", "suspicious", "legitimate") and p.get("verdict") == g)
    exact_n = sum(1 for g in gts if g in ("scam", "suspicious", "legitimate"))
    legit = [(p, g) for p, g in zip(preds, gts) if g == "legitimate"]
    bad = [(p, g) for p, g in zip(preds, gts) if g in ("scam", "spam")]
    quotes = grounded = 0
    for p, t in zip(preds, texts):
        for e in (p or {}).get("evidence", []) or []:
            if isinstance(e, dict) and e.get("quote"):
                quotes += 1
                grounded += norm(e["quote"]) in norm(t)
    return {
        "model": name, "n": n,
        "json_valid_rate": round(len(valid) / n, 3),
        "binary_accuracy": round(correct / n, 3),
        "three_class_accuracy": round(exact / max(exact_n, 1), 3),
        "scam_recall": round(sum(1 for p, _ in bad if p and positive(p.get("verdict"))) / max(len(bad), 1), 3),
        "legit_false_positive_rate": round(sum(1 for p, _ in legit if not p or positive(p.get("verdict"))) / max(len(legit), 1), 3),
        "evidence_grounding_rate": round(grounded / max(quotes, 1), 3),
        "avg_latency_ms": int(sum(lat) / max(len(lat), 1)),
    }


def run_mlx(model_path, adapter, rows, max_tokens=320):
    from mlx_lm import generate, load
    model, tok = load(model_path, adapter_path=adapter)
    preds, lat = [], []
    for r in rows:
        prompt = tok.apply_chat_template([{"role": "system", "content": MSG_SYSTEM},
                                          {"role": "user", "content": msg_user(r["text"])}],
                                         add_generation_prompt=True, tokenize=False, enable_thinking=False)
        t0 = time.time()
        out = generate(model, tok, prompt=prompt, max_tokens=max_tokens, verbose=False)
        lat.append((time.time() - t0) * 1000)
        preds.append(parse(out))
    return preds, lat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-other", type=int, default=70)
    ap.add_argument("--skip-base", action="store_true")
    ap.add_argument("--adapter", default=str(ROOT / "adapters/s2"))
    ap.add_argument("--out", default=str(ART / "s2_metrics.json"))
    ap.add_argument("--skip-explain", action="store_true")
    a = ap.parse_args()
    gt_rows = [json.loads(l) for l in (ROOT / "data/s2/test_gt.jsonl").read_text().splitlines()]
    seeds = [r for r in gt_rows if r["source"] in ("seed", "variant")]
    other = [r for r in gt_rows if r["source"] not in ("seed", "variant") and r["gt_verdict"]]
    rows = seeds + random.sample(other, min(a.n_other, len(other)))
    gts = [r["gt_verdict"] for r in rows]
    texts = [r["text"] for r in rows]
    print(f"eval on {len(rows)} held-out messages ({len(seeds)} from unseen seed families, "
          f"{sum(g == 'legitimate' for g in gts)} legitimate)", flush=True)
    results = []

    import joblib
    s1 = joblib.load(ART / "msg_model.joblib")["model"]
    t0 = time.time()
    p1 = s1.predict_proba(texts)
    lat1 = [(time.time() - t0) * 1000 / len(texts)] * len(texts)
    results.append(score("system1-msg (TF-IDF LR)", [{"verdict": "scam" if p >= 0.5 else "legitimate"} for p in p1],
                         gts, texts, lat1))
    print(results[-1], flush=True)

    teacher_preds = [r["teacher"] for r in rows]
    results.append(score("teacher qwen3-4b (labels, offline)", teacher_preds, gts, texts, [0]))
    print(results[-1], flush=True)

    base = str(ROOT / "models/qwen3-1.7b-4bit")
    if not a.skip_base:
        pb, lb = run_mlx(base, None, rows)
        results.append(score("qwen3-1.7b base (no fine-tune)", pb, gts, texts, lb))
        print(results[-1], flush=True)
    ps, ls = run_mlx(base, a.adapter, rows)
    results.append(score("threatscope-s2 (qwen3-1.7b + our LoRA)", ps, gts, texts, ls))
    print(results[-1], flush=True)

    # Full decision layer: deterministic risk engine over rules + System-1 (+/- System-2)
    from app.checks.message import detect_tactics
    from app.ml.system2 import _consistent
    from app.risk import classify_message
    from app.schemas import ModelScore, RiskLevel

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

    def hybrid(s2preds, name):
        out = []
        for i, t in enumerate(texts):
            lvl, _, _, _ = classify_message(detect_tactics(t), grounded(s2preds[i], t) if s2preds else None,
                                            ModelScore(model="s1", label="", probability=float(p1[i])), [], 1.0)
            out.append({"verdict": "scam" if lvl in (RiskLevel.HIGH, RiskLevel.CONFIRMED) else
                        "suspicious" if lvl == RiskLevel.SUSPICIOUS else "legitimate"})
        r = score(name, out, gts, texts, [0])
        r.pop("evidence_grounding_rate", None)
        r.pop("json_valid_rate", None)
        return r

    results.append(hybrid(None, "risk engine: rules + System-1 (no System-2)"))
    print(results[-1], flush=True)
    results.append(hybrid(ps, "risk engine: rules + System-1 + threatscope-s2 (full hybrid)"))
    print(results[-1], flush=True)

    # Explanation task: held-out (validation) explanation examples
    from mlx_lm import generate, load
    if a.skip_explain:
        ex_rows_skip = True
    else:
        ex_rows_skip = False
    from app.ml.s2_prompt import EXPLAIN_SYSTEM
    ex_rows = [json.loads(l) for l in (ROOT / "data/s2/valid.jsonl").read_text().splitlines()]
    ex_rows = [r for r in ex_rows if r["messages"][0]["content"] == EXPLAIN_SYSTEM] if not ex_rows_skip else []
    model, tok = load(base, adapter_path=a.adapter)
    ok_json = cited = points = valid_cites = 0
    for r in ex_rows:
        user = r["messages"][1]["content"]
        ids = set(re.findall(r'"id": ?"(F\d+)"', user))
        prompt = tok.apply_chat_template([{"role": "system", "content": EXPLAIN_SYSTEM}, {"role": "user", "content": user}],
                                         add_generation_prompt=True, tokenize=False, enable_thinking=False)
        o = parse(generate(model, tok, prompt=prompt, max_tokens=450, verbose=False))
        if o and o.get("summary"):
            ok_json += 1
            for kp in o.get("key_points", []):
                if isinstance(kp, dict):
                    points += 1
                    fids = kp.get("finding_ids", [])
                    cited += bool(fids)
                    valid_cites += bool(fids) and all(f in ids for f in fids)
    results.append({"model": "threatscope-s2 explanation task", "n": len(ex_rows),
                    "json_valid_rate": round(ok_json / max(len(ex_rows), 1), 3),
                    "points_with_citation": round(cited / max(points, 1), 3),
                    "citations_all_valid": round(valid_cites / max(points, 1), 3)})
    print(results[-1], flush=True)

    hn = [i for i, r in enumerate(rows) if r["source"] in ("seed", "variant") and r["gt_verdict"] == "legitimate"]
    out = {"evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "n": len(rows),
           "held_out": "whole seed families never seen in training + random SMS/email sample",
           "hard_negatives_n": len(hn), "results": results}
    out["adapter"] = a.adapter
    Path(a.out).write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
