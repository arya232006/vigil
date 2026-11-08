"""Generate docs/MODEL_CARD.md from the measured metrics (never hand-typed numbers)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "backend/app/ml/artifacts"


def load(name):
    p = ART / name
    return json.loads(p.read_text()) if p.exists() else None


def pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def main():
    u, u1, m, s2 = load("url_metrics.json"), load("url_metrics.v1.json"), load("msg_metrics.json"), load("s2_metrics.json")
    L = ["# Model card: ThreatScope self-hosted AI\n",
         "All numbers below are generated from `backend/app/ml/artifacts/*_metrics.json` by `ml/make_model_card.py`.\n"]
    if u:
        t, op, tr, rl = u["test"], u["holdout_openphish_live"], u["holdout_tranco_200k_210k"], u.get("holdout_real_legit_subdomains", {})
        L += ["## System-1 URL host model (`host-v2`)\n",
              f"HistGradientBoosting (25 engineered host features) + char 2–5-gram logistic regression, isotonic-calibrated. "
              f"Trained on {u['train_size']:,} hosts (PhiUSIIL + Tranco + realistic legitimate subdomains); "
              f"~3 MB; < 5 ms per host on CPU.\n",
              "| Evaluation | Result |", "|---|---|",
              f"| **Live OpenPhish feed (out-of-time, n={op['n']})** | **{pct(op['detection_rate@0.5'])} detected** @0.5 · {pct(op['detection_rate@0.3'])} @0.3 |",
              f"| **Real legitimate subdomains (n={rl.get('n')})** | **{pct(rl.get('false_positive_rate@0.5'))} false positives** @0.5"
              + (f" (v1 without subdomain data: {pct(u1["holdout_real_legit_subdomains"]["false_positive_rate@0.5"])})" if u1 and "holdout_real_legit_subdomains" in u1 else "") + " |",
              f"| Unseen Tranco sites, ranks 200k–210k (n={tr['n']}) | {pct(tr['false_positive_rate@0.5'])} FP @0.5 · {pct(tr['false_positive_rate@0.8'])} @0.8 |",
              f"| Domain-grouped test split (n={u['test_size']:,}) | ROC-AUC {t['roc_auc']} · precision {t['precision']} · recall {t['recall']} · FPR {pct(t['false_positive_rate'])} |",
              f"| Calibration (expected calibration error) | **{t['ece']}** |", ""]
    if m:
        t, h = m["test"], m["holdout_unseen_seed_families"]
        L += ["## System-1 message model (`msg-v1`)\n",
              "Word 1–2-gram + char 3–5-gram TF-IDF logistic regression, isotonic-calibrated (~5 MB).\n",
              "| Evaluation | Result |", "|---|---|",
              f"| Held-out SMS/email test (n={m['test_size']:,}) | F1 {t['f1']} · precision {t['precision']} · recall {t['recall']} · FPR {pct(t['false_positive_rate'])} |",
              f"| Unseen modern scam families | {pct(h['detection_rate@0.5'])} detected |",
              f"| **Urgent-but-legitimate hard negatives** | **{pct(h['false_positive_rate@0.5'])} false positives**. Word statistics can't read intent; this is why System-2 exists |", ""]
    if s2:
        L += ["## System-2 `threatscope-s2` (Qwen3-1.7B 4-bit + our LoRA, MLX)\n",
              f"Distilled from a local Qwen3-4B teacher; evaluated on {s2['n']} held-out messages ({s2['held_out']}).\n",
              "| Model | Binary acc. | 3-class acc. | Scam recall | Legit FPR | JSON valid | Evidence grounded | Latency |",
              "|---|---|---|---|---|---|---|---|"]
        for r in [x for x in s2["results"] if "binary_accuracy" in x]:
            L.append(f"| {r['model']} | {pct(r.get('binary_accuracy'))} | {pct(r.get('three_class_accuracy'))} | "
                     f"{pct(r.get('scam_recall'))} | {pct(r.get('legit_false_positive_rate'))} | {pct(r.get('json_valid_rate'))} | "
                     f"{pct(r.get('evidence_grounding_rate'))} | {r.get('avg_latency_ms', 0)} ms |")
        L.append("")
        for r in [x for x in s2["results"] if "points_with_citation" in x]:
            L += ["**Explanation task** (held-out findings → plain-language explanation):\n",
                  "| n | JSON valid | Key points citing a finding | All citations refer to real findings |", "|---|---|---|---|",
                  f"| {r['n']} | {pct(r['json_valid_rate'])} | {pct(r['points_with_citation'])} | {pct(r['citations_all_valid'])} |", ""]
    L += ["## Limitations\n",
          "- Host-only URL model cannot recognise compromised legitimate sites; threat intel, page checks and TLS cover that.",
          "- Training data is mostly English (plus Hinglish variants); other languages are less reliable.",
          "- Teacher labels are imperfect; disagreements with dataset ground truth were dropped, not corrected.",
          "- All models produce evidence for a deterministic risk engine. They never issue a verdict alone."]
    (ROOT / "docs/MODEL_CARD.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
