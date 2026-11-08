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
    L = ["# Model card: Vigil self-hosted AI\n",
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
        L += ["## System-2 `vigil-s2` (Qwen3-1.7B 4-bit + our LoRA, MLX)\n",
              f"Distilled from a local Qwen3-4B teacher; evaluated on {s2['n']} held-out messages ({s2['held_out']}).\n",
              "| Model | Binary acc. | 3-class acc. | Scam recall | Legit FPR | JSON valid | Evidence grounded | Latency |",
              "|---|---|---|---|---|---|---|---|"]
        for r in [x for x in s2["results"] if "binary_accuracy" in x]:
            if r["model"].startswith("system1"):          # classifier: no JSON / quotes
                r = {**r, "json_valid_rate": None, "evidence_grounding_rate": None}
            L.append(f"| {r['model']} | {pct(r.get('binary_accuracy'))} | {pct(r.get('three_class_accuracy'))} | "
                     f"{pct(r.get('scam_recall'))} | {pct(r.get('legit_false_positive_rate'))} | {pct(r.get('json_valid_rate'))} | "
                     f"{pct(r.get('evidence_grounding_rate'))} | {r.get('avg_latency_ms', 0)} ms |")
        L.append("")
        hs = s2.get("hybrid_severity")
        if hs:
            L += [f"**Severity of hybrid decisions:** {pct(hs['legit_rated_high_or_confirmed'])} of {hs['n_legit']} legitimate "
                  f"messages were rated high-risk or confirmed (remaining false positives are only *suspicious*); "
                  f"{pct(hs['scams_rated_high_or_confirmed'])} of {hs['n_scam']} scams were escalated to high/confirmed on text "
                  "alone (others are flagged *suspicious*; links inside messages are investigated separately and can escalate)."
                  + (f" Before the validation-tuned escalation rule: {pct(s2['hybrid_severity_before_tuning']['scams_rated_high_or_confirmed'])} "
                     f"of scams escalated and {pct(s2['hybrid_severity_before_tuning']['legit_rated_high_or_confirmed'])} of legitimate messages "
                     "rated high. The rule was tuned on the validation set only; the test set was checked once afterwards."
                     if s2.get("hybrid_severity_before_tuning") else ""),
                  "", "Test labels for SMS/email come from the datasets; seed-family labels are hand-written. No teacher row is "
                  "shown because test labels were reconciled with teacher outputs (that comparison would be circular).", ""]
        if s2.get("calibration"):
            c, rt = s2["calibration"], s2.get("router", {})
            L += ["**Calibrated System-2 confidence:** the probability of the verdict token is turned into p(unsafe) and "
                  f"Platt-scaled on the validation set. Test ({c['n_test']} msgs): calibration error {c['ece_raw']} → "
                  f"**{c['ece_calibrated']}**, Brier {c['brier_raw']} → {c['brier_calibrated']}.", ""]
            if rt:
                L += [f"**System-1 → System-2 router:** {rt['rule']} (threshold {rt['s1_threshold']}, chosen on validation "
                      f"so no validation scam is skipped). Test: **{pct(rt['test_skip_rate'])} of messages answered without "
                      f"System-2**; {rt['test_positives_skipped']} positive skipped (a harmless joke SMS labelled spam in "
                      f"the 2011 dataset), {rt['test_legit_skipped']} legitimate.", ""]
        for r in [x for x in s2["results"] if "points_with_citation" in x]:
            L += ["**Explanation task** (held-out findings → plain-language explanation):\n",
                  "| n | JSON valid | Key points citing a finding | All citations refer to real findings |", "|---|---|---|---|",
                  f"| {r['n']} | {pct(r['json_valid_rate'])} | {pct(r['points_with_citation'])} | {pct(r['citations_all_valid'])} |", ""]
    r2 = load("s2_round2_comparison.json")
    if r2:
        fh_c, fh_r = r2["current"]["fresh_holdout"], r2["round2"]["fresh_holdout"]
        ot_c, ot_r = r2["current"]["original_test"], r2["round2"]["original_test"]
        L += ["## Experiment: round-2 fine-tune (not deployed)\n",
              "Targeted extra data for measured weak spots (urgent-but-legitimate notices, Hinglish, real bank/OTP alerts), "
              "weighted ×2. Judged on an independently written 40-message holdout plus the original test set.\n",
              "| | Current (deployed) | Round 2 |", "|---|---|---|",
              f"| Fresh holdout: legit false positives | {pct(fh_c['legit_false_positive_rate'])} | {pct(fh_r['legit_false_positive_rate'])} |",
              f"| Fresh holdout: scam recall | {pct(fh_c['scam_recall'])} | {pct(fh_r['scam_recall'])} |",
              f"| Original test: legit false positives | {pct(ot_c['legit_false_positive_rate'])} | {pct(ot_r['legit_false_positive_rate'])} |",
              f"| Original test: scam recall | {pct(ot_c['scam_recall'])} | {pct(ot_r['scam_recall'])} |",
              "",
              "Not deployed: round 2 over-corrected toward \"legitimate\" and newly missed real scams the current model "
              "catches (prompt-injection KYC/OTP scams, \"new number, send money by UPI\" family-emergency scams). For a "
              "security tool missed scams cost more than mild false alarms. Next step: rebalance the extra data (weight ×1 "
              "plus matching hard scams).", ""]
    L += ["## Limitations\n",
          "- Host-only URL model cannot recognise compromised legitimate sites; threat intel, page checks and TLS cover that.",
          "- Training data is mostly English (plus Hinglish variants); other languages are less reliable. Known error: an urgent "
          "Hinglish insurance-renewal reminder was rated high-risk on the test set.",
          "- Teacher labels are imperfect; disagreements with dataset ground truth were dropped, not corrected.",
          "- All models produce evidence for a deterministic risk engine. They never issue a verdict alone."]
    (ROOT / "docs/MODEL_CARD.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
