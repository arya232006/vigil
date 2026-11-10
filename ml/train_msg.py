"""Train the System-1 message classifier (scam/phish/spam vs legitimate) on ground-truth labels.

Data: UCI SMS Spam Collection, phishing-email dataset, hand-written seeds + teacher variants.
Evaluation: stratified held-out test + a hard-negative set (urgent-but-legitimate seed variants, grouped by seed
so no variant of a test seed is seen in training).
Output: backend/app/ml/artifacts/msg_model.joblib + msg_metrics.json
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
sys.path.insert(0, str(ROOT))
from app.ml.msg_model import MessageModel  # noqa: E402
from seeds import SEEDS  # noqa: E402

ART = ROOT.parent / "backend" / "app" / "ml" / "artifacts"
DATA = ROOT / "data"
random.seed(3)


def load() -> pd.DataFrame:
    rows = []
    sms = [l.split("\t", 1) for l in (DATA / "sms" / "SMSSpamCollection").read_text(encoding="latin-1").splitlines() if "\t" in l]
    rows += [{"text": t, "y": int(g == "spam"), "src": "sms", "group": f"sms{i}"} for i, (g, t) in enumerate(sms)]
    em = pd.read_csv(DATA / "emails" / "Phishing_Email.csv").dropna(subset=["Email Text", "Email Type"])
    em = em[em["Email Text"].str.len().between(30, 6000)]
    rows += [{"text": t, "y": int("Phishing" in ty), "src": "email", "group": f"em{i}"}
             for i, (t, ty) in enumerate(zip(em["Email Text"], em["Email Type"]))]
    import hashlib
    sid = {hashlib.sha1(s[2].encode()).hexdigest()[:16]: i for s, i in zip(SEEDS, range(len(SEEDS)))}
    for i, (v, ty, t) in enumerate(SEEDS):
        rows.append({"text": t, "y": int(v != "legitimate"), "src": f"seed_{v}", "group": f"seed{i}"})
    var_path = DATA / "distill" / "variants.jsonl"
    for l in var_path.read_text().splitlines():
        d = json.loads(l)
        g = sid.get(d["seed_id"], -1)
        rows.append({"text": d["text"], "y": int(d["verdict"] != "legitimate"), "src": f"seed_{d['verdict']}", "group": f"seed{g}"})
    df = pd.DataFrame(rows).drop_duplicates("text").reset_index(drop=True)
    return df


def main():
    t0 = time.time()
    df = load()
    print(df.groupby(["src", "y"]).size(), flush=True)
    # Use EXACTLY the System-2 held-out set (same seed families + same SMS/email messages) so System-1 and
    # System-2 are compared on data neither has seen.
    s2_test = [json.loads(l) for l in (DATA / "s2" / "test_gt.jsonl").read_text().splitlines()]
    s2_texts = {r["text"] for r in s2_test}
    text_group = dict(zip(df.text.str[:1400], df.group))
    hold_groups = {text_group[t] for t in s2_texts if t in text_group and text_group[t].startswith("seed")}
    hold = df[df.group.isin(hold_groups)]
    rest = df[~df.group.isin(hold_groups) & ~df.text.str[:1400].isin(s2_texts)]
    train, test = train_test_split(rest, test_size=0.2, stratify=rest.y, random_state=0)
    fit, cal = train_test_split(train, test_size=0.15, stratify=train.y, random_state=1)

    w = np.where(fit.src.str.startswith("seed").values, 10.0, 1.0)   # modern hand-written families matter more
    m = MessageModel().fit(fit.text.tolist(), fit.y.values, cal.text.tolist(), cal.y.values, sample_weight=w)
    p = m.predict_proba(test.text.tolist())
    y = test.y.values
    pred = (p >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(y, pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()

    ph = m.predict_proba(hold.text.tolist())
    hold_legit = hold[hold.y == 0]
    hold_scam = hold[hold.y == 1]
    metrics = {
        "model": "vigil-msg-v1 (word+char TF-IDF LR, isotonic calibrated)",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_size": int(len(fit)), "test_size": int(len(test)),
        "test": {"roc_auc": round(float(roc_auc_score(y, p)), 4), "pr_auc": round(float(average_precision_score(y, p)), 4),
                 "precision": round(float(prec), 4), "recall": round(float(rec), 4), "f1": round(float(f1), 4),
                 "false_positive_rate": round(float(fp / (fp + tn)), 4), "brier": round(float(brier_score_loss(y, p)), 4),
                 "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
        "holdout_unseen_seed_families": {
            "groups": len(hold_groups),
            "scam_or_suspicious_n": int(len(hold_scam)),
            "detection_rate@0.5": round(float((ph[hold.y.values == 1] >= 0.5).mean()), 4) if len(hold_scam) else None,
            "legit_hard_negative_n": int(len(hold_legit)),
            "false_positive_rate@0.5": round(float((ph[hold.y.values == 0] >= 0.5).mean()), 4) if len(hold_legit) else None,
        },
    }
    joblib.dump({"model": m, "version": "msg-v1"}, ART / "msg_model.joblib", compress=3)
    (ART / "msg_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))
    for t in ["URGENT: Server prod-db-02 is down. On-call engineer please join the incident bridge now.",
              "Your OTP for login is 482913. Do not share this OTP with anyone.",
              "Dear customer your SBI account will be blocked today, update KYC at sbi-kyc.in-verify.co",
              "Congratulations you won Rs 25 lakh in KBC lottery, pay Rs 12500 processing fee"]:
        print(round(float(m.predict_proba([t])[0]), 3), t[:70], m.top_terms(t, 4))
    print(f"total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
