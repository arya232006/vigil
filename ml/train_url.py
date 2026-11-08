"""Train the System-1 host classifier (phishing vs legitimate) with honest evaluation.

Data: PhiUSIIL (UCI, label 1=legit/0=phish) + Tranco top 50k (benign).
Held out: today's OpenPhish feed (fresh, out-of-time phishing) and Tranco ranks 200k-210k (unseen benign).
Split by registered domain so subdomains of one site never straddle train/test.
Output: backend/app/ml/artifacts/url_model.joblib + url_metrics.json
"""
from __future__ import annotations

import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, brier_score_loss, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))
from app.ml.host_model import HostModel  # noqa: E402
from app.ml.url_features import HOST_FEATURE_NAMES, _extract, clean_host, host_vector  # noqa: E402

ART = ROOT.parent / "backend" / "app" / "ml" / "artifacts"
ART.mkdir(parents=True, exist_ok=True)
DATA = ROOT / "data"


def reg_domain(h: str) -> str:
    e = _extract(h)
    return e.registered_domain or h


def feats(hosts: list[str]) -> np.ndarray:
    with Pool(8) as p:
        return np.array(p.map(host_vector, hosts, chunksize=2000), dtype=np.float32)


def ece(y, p, bins=10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    return float(sum(abs(p[idx == b].mean() - y[idx == b].mean()) * (idx == b).mean()
                     for b in range(bins) if (idx == b).any()))


def main():
    t0 = time.time()
    df = pd.read_csv(DATA / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    df["host"] = df.URL.map(clean_host)
    df["y"] = 1 - df.label                                      # 1 = phishing
    df = df[df.host.str.len() > 3]

    tr = pd.read_csv(DATA / "tranco" / "top-1m.csv", header=None, names=["rank", "host"])
    tr["host"] = tr.host.map(clean_host)
    benign_train = tr[tr["rank"] <= 50_000][["host"]].assign(y=0)
    # Synthetic-but-realistic legitimate subdomains (service prefixes on popular registered domains). Without these,
    # the model only ever sees bare registered domains as benign and learns "has subdomain = phishing".
    import random as _r
    from app.ml.url_features import FREE_HOSTING, SHORTENERS
    _r.seed(9)
    prefixes = ["mail", "login", "accounts", "account", "secure", "support", "help", "docs", "developer", "api", "app",
                "my", "portal", "web", "m", "shop", "store", "blog", "news", "auth", "sso", "id", "signin", "pay",
                "payments", "billing", "cdn", "static", "careers", "community", "status", "dashboard", "console",
                "cloud", "drive", "online", "netbanking", "retail", "corp", "investor", "en", "in", "us", "uk",
                "mobile", "media", "images", "learn", "student", "admissions", "exam", "results", "services", "eservices"]
    pool = [h for h in tr[tr["rank"] <= 40_000].host if h not in FREE_HOSTING and h not in SHORTENERS]
    synth = {f"{_r.choice(prefixes)}.{d}" for d in _r.sample(pool, 25_000) for _ in range(2)}
    synth |= {f"{_r.choice(prefixes)}.{_r.choice(prefixes)}.{d}" for d in _r.sample(pool, 4_000)}
    benign_train = pd.concat([benign_train, pd.DataFrame({"host": sorted(synth), "y": 0})])
    benign_hold = tr[(tr["rank"] > 200_000) & (tr["rank"] <= 210_000)].host.tolist()

    op = [clean_host(l) for l in (DATA / "openphish" / "feed.txt").read_text().splitlines() if l.strip()]
    op = sorted(set(op))

    data = pd.concat([df[["host", "y"]], benign_train]).drop_duplicates()
    conflict = data.groupby("host").y.nunique()
    data = data[~data.host.isin(conflict[conflict > 1].index)].drop_duplicates("host")
    hold_hosts = set(op) | set(benign_hold) | {"accounts.google.com", "login.microsoftonline.com", "web.whatsapp.com"}
    data = data[~data.host.isin(hold_hosts)].reset_index(drop=True)
    data["group"] = data.host.map(reg_domain)
    print(f"dataset {len(data)} hosts, phishing share {data.y.mean():.3f}", flush=True)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    tr_idx, te_idx = next(gss.split(data, groups=data.group))
    train, test = data.iloc[tr_idx], data.iloc[te_idx]
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=7)
    f_idx, c_idx = next(gss2.split(train, groups=train.group))
    fit, cal = train.iloc[f_idx], train.iloc[c_idx]

    X_fit, X_cal, X_te = feats(fit.host.tolist()), feats(cal.host.tolist()), feats(test.host.tolist())
    print(f"features done {time.time() - t0:.0f}s", flush=True)
    m = HostModel().fit(fit.host.tolist(), X_fit, fit.y.values, cal.host.tolist(), X_cal, cal.y.values)
    print(f"trained {time.time() - t0:.0f}s", flush=True)

    p = m.predict_proba(test.host.tolist(), X_te)
    y = test.y.values
    pred = (p >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(y, pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()

    real_legit_subs = ["accounts.google.com", "login.microsoftonline.com", "mail.yahoo.com", "docs.github.com",
                       "en.wikipedia.org", "netbanking.hdfcbank.com", "retail.onlinesbi.sbi", "api.razorpay.com",
                       "portal.azure.com", "my.zerodha.com", "support.apple.com", "developer.mozilla.org",
                       "web.whatsapp.com", "mail.google.com", "outlook.office.com", "signin.aws.amazon.com",
                       "kite.zerodha.com", "app.slack.com", "music.youtube.com", "secure.chase.com",
                       "online.citi.com", "infinity.icicibank.com", "omni.axisbank.co.in", "student.amity.edu",
                       "results.cbse.nic.in", "eportal.incometax.gov.in", "uidai.gov.in", "services.gst.gov.in",
                       "pay.google.com", "business.facebook.com", "help.instagram.com", "status.cloud.google.com",
                       "learn.microsoft.com", "community.cisco.com", "careers.tcs.com", "my.jio.com",
                       "selfcare.airtel.in", "www.nptel.ac.in", "erp.iitb.ac.in", "moodle.nitk.ac.in"]
    p_rl = m.predict_proba(real_legit_subs, feats(real_legit_subs))
    p_op = m.predict_proba(op, feats(op))
    p_bh = m.predict_proba(benign_hold, feats(benign_hold))
    metrics = {
        "model": "threatscope-host-v2 (HGB + char-ngram LR, isotonic calibrated; + legitimate-subdomain data)",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "train_size": int(len(fit)), "calibration_size": int(len(cal)), "test_size": int(len(test)),
        "test_split": "group split by registered domain (no domain overlap)",
        "test": {"roc_auc": round(float(roc_auc_score(y, p)), 4), "pr_auc": round(float(average_precision_score(y, p)), 4),
                 "precision": round(float(prec), 4), "recall": round(float(rec), 4), "f1": round(float(f1), 4),
                 "false_positive_rate": round(float(fp / (fp + tn)), 4), "brier": round(float(brier_score_loss(y, p)), 4),
                 "ece": round(ece(y, p), 4), "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
        "holdout_openphish_live": {"n": len(op), "detection_rate@0.5": round(float((p_op >= 0.5).mean()), 4),
                                   "detection_rate@0.3": round(float((p_op >= 0.3).mean()), 4)},
        "holdout_tranco_200k_210k": {"n": len(benign_hold), "false_positive_rate@0.5": round(float((p_bh >= 0.5).mean()), 4),
                                     "false_positive_rate@0.8": round(float((p_bh >= 0.8).mean()), 4)},
        "holdout_real_legit_subdomains": {"n": len(real_legit_subs),
                                          "false_positive_rate@0.5": round(float((p_rl >= 0.5).mean()), 4),
                                          "false_positive_rate@0.8": round(float((p_rl >= 0.8).mean()), 4),
                                          "flagged@0.5": [h for h, p in zip(real_legit_subs, p_rl) if p >= 0.5]},
        "feature_names": HOST_FEATURE_NAMES,
    }
    joblib.dump({"model": m, "feature_names": HOST_FEATURE_NAMES, "version": "host-v2"}, ART / "url_model.joblib", compress=3)
    (ART / "url_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: v for k, v in metrics.items() if k != "feature_names"}, indent=2))
    print(f"total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
