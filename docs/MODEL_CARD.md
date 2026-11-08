# Model card: ThreatScope self-hosted AI

All numbers below are generated from `backend/app/ml/artifacts/*_metrics.json` by `ml/make_model_card.py`.

## System-1 URL host model (`host-v2`)

HistGradientBoosting (25 engineered host features) + char 2–5-gram logistic regression, isotonic-calibrated. Trained on 207,145 hosts (PhiUSIIL + Tranco + realistic legitimate subdomains); ~3 MB; < 5 ms per host on CPU.

| Evaluation | Result |
|---|---|
| **Live OpenPhish feed (out-of-time, n=227)** | **86.3% detected** @0.5 · 91.2% @0.3 |
| **Real legitimate subdomains (n=40)** | **2.5% false positives** @0.5 (v1 without subdomain data: 50.0%) |
| Unseen Tranco sites, ranks 200k–210k (n=10000) | 8.7% FP @0.5 · 4.8% @0.8 |
| Domain-grouped test split (n=66,733) | ROC-AUC 0.9278 · precision 0.9364 · recall 0.7239 · FPR 2.2% |
| Calibration (expected calibration error) | **0.008** |

## System-1 message model (`msg-v1`)

Word 1–2-gram + char 3–5-gram TF-IDF logistic regression, isotonic-calibrated (~5 MB).

| Evaluation | Result |
|---|---|
| Held-out SMS/email test (n=4,406) | F1 0.9767 · precision 0.9739 · recall 0.9794 · FPR 1.2% |
| Unseen modern scam families | 90.9% detected |
| **Urgent-but-legitimate hard negatives** | **50.0% false positives**. Word statistics can't read intent; this is why System-2 exists |

## Limitations

- Host-only URL model cannot recognise compromised legitimate sites; threat intel, page checks and TLS cover that.
- Training data is mostly English (plus Hinglish variants); other languages are less reliable.
- Teacher labels are imperfect; disagreements with dataset ground truth were dropped, not corrected.
- All models produce evidence for a deterministic risk engine. They never issue a verdict alone.
