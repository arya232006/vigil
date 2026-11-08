# Model card: Vigil self-hosted AI

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
| Held-out SMS/email test (n=4,378) | F1 0.9734 · precision 0.979 · recall 0.9678 · FPR 1.0% |
| Unseen modern scam families | 80.6% detected |
| **Urgent-but-legitimate hard negatives** | **18.5% false positives**. Word statistics can't read intent; this is why System-2 exists |

## System-2 `threatscope-s2` (Qwen3-1.7B 4-bit + our LoRA, MLX)

Distilled from a local Qwen3-4B teacher; evaluated on 169 held-out messages (whole seed families never seen in training + random SMS/email sample).

| Model | Binary acc. | 3-class acc. | Scam recall | Legit FPR | JSON valid | Evidence grounded | Latency |
|---|---|---|---|---|---|---|---|
| system1-msg (TF-IDF LR) | 87.0% | 74.1% | 80.9% | 8.1% | n/a | n/a | 0 ms |
| qwen3-1.7b base (no fine-tune) | 66.9% | 50.3% | 96.6% | 85.5% | 97.0% | 96.4% | 643 ms |
| threatscope-s2 (qwen3-1.7b + our LoRA) | 92.9% | 82.5% | 93.3% | 9.7% | 100.0% | 98.7% | 631 ms |
| risk engine: rules + System-1 (no System-2) | 62.7% | 53.8% | 49.4% | 1.6% | n/a | n/a | 0 ms |
| risk engine: rules + System-1 + threatscope-s2 (full hybrid) | 93.5% | n/a | 95.5% | 11.3% | n/a | n/a | 0 ms |

**Severity of hybrid decisions:** 1.6% of 62 legitimate messages were rated high-risk or confirmed (remaining false positives are only *suspicious*); 74.6% of 63 scams were escalated to high/confirmed on text alone (others are flagged *suspicious*; links inside messages are investigated separately and can escalate). Before the validation-tuned escalation rule: 34.9% of scams escalated and 0.0% of legitimate messages rated high. The rule was tuned on the validation set only; the test set was checked once afterwards.

Test labels for SMS/email come from the datasets; seed-family labels are hand-written. No teacher row is shown because test labels were reconciled with teacher outputs (that comparison would be circular).

**Calibrated System-2 confidence:** the probability of the verdict token is turned into p(unsafe) and Platt-scaled on the validation set. Test (256 msgs): calibration error 0.0551 → **0.0443**, Brier 0.0561 → 0.0486.

**System-1 → System-2 router:** skip System-2 when no rule tactic, no URL/email/phone/UPI, and System-1 p < threshold (threshold 0.0115, chosen on validation so no validation scam is skipped). Test: **25.8% of messages answered without System-2**; 1 positive skipped (a harmless joke SMS labelled spam in the 2011 dataset), 65 legitimate.

**Explanation task** (held-out findings → plain-language explanation):

| n | JSON valid | Key points citing a finding | All citations refer to real findings |
|---|---|---|---|
| 27 | 96.3% | 100.0% | 100.0% |

## Experiment: round-2 fine-tune (not deployed)

Targeted extra data for measured weak spots (urgent-but-legitimate notices, Hinglish, real bank/OTP alerts), weighted ×2. Judged on an independently written 40-message holdout plus the original test set.

| | Current (deployed) | Round 2 |
|---|---|---|
| Fresh holdout: legit false positives | 20.8% | 4.2% |
| Fresh holdout: scam recall | 93.8% | 93.8% |
| Original test: legit false positives | 9.7% | 0.0% |
| Original test: scam recall | 93.3% | 85.4% |

Not deployed: round 2 over-corrected toward "legitimate" and newly missed real scams the current model catches (prompt-injection KYC/OTP scams, "new number, send money by UPI" family-emergency scams). For a security tool missed scams cost more than mild false alarms. Next step: rebalance the extra data (weight ×1 plus matching hard scams).

## Limitations

- Host-only URL model cannot recognise compromised legitimate sites; threat intel, page checks and TLS cover that.
- Training data is mostly English (plus Hinglish variants); other languages are less reliable. Known error: an urgent Hinglish insurance-renewal reminder was rated high-risk on the test set.
- Teacher labels are imperfect; disagreements with dataset ground truth were dropped, not corrected.
- All models produce evidence for a deterministic risk engine. They never issue a verdict alone.
