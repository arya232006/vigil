# Vigil — Architecture & Security Methodology (AI + Cybersecurity engine)

## 1. Design principles

1. **Self-hosted AI.** Every model runs on our hardware. No user URL, message or report is sent to a third-party AI
   provider (OpenAI, Anthropic, Google…).
2. **Evidence decides, AI explains.** A deterministic risk engine assigns the risk class from verifiable evidence.
   Models contribute calibrated signals and explanations, and every AI claim is checked against the input.
3. **Passive and safe.** No exploitation, no active scanning, no JavaScript execution, no downloads. Every outbound
   request is SSRF-validated and IP-pinned.
4. **Honest uncertainty.** Five classes including *Inconclusive*. Every report includes confidence (evidence
   coverage), limitations, and which checks could not run. "No threats found" is never reported as "safe".

## 2. Hybrid AI: System-1 / System-2

Inspired by "System One" decision models (typed, calibrated outputs instead of chat), combined with a small
reasoning model for intent and explanation.

| | System-1 (fast, typed) | System-2 (reasoning) |
|---|---|---|
| What | `host-v2`: HistGradientBoosting on 25 engineered host features + char-n-gram logistic regression, isotonic-calibrated · `msg-v1`: word+char TF-IDF logistic regression, isotonic-calibrated | `threatscope-s2`: Qwen3-1.7B (4-bit) + our LoRA adapter, fine-tuned with MLX |
| Output | label + calibrated probability | typed JSON: verdict, scam_type, impersonated_entity, tactics, evidence quotes, requested_action, explanation · grounded explanations of findings citing finding ids |
| Latency | < 5 ms, CPU | ~1–2 s on Apple Silicon |
| Size | ~10 MB | ~1 GB (4-bit) |
| Role | Every request; ML evidence in URL reports; "language similarity" signal for messages | Message intent (e.g. "do **not** share your OTP" vs "share the OTP") and plain-language explanations |

### Training data & distillation
- URL: PhiUSIIL phishing URL dataset (UCI, 235k URLs) + Tranco top 50k benign. **Bias fix:** PhiUSIIL's legitimate
  URLs are all bare `https://www.` homepages, so a full-URL model learns "has path / http = phishing". We train on the
  **hostname only** (www stripped) and handle path/query signals with explainable rules. **Second bias fix (v2):**
  benign examples were all bare registered domains, so v1 flagged 50 % of real legitimate subdomains
  (`login.microsoftonline.com`, `netbanking.hdfcbank.com`…). v2 adds realistic service subdomains of popular
  domains (excluding free-hosting platforms) and drops that to 2.5 % while subdomain-phishing tricks still score ≈1.0.
- Messages: UCI SMS Spam Collection, a phishing email corpus, and 56 hand-written modern scam/hard-negative seeds
  (Indian KYC/UPI/parcel/job/digital-arrest scams, prompt-injection attempts, urgent-but-legitimate alerts), expanded
  to ~450 variants by a local teacher.
- **Distillation:** a local teacher (Qwen3-4B-Instruct via Ollama, structured-output constrained) labels ~3k
  messages. Labels are reconciled with ground truth (teacher/dataset disagreements are dropped), and evidence quotes
  that don't occur verbatim in the message are removed. The 1.7B student is LoRA-fine-tuned on this data plus
  ~300 teacher-written, finding-grounded explanations of real pipeline reports.

### Evaluation (honest splits)
- URL: test split **grouped by registered domain** (no subdomain leakage); out-of-time holdout = **today's live
  OpenPhish feed**; benign holdout = Tranco ranks 200k–210k (never trained on).
- Messages: **whole seed families held out** (none of their variants seen in training) + random SMS/email sample.
- Metrics live at `GET /api/models` and in `backend/app/ml/artifacts/*_metrics.json`.

## 3. Investigation pipeline

```
input ──► type detection ──► URL/domain ─┬─► SSRF-safe fetcher (redirect chain, each hop re-validated)
                                         ├─► domain intel (typosquat+homoglyph, punycode, brand/official-domain,
                                         │                 free hosting, RDAP age, DNS, Tranco popularity)
                                         ├─► threat intel (OpenPhish local feed, optional URLhaus/GSB keys)
                                         ├─► System-1 URL model (calibrated p)
                                         ├─► page/headers (security headers, cookies, EOL software banners, mixed
                                         │                 content, credential forms, cross-domain form posts,
                                         │                 brand-title mismatch, obfuscated JS, client redirects)
                                         └─► TLS (validation, SAN, chain, OCSP→CRL revocation, key/sig strength,
                                                  SCTs + crt.sh CT, legacy TLS, distrusted-CA dataset, weak-key test)
       └──► message ──► IOC extraction (URLs incl. defanged, emails, phones, UPI ids)
                        ├─► rule engine (negation-aware tactic patterns, exact quotes)
                        ├─► System-1 message model
                        ├─► System-2 analysis (grounded evidence only)
                        └─► every extracted link → full URL investigation (linked sub-reports)
──► findings (id, severity, evidence, source, impact, recommendation, limitations)
──► deterministic risk engine (5 classes, score, confidence)
──► System-2 explanation (must cite finding ids; ungrounded points dropped; template fallback)
──► correlation (shared domain / IP / certificate / phone / UPI / impersonated entity / near-duplicate wording)
──► canonical JSON → sha256 report_hash → Web3 registry (hash only, no personal data on-chain)
```

### Risk engine rules (summary)
- **Confirmed malicious:** authoritative threat-intel match (or a message containing such a link).
- **High risk:** a critical finding, ≥2 high findings, high finding + ML p ≥ 0.7, or score ≥ 60. For messages: a
  harmful request (OTP/credentials/payment/fee/remote access/KYC) confirmed by the rule engine **or** by a firm
  System-2 "scam" verdict, combined with manipulation tactics.
- **Suspicious:** one significant indicator, or scam-like language without a harmful request.
- **Low risk:** nothing significant in completed checks. Popular domains (Tranco top 20k, excluding shared hosting)
  dampen the ML contribution. Hygiene issues (missing headers) never make a site "malicious".
- **Inconclusive:** < 50 % of checks completed and no indicators.

## 4. Security & privacy of the platform itself

| Threat | Mitigation |
|---|---|
| SSRF (internal network, cloud metadata `169.254.169.254`) | Resolve → reject any non-global IP (private, loopback, link-local, CGNAT, multicast, reserved, IPv4-mapped IPv6) → **connect to the validated IP** with original Host/SNI (defeats DNS rebinding) · ports 80/443/8080/8443 only · each redirect hop re-validated · OCSP/CRL URLs from certificates get the same guard |
| Malicious content | No JS execution, no downloads, 1.5 MB body cap, 8 s timeout, max 8 redirects |
| Prompt injection | Inputs wrapped as untrusted data; injection phrases detected and flagged as a scam tactic; AI cannot set the risk class; evidence quotes and cited finding ids are verified |
| Privacy | Never asks for passwords/OTPs/keys; only hashes go on-chain; optional external TI APIs are off by default |
| Abuse | 20 analyses/min/IP rate limit |

## 5. Deployment

- **Apple Silicon (demo):** `scripts/serve_s2.sh` (MLX server :8090) + `scripts/run_api.sh` (:8000).
- **Linux/cloud (compact):** `scripts/export_s2.sh` fuses the LoRA adapter (`mlx_lm fuse --dequantize`) and imports
  it into Ollama with int4 quantization as **`threatscope-s2` (1.7 GB, ~176 tokens/s on Apple Silicon)**. Copy or
  push that model to any server running Ollama and point the backend at it:
  `S2_BASE_URL=http://<host>:11434/v1 S2_MODEL=threatscope-s2`, which is the same OpenAI-compatible API. Backend:
  `backend/Dockerfile`.
- Fallback: if the student is unreachable, the backend uses the local teacher via Ollama, then templates. The UI
  never breaks.
