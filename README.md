# ThreatScope — AI-Powered Web Threat Detection & Digital Trust Intelligence

Paste a suspicious **URL, domain, email or message** and get an evidence-backed risk report that a non-technical
person can understand. Reports can be anchored on-chain (hash only) for tamper-evident threat-intelligence sharing.

**What makes it different: the AI is ours.** Instead of calling a third-party LLM, ThreatScope runs a self-hosted
**System-1 / System-2 hybrid**:
- **System-1**: calibrated classifiers we trained (URL host model, message model), < 5 ms each, ~10 MB.
- **System-2**: `threatscope-s2`, a Qwen3-1.7B we fine-tuned with LoRA on MLX by distilling a local teacher.
  It reads intent ("do **not** share your OTP" vs "share the OTP") and writes explanations that must cite evidence.
- A deterministic **risk engine** decides the verdict from evidence. The AI can't overrule it, and every AI quote
  and citation is verified against the input.

No user data ever leaves our infrastructure for an AI provider.

## Quick start (backend: AI + cybersecurity)

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt mlx-lm   # mlx-lm: Apple Silicon only
scripts/serve_s2.sh          # System-2 model server on :8090 (needs ml/adapters/s2 + ml/models/qwen3-1.7b-4bit)
scripts/run_api.sh           # API on :8000 → open http://localhost:8000/docs
python tests/run_cases.py    # end-to-end test cases → docs/TESTING.md
```

The backend still works without the System-2 server: it falls back to a local Ollama model, then to templates.

## Reproduce the models

```bash
# data (public): PhiUSIIL (UCI), Tranco top-1M, OpenPhish feed, UCI SMS Spam, phishing-email corpus → ml/data/
.venv/bin/python ml/train_url.py          # System-1 URL model  → backend/app/ml/artifacts/url_model.joblib
.venv/bin/python ml/train_msg.py          # System-1 msg model  → msg_model.joblib
.venv/bin/python ml/build_distill.py --emails 600   # local teacher labels (Ollama qwen3:4b-instruct)
.venv/bin/python ml/collect_reports.py && .venv/bin/python ml/build_explain.py
.venv/bin/python ml/build_s2_sets.py && scripts/train_s2.sh   # LoRA fine-tune (MLX)
.venv/bin/python ml/eval_s2.py            # base vs fine-tuned vs teacher vs System-1 → s2_metrics.json
```

## Docs
- [docs/API.md](docs/API.md): API contract for the frontend and Web3 integration (report hash format, verification)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): architecture, analysis pipeline, threat-intel sources, security methodology
- [docs/TESTING.md](docs/TESTING.md): test cases with observed results + model evaluation

## Repository layout
```
backend/app/
  main.py            FastAPI endpoints          pipeline.py   investigation orchestration
  risk.py            deterministic risk engine  store.py      reports, hashing, correlation index
  checks/            fetcher (SSRF-safe) · domain · tls · page/headers · threatintel · message rules
  ml/                System-1 models · System-2 client · prompts · artifacts/ (models + metrics)
ml/                  datasets, teacher, distillation, training & evaluation scripts
scripts/             train_s2.sh · serve_s2.sh · run_api.sh
tests/run_cases.py   end-to-end test suite
```
