# Vigil — AI-Powered Web Threat Detection & Digital Trust Intelligence

Paste a suspicious **URL, domain, email or message** and get an evidence-backed risk report that a non-technical
person can understand. Reports can be anchored on-chain (hash only) for tamper-evident threat-intelligence sharing.

**What makes it different: the AI is ours.** Instead of calling a third-party LLM, Vigil runs a self-hosted
**System-1 / System-2 hybrid**:
- **System-1**: calibrated classifiers we trained (URL host model, message model), < 5 ms each, ~10 MB.
- **System-2**: `threatscope-s2`, a Qwen3-1.7B we fine-tuned with LoRA on MLX by distilling a local teacher.
  It reads intent ("do **not** share your OTP" vs "share the OTP") and writes explanations that must cite evidence.
- A deterministic **risk engine** decides the verdict from evidence. The AI can't overrule it, and every AI quote
  and citation is verified against the input.

No user data ever leaves our infrastructure for an AI provider.

## Quick start

Needs Python 3.13 and Node 24. Run each long-lived command in its own terminal.

```bash
# 1. Install
python3.13 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
(cd contracts && npm install) && (cd frontend && npm install)
cp .env.example .env && cp frontend/.env.example frontend/.env.local

# 2. Local chain: start it, then deploy from a second terminal
(cd contracts && npm run node)
(cd contracts && npm run deploy:local)   # put the printed address in .env and frontend/.env.local

# 3. API on :8000 (docs at http://localhost:8000/docs)
scripts/run_api.sh

# 4. Landing page on http://localhost:3100, the app at /investigate
(cd frontend && npm run build && npm run start -- -p 3100)
```

A Hardhat node keeps its chain in memory: after restarting it, run `deploy:local` again. Reports anchored earlier show
as not anchored and can be registered again.

### Optional: the self-hosted System-2 model

Without it the backend falls back to a local Ollama model, then to templates, and the risk level is unaffected.

```bash
.venv/bin/pip install mlx-lm    # Apple Silicon only
scripts/serve_s2.sh             # serves on :8090; needs ml/models/qwen3-1.7b-4bit (not in the repo)
```

### Deploy to Sepolia

Use a dedicated wallet holding only test ETH. In `.env`, set `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY`, then run
`(cd contracts && npm run deploy:sepolia)`. Point `CHAIN_RPC_URL`, `CHAIN_PRIVATE_KEY`, `CHAIN_CONTRACT_ADDRESS` and
`CHAIN_DEPLOY_BLOCK` at that deployment, set `NEXT_PUBLIC_RPC_URL` (a public RPC, because it ships to the browser) and
`NEXT_PUBLIC_CONTRACT_ADDRESS` in `frontend/.env.local`, and rebuild the frontend.

### Tests

```bash
.venv/bin/pip install pytest && .venv/bin/python -m pytest tests   # backend
(cd contracts && npm test)                                         # contract
.venv/bin/python tests/run_cases.py                                # end-to-end cases → docs/TESTING.md
```

### Tamper demo

Register a report on-chain from its report page, then:

```bash
.venv/bin/python scripts/tamper_report.py <report_id>             # changes the verdict and rewrites the stored hash
.venv/bin/python scripts/tamper_report.py <report_id> --restore   # puts it back
```

Click **Verify against chain** after each step.

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
  chain.py           on-chain anchoring, verification and domain lookup
  ml/                System-1 models · System-2 client · prompts · artifacts/ (models + metrics)
contracts/           ThreatRegistry.sol · Hardhat tests · deploy script
frontend/            Next.js UI: investigate · report · history · dashboard · our AI
ml/                  datasets, teacher, distillation, training & evaluation scripts
scripts/             train_s2.sh · serve_s2.sh · run_api.sh · tamper_report.py
tests/run_cases.py   end-to-end test suite
```
