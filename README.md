<div align="center">

<img src="docs/assets/readme/banner.png" alt="Vigil: Every Verdict Comes With Evidence" width="100%">

<br>

**AI-powered web threat detection and digital trust intelligence.**<br>
Paste a suspicious link, domain, email or message. Get an evidence-backed risk report anyone can read.

<br>

![Python](https://img.shields.io/badge/Python-3.13-f386a1?style=flat-square&labelColor=1e1e1e)
![Node](https://img.shields.io/badge/Node-24-f386a1?style=flat-square&labelColor=1e1e1e)
![Next.js](https://img.shields.io/badge/Next.js-16-f386a1?style=flat-square&labelColor=1e1e1e)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-f386a1?style=flat-square&labelColor=1e1e1e)
![MLX](https://img.shields.io/badge/MLX-LoRA_fine--tune-f386a1?style=flat-square&labelColor=1e1e1e)
[![Sepolia](https://img.shields.io/badge/Sepolia-ThreatRegistry-f386a1?style=flat-square&labelColor=1e1e1e)](https://sepolia.etherscan.io/address/0x012175dc68cb5480e37419a2ec9e04ee5Eef216F)
[![End-to-end cases](https://img.shields.io/badge/end--to--end_cases-14%2F14_passing-44c086?style=flat-square&labelColor=1e1e1e)](docs/TESTING.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-f386a1?style=flat-square&labelColor=1e1e1e)](LICENSE)

**[How it works](#how-it-works)** ·
**[What it checks](#what-it-checks)** ·
**[Screens](#screens)** ·
**[Our AI](#our-ai)** ·
**[Limits](#known-limits)** ·
**[Quick start](#quick-start)** ·
**[Deploy](#deploying)** ·
**[Docs](#docs)** ·
**[References](#references)** ·
**[License](#license)**

</div>

<br>

`vg.overview`

## Why Vigil

Ask a language model whether a message is a scam and you get an opinion. Its answer can shift with the wording, the
message itself can talk it out of that answer, and it cannot show you what it actually checked.

Vigil separates the jobs:

| | |
|---|---|
| **Checks decide** | Passive checks collect evidence, and a deterministic rule engine turns it into a risk level. Model output counts only as evidence, so the AI cannot overrule the engine. |
| **AI explains** | `vigil-s2`, our self-hosted model, turns findings into plain language. Every quote and citation it produces is verified against the input. |
| **Limits are listed** | Checks that could not run appear on the report. When the evidence runs out, the verdict is *Inconclusive*, not a confident guess. |
| **Reports are tamper-evident** | A report's SHA-256 hash can be anchored on-chain. Only the hash goes on-chain, never the content. |

No user data ever leaves our infrastructure for an AI provider. Inspection is passive: no exploitation, no active
scanning, no JavaScript execution and no downloads.

<br>

`vg.pipeline`

## How it works

<img src="docs/assets/readme/pipeline.png" alt="Input flows through URL and message evidence checks into findings, then a deterministic risk engine that sets one of five classes, then a System-2 explanation and an on-chain hash." width="100%">

The risk engine assigns one of five classes:

| Class | When |
|---|---|
| ![Confirmed malicious](https://img.shields.io/badge/Confirmed_malicious-7f1416?style=flat-square) | An authoritative threat-intel match, or a message containing such a link |
| ![High risk](https://img.shields.io/badge/High_risk-c0272d?style=flat-square) | A critical finding, two or more high findings, a high finding with model probability ≥ 0.7, or score ≥ 60. For messages: a confirmed harmful request combined with manipulation tactics |
| ![Suspicious](https://img.shields.io/badge/Suspicious-a85a06?style=flat-square) | One significant indicator, or scam-like language without a harmful request |
| ![Low risk](https://img.shields.io/badge/Low_risk-1a7a42?style=flat-square) | Nothing significant in the completed checks |
| ![Inconclusive](https://img.shields.io/badge/Inconclusive-5a6069?style=flat-square) | Fewer than half the checks completed and no indicators |

The full pipeline, rules and platform threat model are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

<br>

`vg.checks`

## What it checks

| Input | Evidence collected |
|---|---|
| **Links and domains** | Redirect chain, typosquats and homoglyphs, punycode, brand look-alikes, domain age, DNS, embedded redirect parameters, OpenPhish feed, optional URLhaus and Google Safe Browsing |
| **Certificates** | Validation, hostname match, chain, OCSP and CRL revocation, Certificate Transparency, legacy TLS, distrusted CAs, weak-key test |
| **Web pages** | Credential forms, cross-domain form posts, brand and title mismatch, obfuscated scripts, exposed files, security headers, cookies |
| **Messages** | OTP, payment and KYC requests, urgency, impersonation, remote-access lures, prompt injection, plus links, phone numbers and UPI IDs. Each link gets its own investigation |
| **Email (`.eml`)** | SPF, DKIM and DMARC with alignment, sender identity, deceptive links, risky attachments, the Received chain, sender-domain DNS |
| **QR codes** | Decoded in the browser, so the image is never uploaded, then investigated like any other input |

Reports that share a domain, IP, certificate, phone number, UPI ID or near-duplicate wording are linked, which exposes
campaigns.

**The platform protects itself too.** The fetcher rejects private and cloud-metadata addresses, pins each connection to
the validated IP, and re-checks every redirect. It never runs page JavaScript or downloads files. Details are in the
[threat model](docs/ARCHITECTURE.md#4-security--privacy-of-the-platform-itself).

<br>

`vg.screens`

## Screens

<table>
  <tr>
    <td width="50%"><img src="docs/assets/readme/investigate.png" alt="Investigate page with input for a link, message, email file or QR code"></td>
    <td width="50%"><img src="docs/assets/readme/report.png" alt="High-risk report for a bank KYC scam with cited findings F1 to F4"></td>
  </tr>
  <tr>
    <td><b>Investigate.</b> Paste a link or message, or upload an email file or QR code.</td>
    <td><b>Report.</b> A verdict, its score and evidence coverage, with each finding cited.</td>
  </tr>
  <tr>
    <td><img src="docs/assets/readme/dashboard.png" alt="Threat Desk dashboard with report totals, on-chain anchors and active campaigns"></td>
    <td><img src="docs/assets/readme/models.png" alt="Our AI page showing false alarms falling from 85.5% to 9.7% after fine-tuning"></td>
  </tr>
  <tr>
    <td><b>The Threat Desk.</b> Activity, risk mix and indicators that keep coming back.</td>
    <td><b>Our AI.</b> Live evaluation numbers, served from the model metrics.</td>
  </tr>
</table>

<sub>Captured from a local instance using demo inputs, with System-2 offline. That is why the status bar reads "Rules only" and the report shows the rule-based fallback summary.</sub>

<br>

`vg.models`

## Our AI

Instead of calling a third-party LLM, Vigil runs a self-hosted **System-1 / System-2 hybrid**.

| | System-1 | System-2 |
|---|---|---|
| **What** | Calibrated classifiers we trained: `host-v2` for URLs and `msg-v1` for messages | `vigil-s2`: Qwen3-1.7B (4-bit) fine-tuned with LoRA on MLX, distilled from a local teacher |
| **Job** | Fast calibrated signals on every request, and routing confidently benign messages past System-2 | Reads intent ("do **not** share your OTP" vs "share the OTP") and writes explanations that must cite evidence |
| **Speed** | < 5 ms on CPU | 631 ms average in evaluation |
| **Size** | ~10 MB | ~1 GB |

Fine-tuning cut false alarms on legitimate messages from **85.5% to 9.7%** on a held-out test set of 169 messages,
including whole scam families never seen in training.

| Measure | Result |
|---|---|
| `vigil-s2` scam recall | **93.3%** |
| `vigil-s2` legitimate false positives (base model: 85.5%) | **9.7%** |
| `vigil-s2` evidence quotes grounded in the input | **98.7%** |
| `vigil-s2` valid structured output | **100%** |
| Full hybrid scam recall / legitimate false positives | **95.5%** / **11.3%** |
| `host-v2` live OpenPhish URLs detected (out-of-time, n=227) | **86.3%** |
| `host-v2` false positives on real legitimate subdomains (n=40) | **2.5%** |
| `host-v2` expected calibration error | **0.008** |
| `msg-v1` held-out SMS/email F1 (n=4,378) | **0.9734** |

The [model card](docs/MODEL_CARD.md) has the complete evaluation, known limitations and a round-2 fine-tune we measured
and chose not to deploy because it missed real scams.

<br>

`vg.limits`

## Known limits

- **Low risk doesn't mean safe.** New or targeted attacks can slip past automated checks.
- **The link model reads hostnames only.** It can't recognise a compromised legitimate site. Threat intel, page checks
  and TLS cover part of that gap.
- **Training data is mostly English**, with some Hinglish. Other languages are less reliable.
- **An on-chain record proves integrity, not truth.** It shows a report hasn't changed since it was anchored, not that
  its conclusions are right.
- **Accounts created with only a username can't be recovered** if the password is lost.
- **Password accounts have no reset or email verification yet**, because Vigil doesn't send email. Signing in with
  Google for the same address links the accounts and removes the password.
- **One API instance unless Redis is configured.** Without `REDIS_URL`, rate limits and jobs are per process.
- **Message checks are weaker without System-2.** Scam recall is 95.5% with it and 49.4% on rules and System-1 alone.

<br>

`vg.quickstart`

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

Reports go to Postgres when `DATABASE_URL` is set in `.env`, otherwise to a local SQLite file. Accounts are stored in the
same database, so no extra service is needed. Without an account you can still run investigations, but History and the
Dashboard need sign-in.

A Hardhat node keeps its chain in memory: after restarting it, run `deploy:local` again. Reports anchored earlier show
as not anchored and can be registered again.

<details>
<summary><b>Optional: the self-hosted System-2 model</b></summary>

<br>

Without it the backend falls back to a local Ollama model, then to template summaries. Link verdicts don't use
System-2. Message and email verdicts do use its signal, so with no model available they rely on rules and System-1 and
catch fewer scams. The status bar shows "Rules only" when that happens.

```bash
.venv/bin/pip install mlx-lm    # Apple Silicon only
scripts/serve_s2.sh             # serves on :8090; needs ml/models/qwen3-1.7b-4bit (not in the repo)
```

For Linux or cloud hosting, `scripts/export_s2.sh` packages the model for Ollama as `vigil-s2`. Point the backend at it
with `S2_BASE_URL=http://<host>:11434/v1` and `S2_MODEL=vigil-s2`.

</details>

<details>
<summary><b>Deploy to Sepolia</b></summary>

<br>

Use a dedicated wallet holding only test ETH. In `.env`, set `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY`, then run
`(cd contracts && npm run deploy:sepolia)`. Point `CHAIN_RPC_URL`, `CHAIN_PRIVATE_KEY`, `CHAIN_CONTRACT_ADDRESS` and
`CHAIN_DEPLOY_BLOCK` at that deployment, set `NEXT_PUBLIC_RPC_URL` (a public RPC, because it ships to the browser) and
`NEXT_PUBLIC_CONTRACT_ADDRESS` in `frontend/.env.local`, and rebuild the frontend.

The current `ThreatRegistry` deployment is
[`0x012175dc…f216F`](https://sepolia.etherscan.io/address/0x012175dc68cb5480e37419a2ec9e04ee5Eef216F) on Sepolia.

</details>

<details>
<summary><b>Run the tests</b></summary>

<br>

```bash
.venv/bin/pip install pytest && .venv/bin/python -m pytest tests   # backend
(cd contracts && npm test)                                         # contract
.venv/bin/python tests/run_cases.py                                # end-to-end cases → docs/TESTING.md
```

</details>

<details>
<summary><b>Try the tamper demo</b></summary>

<br>

Register a report on-chain from its report page, then:

```bash
.venv/bin/python scripts/tamper_report.py <report_id>             # changes the verdict and rewrites the stored hash
.venv/bin/python scripts/tamper_report.py <report_id> --restore   # puts it back
```

Click **Verify against chain** after each step.

</details>

<details>
<summary><b>Reproduce the models</b></summary>

<br>

```bash
# data (public): PhiUSIIL (UCI), Tranco top-1M, OpenPhish feed, UCI SMS Spam, phishing-email corpus → ml/data/
.venv/bin/python ml/train_url.py          # System-1 URL model  → backend/app/ml/artifacts/url_model.joblib
.venv/bin/python ml/train_msg.py          # System-1 msg model  → msg_model.joblib
.venv/bin/python ml/build_distill.py --emails 600   # local teacher labels (Ollama qwen3:4b-instruct)
.venv/bin/python ml/collect_reports.py && .venv/bin/python ml/build_explain.py
.venv/bin/python ml/build_s2_sets.py && scripts/train_s2.sh   # LoRA fine-tune (MLX)
.venv/bin/python ml/eval_s2.py            # base vs fine-tuned vs teacher vs System-1 → s2_metrics.json
```

</details>

<br>

`vg.deploy`

## Deploying

By default the API binds to localhost and accepts only local hosts and origins. To serve other machines, set these in
`.env`:

| Variable | Set it to |
|---|---|
| `HOST` | `0.0.0.0` (read by `scripts/run_api.sh`) |
| `ALLOWED_HOSTS` | The API's own hostname, comma-separated if there are several |
| `CORS_ORIGINS` | The frontend's exact origin, such as `https://app.example.com` |
| `DATABASE_URL` | A Postgres connection string. Without it, reports stay in a local SQLite file |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | From a Google Cloud OAuth web client, for "Continue with Google". Leave unset to turn it off |
| `GOOGLE_REDIRECT_URI` | `https://<your-api-host>/api/auth/google/callback`, matching the Google Cloud setting exactly |
| `FRONTEND_URL` | The frontend's origin, where people return after Google sign-in. Defaults to the first `CORS_ORIGINS` entry |
| `SESSION_COOKIE_SAMESITE` | Leave as `lax` when the frontend and API share a site, like `example.com` and `api.example.com`. Use `none` only across different sites, where some browsers may still block the cookie |
| `REPORT_RETENTION_DAYS` | The number of days to keep reports. The default, `0`, keeps them forever |

In `frontend/.env.local`, set `NEXT_PUBLIC_API_URL`, then rebuild, because `NEXT_PUBLIC_` values are
fixed at build time. `NEXT_PUBLIC_TRUSTED_REPORTER` must be the backend signer's public address.

The backend also has a container image, which runs as a non-root user and stores SQLite in `/data`:

```bash
docker build -t vigil-api backend
docker run -p 8000:8000 --env-file .env -v vigil-data:/data vigil-api
```

**Running more than one API instance needs Redis.** Without `REDIS_URL`, rate limits, jobs and the result cache live in
each process's memory, which is only correct for a single instance: with several, each keeps its own rate-limit count,
and a job can only be polled on the instance that created it. Set `REDIS_URL` to share all three. Each analysis still
runs on the instance that accepted it, so if that instance stops mid-analysis, the job stays `running` until it
expires and the input can be resubmitted after `JOB_INFLIGHT_TTL_SECONDS`. `GET /api/health` reports which mode is
active as `shared_state`. Behind a reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy's address, or every visitor
will share one rate limit.

**What needs an account**

| Action | Guest | Signed in |
|---|---|---|
| Run an investigation | Yes | Yes |
| Open a report | Anyone with the link | Owner only |
| History and the Dashboard | No | Your own reports |
| Anchor a report on-chain | No | Yes, up to the hourly cap |
| Verify a report you can open | Yes | Yes |

<details>
<summary><b>Other settings</b></summary>

<br>

| Variable | Default | What it does |
|---|---|---|
| `RATE_LIMIT_PER_MIN` | `20` | New analyses per minute, per IP |
| `CHAIN_RATE_LIMIT_PER_MIN` | `120` | Chain status, lookup and verify calls per minute, per IP |
| `ANCHOR_MAX_PER_HOUR` | `60` | Cap on on-chain transactions per hour |
| `AUTH_RATE_LIMIT_PER_MIN` | `10` | Sign-up and sign-in attempts per minute, per IP and per email |
| `SESSION_TTL_DAYS` | `14` | How long a sign-in lasts |
| `CHAIN_TRUSTED_REPORTER` | Signer's address | Only needed if the signing key isn't on this server. Records from other addresses are rejected |
| `REDIS_URL` | Unset | Shares rate limits, jobs and the result cache across API instances. Required for more than one |
| `JOB_TTL_SECONDS` / `JOB_INFLIGHT_TTL_SECONDS` | `3600` / `900` | With Redis: how long a job can be polled, and how long a stalled analysis blocks resubmitting the same input |
| `JOB_WORKERS` | `4` | Background analysis workers |
| `CACHE_TTL_URL` / `CACHE_TTL_MESSAGE` | `600` / `3600` | Result cache lifetime, in seconds |
| `MAX_JSON_BODY_BYTES` / `EMAIL_MAX_BODY_BYTES` | `262144` / `3145728` | Request size limits |
| `EMAIL_TRUSTED_AUTHSERV_IDS` | Unset | Trust email authentication results only from the named servers |
| `S2_BASE_URL` / `S2_MODEL` / `S2_TIMEOUT` | `http://127.0.0.1:8090/v1` / `default_model` / `45` | System-2 server |
| `OLLAMA_URL` / `FALLBACK_MODEL` | `http://127.0.0.1:11434` / `qwen3:4b-instruct-2507-q4_K_M` | Fallback model |
| `ROUTER_ENABLED` | `1` | Set to `0` to send every message to System-2 |
| `DB_PATH` / `DB_POOL_MAX` | `backend/data/reports.db` / `8` | SQLite file location and Postgres pool size |
| `URLHAUS_AUTH_KEY` / `GSB_API_KEY` | Unset | Optional threat intel. When set, submitted URLs are sent to abuse.ch and Google |
| `VIGIL_VENV` | `~/.venvs/vigil` | Virtualenv used by `run_api.sh`, falling back to `.venv` |

</details>

<br>

`vg.docs`

## Docs

| Document | What it covers |
|---|---|
| [API.md](docs/API.md) | API contract for the frontend and Web3 integration, including report hash format and verification |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture, analysis pipeline, threat-intel sources and security methodology |
| [MODEL_CARD.md](docs/MODEL_CARD.md) | Training data, evaluation results and limitations for each model |
| [TESTING.md](docs/TESTING.md) | Test cases with observed results and model evaluation |
| [DEMO.md](docs/DEMO.md) | A five-minute live demo script |
| [FRONTEND_GUIDE.md](docs/FRONTEND_GUIDE.md) | Guidance for building UI on the API, such as error handling and showing URLs safely |

Sample reports: [phishing URL](docs/sample_report_phishing_url.json) ·
[scam message](docs/sample_report_scam_message.json) · [TLS issue](docs/sample_report_tls_issue.json) ·
[legitimate OTP](docs/sample_report_legit_otp.json) · [benign URL](docs/sample_report_benign_url.json)

### Repository layout

```
backend/app/
  main.py            FastAPI endpoints          pipeline.py   investigation orchestration
  risk.py            deterministic risk engine  store.py      reports, hashing, correlation index
  auth.py            accounts and sessions      jobs.py       async jobs and the result cache
  email_pipeline.py  .eml investigation         schemas.py    request and report models
  checks/            fetcher (SSRF-safe) · domain · tls · page/headers · threatintel · message rules · email_auth
  chain.py           on-chain anchoring, verification and domain lookup
  ml/                System-1 models · System-2 client · prompts · artifacts/ (models + metrics)
contracts/           ThreatRegistry.sol · Hardhat tests · deploy script
frontend/            Next.js UI: landing · investigate · report · history · dashboard · our AI · field notes · sign-in
ml/                  teacher, distillation, training & evaluation scripts
scripts/             train_s2.sh · serve_s2.sh · export_s2.sh · run_api.sh · tamper_report.py
tests/               backend tests · run_cases.py (end-to-end suite)
```

<br>

`vg.references`

## References

**Datasets and threat intelligence**

1. Prasad, A., & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework
   based on similarity index and incremental learning. *Computers & Security*, 136.
   [DOI](https://doi.org/10.1016/j.cose.2023.103545) · [UCI dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
2. Le Pochat, V., et al. (2019). Tranco: A research-oriented top sites ranking hardened against manipulation. *NDSS*.
   [DOI](https://doi.org/10.14722/ndss.2019.23386) · [tranco-list.eu](https://tranco-list.eu/)
3. Almeida, T. A., & Gómez Hidalgo, J. M. (2011). [SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection). UCI Machine Learning Repository.
4. [OpenPhish](https://openphish.com/) phishing feed, with optional [URLhaus](https://urlhaus.abuse.ch/) and
   [Google Safe Browsing](https://developers.google.com/safe-browsing) lookups.
5. [crt.sh](https://crt.sh/) Certificate Transparency search, and [badssl.com](https://badssl.com/) test hosts.

**Models and methods**

6. Yang, A., et al. (2025). [Qwen3 Technical Report](https://arxiv.org/abs/2505.09388). arXiv:2505.09388.
7. Hu, E. J., et al. (2021). [LoRA: Low-Rank Adaptation of Large Language Models](https://arxiv.org/abs/2106.09685). arXiv:2106.09685.
8. Hinton, G., Vinyals, O., & Dean, J. (2015). [Distilling the Knowledge in a Neural Network](https://arxiv.org/abs/1503.02531). arXiv:1503.02531.
9. Zadrozny, B., & Elkan, C. (2002). Transforming classifier scores into accurate multiclass probability estimates.
   *KDD*. [DOI](https://doi.org/10.1145/775047.775151)
10. Platt scaling and isotonic regression: [scikit-learn probability calibration guide](https://scikit-learn.org/stable/modules/calibration.html).

**Standards and security guidance**

11. Certificates and transparency: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (X.509) ·
    [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) (OCSP) · [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Certificate Transparency)
12. Email authentication: [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) (SPF) ·
    [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) (DKIM) · [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) (DMARC)
13. Domain registration data: [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083) (RDAP)
14. OWASP [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) ·
    OWASP [LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

**Built with**

[Next.js](https://nextjs.org/) · [FastAPI](https://fastapi.tiangolo.com/) · [scikit-learn](https://scikit-learn.org/) ·
[MLX](https://github.com/ml-explore/mlx) · [mlx-lm](https://github.com/ml-explore/mlx-lm) · [Ollama](https://ollama.com/) ·
[Hardhat](https://hardhat.org/) · [ethers](https://docs.ethers.org/v6/)

**Team**

Built for HackMatrix by Team 0DAY.

<br>

`vg.license`

## License

Vigil's own code is released under the [MIT License](LICENSE).

Third-party material in this repo keeps its own terms. That includes the OpenPhish and Tranco feed files in
`backend/app/data/feeds/`, the datasets listed under [References](#references), and the Qwen3 base model that the
adapter in `ml/adapters/` was trained on. Check those terms before reusing them or the models trained from them.

<br>

<img src="docs/assets/readme/footer.png" alt="Vigil. Spotted something? Check the evidence first." width="100%">
