# ThreatScope API — integration guide (frontend + Web3)

Base URL (local): `http://<backend-host>:8000` · Interactive docs: `http://<backend-host>:8000/docs`
Full typed schema: `backend/app/schemas.py` (the `Report` model is the contract).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze` | Body `{"input": "<url | domain | message text>", "type": "auto"}` → full `Report` |
| GET | `/api/reports?limit=50` | Recent reports (id, time, type, risk_level, report_hash, input_preview) |
| GET | `/api/reports/{id}` | Full `Report` |
| GET | `/api/reports/{id}/canonical` | Exact canonical JSON string that is hashed |
| GET | `/api/reports/{id}/verify?hash=0x…` | Recompute hash, compare with stored + provided hash |
| GET | `/api/stats` | Dashboard: counts by risk level / input type + indicators recurring across risky reports (campaigns) |
| GET | `/api/health` | Feed + model status |
| GET | `/api/models` | Evaluation metrics of the self-hosted models (show these in the UI!) |

`type` can be `auto | url | domain | message`. URL analyses take ~5–12 s, messages ~5–15 s
(they also investigate up to 3 links inside the message). Show a progress state.
Rate limit: 20 analyses/min per IP (HTTP 429).

## Report — fields the frontend should show

- `risk_level`: `low_risk | suspicious | high_risk | confirmed_malicious | inconclusive` (colour badge)
- `risk_score` (0-100), `confidence` (0-1 = evidence coverage)
- `explanation.summary`, `explanation.key_points[]`, `explanation.generated_by` (shows which self-hosted model wrote it)
- `findings[]`: `id` (F1…), `severity` (critical/high/medium/low/info), `title`, `description`, `evidence` (object),
  `source`, `impact`, `recommendation`, `limitations`, `module`
- `checks[]`: each check's `status` (ok / failed / skipped / unavailable) — show as a checklist
- `target` (URL reports): `final_url`, `redirect_chain[]`, `ip_addresses`, `domain_age_days`, `registrar`, `page_title`
- `tls` (URL reports): `verdict` (valid / suspicious / potentially_compromised / unavailable), issuer, expiry, `chain[]`
- `indicators` (message reports): extracted `urls`, `domains`, `emails`, `phones`, `upi_ids`
- `linked_reports[]`: report ids of links found inside a message (fetch them with GET `/api/reports/{id}`)
- `model_scores[]`: System-1 / System-2 outputs with calibrated probabilities
- `correlations[]`: earlier reports sharing domains/IPs/certs/phones/UPI ids/similar wording
- `recommendations[]`, `limitations[]`, `analyzed_at`, `report_hash`

## Web3 — what goes on-chain

Store **only** `report_hash` (bytes32, `0x` + 64 hex) plus metadata you choose (reporter address, timestamp,
risk level enum, status). **Never** put the URL, message text or any personal data on-chain.

`report_hash = sha256( canonical_json(report without the report_hash field) )` where canonical JSON =
`json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, UTF-8 encoded.

Verification flow:
1. Read hash from the contract for a report id.
2. `GET /api/reports/{id}/verify?hash=<onchain hash>` → `integrity_ok: true/false`.
3. Independent check (no trust in our server): `GET /api/reports/{id}/canonical`, sha256 it yourself
   (e.g. `ethers.sha256(ethers.toUtf8Bytes(text))`), compare with the on-chain value.

Suggested contract shape (your call):
```solidity
struct ThreatReport { bytes32 reportHash; address reporter; uint64 timestamp; uint8 riskLevel; uint8 status; }
// status: 0=submitted 1=validated 2=disputed 3=revised ; revisions point to a new reportHash
function submitReport(bytes32 reportHash, uint8 riskLevel) external returns (uint256 id);
function updateStatus(uint256 id, uint8 status) external;      // validator role
function reviseReport(uint256 id, bytes32 newHash) external;   // keeps history via events
event ReportSubmitted(uint256 indexed id, bytes32 reportHash, address reporter, uint8 riskLevel);
```
Risk-level enum mapping: 0 low_risk, 1 suspicious, 2 high_risk, 3 confirmed_malicious, 4 inconclusive.
