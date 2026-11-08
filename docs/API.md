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

<!-- --- Track A: jobs --- -->
## Async jobs & caching

An analysis takes 2–15 s. Instead of holding one HTTP request open, the frontend can **submit a job, get a
`job_id` back immediately and poll it**. Finished reports are cached, so resubmitting the same input is instant.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/jobs` | Body `{"input": "...", "type": "auto", "fresh": false}` → job (HTTP **202**) |
| GET | `/api/jobs/{job_id}` | Job status; includes the full `report` once `status` is `done`. **404** for unknown ids |
| POST | `/api/analyze?fresh=true` | Same synchronous endpoint as before, now cached; response header `X-Cache: HIT` or `MISS` |

### Job object

| Field | Meaning |
|---|---|
| `job_id` | 12 hex chars |
| `status` | `queued` → `running` → `done` or `failed` |
| `input_type` | `url` / `domain` / `message` (auto-detection already applied) |
| `created_at`, `started_at`, `finished_at` | ISO-8601 UTC (`null` until reached) |
| `elapsed_ms` | ms since submission; keeps growing while queued/running, frozen when finished |
| `report_id` | set when `done` (same id as `GET /api/reports/{id}`) |
| `report` | full `Report` (same shape as `/api/analyze`) when `done`, else `null` |
| `error` | short reason when `failed` (no stack trace), else `null` |
| `cached` | `true` = answered from the cache, no new analysis ran |

### Examples

Submit:
```http
POST /api/jobs
{"input": "http://sbi-kyc-update.top/login", "type": "auto"}
```
```json
HTTP/1.1 202 Accepted
{"job_id": "3f9c1a7e02bd", "status": "queued", "input_type": "url",
 "created_at": "2026-11-08T10:15:02.114+00:00", "started_at": null, "finished_at": null,
 "elapsed_ms": 1, "report_id": null, "error": null, "cached": false, "report": null}
```

Poll while running:
```json
GET /api/jobs/3f9c1a7e02bd
{"job_id": "3f9c1a7e02bd", "status": "running", "input_type": "url",
 "created_at": "2026-11-08T10:15:02.114+00:00", "started_at": "2026-11-08T10:15:02.116+00:00",
 "finished_at": null, "elapsed_ms": 4210, "report_id": null, "error": null, "cached": false, "report": null}
```

Done:
```json
{"job_id": "3f9c1a7e02bd", "status": "done", "input_type": "url",
 "created_at": "2026-11-08T10:15:02.114+00:00", "started_at": "2026-11-08T10:15:02.116+00:00",
 "finished_at": "2026-11-08T10:15:09.874+00:00", "elapsed_ms": 7760, "report_id": "a1b2c3d4e5f6",
 "error": null, "cached": false, "report": {"report_id": "a1b2c3d4e5f6", "risk_level": "high_risk", "...": "..."}}
```

Failed:
```json
{"job_id": "77d0e1c2b3a4", "status": "failed", "...": "...", "report_id": null,
 "error": "TimeoutError: timed out", "cached": false, "report": null}
```

Resubmitting the same input within the cache TTL returns a **new job that is already `done`**, with
`"cached": true` and the `report` included in the POST response itself (no polling needed).

### Frontend polling guidance

1. `POST /api/jobs`. If the response already has `status: "done"` (cache hit), render `report` straight away.
2. Otherwise `GET /api/jobs/{job_id}` **every 1 s**. Stop as soon as `status` is `done` (render `report`) or
   `failed` (show `error` and a "Try again" button that resubmits with `"fresh": true`).
3. While waiting, show a progress state with the elapsed time (`elapsed_ms`, or count locally from submit) and
   the stage: `queued` = "Waiting for a worker", `running` = "Investigating…".
4. Stop polling after ~60 s and show a timeout message. A `404` means the server restarted or the job was
   evicted (only the latest 1000 jobs are kept): resubmit.
5. A "cached" badge (`cached: true`) is useful in the UI, with a "Re-run analysis" action that sends
   `"fresh": true`.

```js
async function investigate(input, fresh = false) {
  let job = await (await fetch(`${API}/api/jobs`, {method: "POST", headers: {"Content-Type": "application/json"},
                                body: JSON.stringify({input, type: "auto", fresh})})).json();
  const t0 = Date.now();
  while (job.status === "queued" || job.status === "running") {
    if (Date.now() - t0 > 60_000) throw new Error("Analysis timed out");
    await new Promise(r => setTimeout(r, 1000));
    job = await (await fetch(`${API}/api/jobs/${job.job_id}`)).json();
    showProgress(job.status, job.elapsed_ms);          // e.g. "Investigating… 4.2 s"
  }
  if (job.status === "failed") throw new Error(job.error);
  return job;                                          // job.report, job.cached
}
```

### Cache behaviour

- **Key** = requested `type` + resolved type + normalised input. URLs/domains are normalised like the scanner does
  (scheme and host lowercased, defanged `hxxp`/`[.]` restored, default path `/`), so `HTTPS://Example.com` and
  `https://example.com/` share an entry. Messages are keyed by the sha256 of the text with whitespace collapsed
  (case-sensitive). `type: "auto"` and an explicit `type: "url"` are separate entries.
- **TTL**: `CACHE_TTL_URL` (default 600 s) for url/domain reports, `CACHE_TTL_MESSAGE` (default 3600 s) for
  messages. `0` disables caching for that kind.
- Only successful analyses are cached. `failed` jobs and `inconclusive` reports (often a temporary network or
  feed outage) are not, so the next submission runs again.
- `POST /api/jobs` and `POST /api/analyze` share one cache: a job's result is a `HIT` for `/api/analyze` and the
  other way round. Cached answers are the stored reports (same `report_id` and `report_hash`), read from the
  report store.
- **`fresh: true`** (jobs body) or **`?fresh=true`** (`/api/analyze`) skips the cache lookup and runs a new
  analysis; its result then replaces the cache entry.
- **De-duplication**: submitting an input that is already `queued`/`running` returns that same job (same `job_id`),
  even with `fresh: true`, since that analysis is already fresh.
- **Rate limit** (20/min per IP, HTTP 429) only counts submissions that start a new analysis. Cache hits and
  de-duplicated submissions are free.
- Jobs run on a pool of `JOB_WORKERS` threads (default 4); extra jobs wait as `queued`. Jobs and the cache live in
  memory: a server restart forgets them (reports stay in SQLite).
- `X-Cache` is listed in `Access-Control-Expose-Headers`, so browser code can read it cross-origin.
