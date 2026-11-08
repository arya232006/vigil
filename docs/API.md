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

<!-- ===================== Track B: email analysis (appended) ===================== -->
## Email analysis

`POST /api/analyze/email` with a JSON body (no multipart upload). Send the **full source** of the message
("Show original" / "Download message" / `.eml` file) as a string. Max 2,000,000 characters (3 MB request body,
HTTP 413 above). Rate-limited like `/api/analyze`. Takes as long as a message analysis plus up to ~3 s of DNS.

```json
{ "raw": "Received: ...\r\nAuthentication-Results: ...\r\nFrom: \"HDFC Bank\" <alerts@hdfc-bank.top>\r\n...", "live_dns": true }
```
```js
const raw = await file.text();   // <input type="file" accept=".eml">
fetch(`${API}/api/analyze/email`, {method: "POST", headers: {"Content-Type": "application/json"},
                                   body: JSON.stringify({raw})});
```

Returns a normal `Report` with `input_type: "email"`. `input` holds only `Email from <sender> | Subject: <subject>`
(the raw email is never stored in the email report). Header findings use `module: "email"`; the subject + body are
also run through the message pipeline (rules, self-hosted AI, link investigation): that report's id is
`email.body_report_id` = `linked_reports[0]` (link sub-reports follow), and its findings are copied in.

### `report.email`
| Field | Meaning |
|---|---|
| `from_address`, `from_domain`, `display_name`, `reply_to[]`, `return_path`, `sender`, `subject`, `date`, `message_id` | Parsed headers |
| `sender_is_freemail` | From is a consumer webmail domain (gmail, outlook, yahoo, ...) |
| `auth.spf / dkim / dmarc / arc` | Verdicts recorded by the receiving server (`pass`, `fail`, `softfail`, `none`, ...; `null` = not evaluated) |
| `auth.spf_domain`, `auth.dkim_domains[]`, `auth.spf_aligned`, `auth.dkim_aligned` | Envelope / signing domains and DMARC relaxed alignment with the From domain |
| `auth.authserv_id`, `auth.source` | Which header was trusted |
| `dmarc_policy` | Live DNS: `reject`, `quarantine`, `none`, `missing`, `invalid`, `unavailable`, `not_checked` |
| `spf_record` | The sender domain's SPF TXT record (live DNS) |
| `received_hops`, `origin_ip` | Received-chain length and earliest public sending IP |
| `link_count`, `link_domains[]`, `link_mismatches[]` (`text`, `href`, `text_domain`, `href_domain`) | Links in the body; mismatches = visible text shows one domain, href goes to another |
| `attachments[]` (`filename`, `content_type`, `size`, `sha256`, `detected_type`, `risky`, `reasons[]`) | Static attachment analysis (`detected_type` from magic bytes) |

### Checks
- **Authentication (SPF / DKIM / DMARC):** read from `Authentication-Results` (RFC 8601). Only the topmost
  header (added by your own receiving server) and others with the same authserv-id are trusted, because the sender
  can forge headers further down. Set `EMAIL_TRUSTED_AUTHSERV_IDS=mx.yourdomain.com` to trust only named servers.
  Falls back to `ARC-Authentication-Results` (forwarded mail) and `Received-SPF`. `dmarc=fail` → high (medium
  when an ARC seal says the original passed); if the server did not evaluate DMARC we compute alignment
  ourselves. A pass is reported as info only: attackers authenticate their own look-alike domains.
- **DKIM body hash:** the canonicalised body hash is recomputed locally and compared with the signature's `bh=`
  (proves the body is unchanged since signing; the RSA signature itself is not verified).
- **DNS posture (live, 3 s timeouts):** `_dmarc.<domain>` policy (missing / p=none / quarantine / reject) and SPF
  TXT presence (`+all` flagged). Skipped for webmail domains; `unavailable` on timeout.
- **Sender identity:** multiple / malformed From headers (parser-ambiguity spoofing); display-name spoofing (an
  address, domain or brand in the display name that the sender does not own); look-alike sender domains
  (edit distance 1-2 after homoglyph folding, brand embedded in the domain, punycode); free-mail accounts claiming
  an executive role (BEC / CEO fraud) or an organisation; Reply-To diverted to webmail or another domain;
  Return-Path on another domain without an aligned DKIM signature.
- **Links:** anchors whose visible text shows a different domain than the real href (Safe Links / Google
  redirects unwrapped; known newsletter click-trackers reported as low), raw-IP links, `javascript:`/`data:`
  links, forms / password fields embedded in the email. The body text sent to the message pipeline uses the
  real href, so link investigation follows the true destination.
- **Attachments (never opened):** risky types (executables/scripts, archives/disk images, HTML/SVG, macro
  Office files), double extensions (`invoice.pdf.exe`), right-to-left-override names, declared Content-Type vs
  extension mismatch, magic bytes vs extension mismatch, SHA-256 for sandbox lookups.
- **Received chain:** hop count and origin IP (info).

### Risk
Email level: any critical → `high_risk`; ≥2 high → `high_risk`; 1 high or ≥2 medium → `suspicious`. Combined with
the body report by taking the more severe level (inconclusive only if both are). Escalated to `high_risk` when an
authentication failure or identity spoof (medium or above) comes with a harmful request in the body (OTP,
credentials, payment, upfront fee, personal data, remote access). `confidence` = evidence coverage (sender parsed,
server auth results present, DNS answered, body confidence). The reasoning is in `checks[name="risk_engine"]`.
