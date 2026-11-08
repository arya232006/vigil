"""API contract shared with the frontend and Web3 teammates.

Every analysis returns a `Report`. The Web3 registry stores `report_hash`
(sha256 of the canonical JSON of the report minus the hash field), never the
raw input.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low_risk"                        # no significant malicious indicators in available checks
    SUSPICIOUS = "suspicious"               # one or more indicators need further investigation
    HIGH = "high_risk"                      # multiple significant indicators
    CONFIRMED = "confirmed_malicious"       # authoritative threat intel / validated evidence
    INCONCLUSIVE = "inconclusive"           # insufficient data or sources unavailable


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


InputType = Literal["url", "domain", "message", "email"]
Module = Literal["url", "domain", "redirect", "tls", "headers", "threat_intel", "ml", "message", "correlation",
                 "email"]


class AnalyzeRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=20_000)
    type: Literal["auto", "url", "domain", "message"] = "auto"


class Finding(BaseModel):
    id: str                                  # "F1", "F2"... referenced by the explanation
    module: Module
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = {}            # raw technical evidence
    source: str                              # where the evidence came from
    impact: str | None = None
    recommendation: str | None = None
    limitations: str | None = None


class CheckStatus(BaseModel):
    name: str
    status: Literal["ok", "failed", "skipped", "unavailable"]
    detail: str | None = None


class RedirectHop(BaseModel):
    url: str
    status: int | None = None
    ip: str | None = None


class TargetInfo(BaseModel):
    submitted: str
    normalized_url: str | None = None
    final_url: str | None = None
    registered_domain: str | None = None
    hostname: str | None = None
    ip_addresses: list[str] = []
    redirect_chain: list[RedirectHop] = []
    domain_created: str | None = None
    domain_age_days: int | None = None
    registrar: str | None = None
    page_title: str | None = None


class TLSInfo(BaseModel):
    https: bool = False
    valid: bool | None = None
    subject_cn: str | None = None
    san: list[str] = []
    issuer: str | None = None
    issuer_org: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    hostname_match: bool | None = None
    key_type: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    protocol: str | None = None
    chain: list[dict[str, Any]] = []
    ct_log_entries: int | None = None
    verdict: Literal["valid", "suspicious", "potentially_compromised", "unavailable"] = "unavailable"


class Indicators(BaseModel):
    urls: list[str] = []
    domains: list[str] = []
    emails: list[str] = []
    phones: list[str] = []
    upi_ids: list[str] = []


class ModelScore(BaseModel):
    model: str
    label: str
    probability: float
    details: dict[str, Any] = {}


class Correlation(BaseModel):
    report_id: str
    shared: list[str]                         # e.g. ["domain:evil.com", "ip:1.2.3.4"]
    risk_level: RiskLevel
    analyzed_at: str


class Explanation(BaseModel):
    summary: str
    key_points: list[str] = []
    generated_by: str                         # "llm:<model>" or "template"


class Report(BaseModel):
    schema_version: str = "1.0"
    report_id: str
    input_type: InputType
    input: str
    analyzed_at: str                          # ISO-8601 UTC
    risk_level: RiskLevel
    risk_score: int                           # 0-100
    confidence: float                         # 0-1, evidence coverage
    findings: list[Finding] = []
    checks: list[CheckStatus] = []
    target: TargetInfo | None = None
    tls: TLSInfo | None = None
    indicators: Indicators | None = None
    model_scores: list[ModelScore] = []
    linked_reports: list[str] = []            # sub-reports for URLs extracted from a message
    correlations: list[Correlation] = []
    explanation: Explanation
    recommendations: list[str] = []
    limitations: list[str] = []
    report_hash: str = ""                     # 0x-prefixed sha256 over canonical JSON (excluding this field)
    # Track B: email reports only. Omitted from JSON when None so hashes of non-email reports are unchanged.
    email: EmailInfo | None = Field(default=None, exclude_if=lambda v: v is None)


class VerifyResponse(BaseModel):
    report_id: str
    stored_hash: str
    recomputed_hash: str
    provided_hash: str | None = None
    integrity_ok: bool


# --- Track A: jobs ---
# Async analysis jobs (POST /api/jobs, GET /api/jobs/{job_id}); see app/jobs.py and docs/API.md.
JobStatus = Literal["queued", "running", "done", "failed"]


class JobRequest(AnalyzeRequest):
    fresh: bool = False                       # true = ignore the result cache and run a new analysis


class JobInfo(BaseModel):
    job_id: str
    status: JobStatus
    input_type: InputType                     # resolved type (auto-detection already applied)
    created_at: str                           # ISO-8601 UTC
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_ms: int = 0                       # since submission; keeps growing while queued/running
    report_id: str | None = None              # set when status == "done"
    error: str | None = None                  # short reason when status == "failed" (no stack trace)
    cached: bool = False                      # true = answered from the result cache, no new analysis ran
    report: Report | None = None              # full report when status == "done"


# --- Track B: email ---
class EmailAuthResult(BaseModel):
    spf: str | None = None                    # pass / fail / softfail / neutral / none / temperror / permerror
    dkim: str | None = None                   # pass / fail / none / ... ("not_reported": signed, but no verdict)
    dmarc: str | None = None                  # pass / fail / none / ... (None: receiver did not evaluate DMARC)
    arc: str | None = None
    spf_domain: str | None = None             # envelope sender (smtp.mailfrom) domain
    dkim_domains: list[str] = []              # d= of DKIM signatures that passed
    spf_aligned: bool | None = None           # relaxed alignment with the From registered domain (RFC 7489)
    dkim_aligned: bool | None = None
    authserv_id: str | None = None            # server whose Authentication-Results header was trusted
    source: str | None = None


class EmailAttachment(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    detected_type: str | None = None          # from magic bytes
    risky: bool = False
    reasons: list[str] = []


class LinkMismatch(BaseModel):
    text: str                                 # what the reader sees
    href: str                                 # where the link really goes
    text_domain: str
    href_domain: str


class EmailInfo(BaseModel):
    from_address: str | None = None
    from_domain: str | None = None
    display_name: str | None = None
    reply_to: list[str] = []
    return_path: str | None = None
    sender: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    sender_is_freemail: bool = False
    auth: EmailAuthResult = Field(default_factory=EmailAuthResult)
    dmarc_policy: str | None = None           # reject / quarantine / none / missing / invalid / unavailable / not_checked
    spf_record: str | None = None
    received_hops: int = 0
    origin_ip: str | None = None              # earliest public IP in the Received chain (forgeable below your MX)
    body_source: str | None = None            # text/html | text/plain | none
    link_count: int = 0
    link_domains: list[str] = []
    link_mismatches: list[LinkMismatch] = []
    attachments: list[EmailAttachment] = []
    body_report_id: str | None = None         # message report for subject + body (rules, AI, link investigation)


class EmailAnalyzeRequest(BaseModel):
    raw: str = Field(..., min_length=1, max_length=2_000_000)   # full .eml source ("Show original" in mail apps)
    live_dns: bool = True                                        # DMARC / SPF DNS lookups for the sender domain


Report.model_rebuild()
JobInfo.model_rebuild()   # JobInfo embeds Report, which references EmailInfo
