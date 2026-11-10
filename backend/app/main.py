"""Vigil API: AI + cybersecurity investigation engine.

Run: scripts/run_api.sh (binds to localhost; see README for deploying)
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError
from starlette.datastructures import MutableHeaders

from . import auth, chain, email_pipeline, jobs, pipeline, shared, store
from .checks import threatintel
from .ml import system1, system2
from .schemas import (
    AnalyzeRequest,
    AnchorInfo,
    ChainVerifyResponse,
    EmailAnalyzeRequest,
    JobInfo,
    JobRequest,
    Report,
    VerifyResponse,
)

# ---------------------------------------------------------------- configuration -------------------------------------
MAX_JSON_BODY_BYTES = int(os.getenv("MAX_JSON_BODY_BYTES", "262144"))     # 20,000 characters, even if fully escaped
EMAIL_MAX_BODY_BYTES = int(os.getenv("EMAIL_MAX_BODY_BYTES", str(3 * 1024 * 1024)))  # 2 MB .eml + JSON escaping
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
RATE = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))
CHAIN_RATE = int(os.getenv("CHAIN_RATE_LIMIT_PER_MIN", "120"))
AUTH_RATE = int(os.getenv("AUTH_RATE_LIMIT_PER_MIN", "10"))
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"     # set behind a reverse proxy (Hugging Face Spaces, tunnels)


@asynccontextmanager
async def _lifespan(_: FastAPI):
    """Warm the threat feeds and models in the background, so the first request doesn't pay for it."""
    threading.Thread(target=threatintel.keep_fresh, daemon=True).start()
    threading.Thread(target=lambda: (system1._url(), system1._msg()), daemon=True).start()
    yield


app = FastAPI(title="Vigil API", version="1.0", lifespan=_lifespan,
              description="Self-hosted AI + cybersecurity threat investigation. No third-party AI services.")


# ---------------------------------------------------------------- middleware -----------------------------------------
class _Hardening:
    """Caps request bodies before they are buffered and adds security headers. Pure ASGI, so streaming still works."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return
        path = scope["path"]
        limit = EMAIL_MAX_BODY_BYTES if path == "/api/analyze/email" else MAX_JSON_BODY_BYTES
        seen = 0

        async def capped_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise HTTPException(413, "Request too large")
            return message

        async def with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                if not path.startswith(DOC_PATHS):
                    headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
                    headers["Cache-Control"] = "no-store"
            await send(message)

        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await JSONResponse({"detail": "Request too large"}, 413)(scope, receive, with_headers)
            return
        await self.inner(scope, capped_receive, with_headers)


# Added last means outermost: the host check runs first, and CORS headers also reach error responses.
app.add_middleware(_Hardening)
app.add_middleware(CORSMiddleware, allow_origins=auth.allowed_origins(), allow_credentials=True,
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"], expose_headers=["X-Cache"])
app.add_middleware(TrustedHostMiddleware,                  # stops DNS rebinding against a locally running API
                   allowed_hosts=[h.strip() for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")])


@app.exception_handler(jobs.QueueUnavailable)
async def _queue_unavailable(request: Request, exc: jobs.QueueUnavailable):
    return JSONResponse({"detail": "The job queue is unavailable right now. Try again shortly."}, 503)


# ---------------------------------------------------------------- shared helpers -------------------------------------
_hits: dict[tuple[str, str], deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    """Real visitor IP. Behind a trusted proxy every request comes from the proxy, so per-IP rate limiting would
    become one global limit; use the left-most X-Forwarded-For entry (or CF-Connecting-IP) instead."""
    if TRUST_PROXY:
        cf = request.headers.get("cf-connecting-ip")
        xff = request.headers.get("x-forwarded-for", "")
        ip = cf or (xff.split(",")[0].strip() if xff else "")
        if ip:
            return ip[:64]
    return request.client.host if request.client else "unknown"


def _rate_limit(ip: str, bucket: str = "analysis", limit: int | None = None):
    """Shared across instances through Redis when REDIS_URL is set; otherwise, or if Redis is down, counted per process."""
    limit = RATE if limit is None else limit
    allowed = shared.allow(bucket, ip, limit)
    if allowed is False:
        raise HTTPException(429, f"Rate limit: {limit} requests per minute")
    if allowed:
        return
    now = time.time()
    if len(_hits) > 50_000:                                 # forget idle clients instead of growing without bound
        for key in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
            del _hits[key]
    q = _hits[(bucket, ip)]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, f"Rate limit: {limit} requests per minute")
    q.append(now)


def _report_or_404(report_id: str, viewer_id: str | None) -> Report:
    r = store.get_for_viewer(report_id, viewer_id)
    if not r:
        raise HTTPException(404, "report not found")
    return r


def _chain_call(fn, *args):
    """A chain outage must never read as a failed integrity check, so it surfaces as 502/503."""
    try:
        return fn(*args)
    except chain.ChainRateLimited as e:
        raise HTTPException(429, str(e)) from None
    except chain.ChainNotConfigured as e:
        raise HTTPException(503, str(e)) from None
    except chain.ChainError as e:
        raise HTTPException(502, str(e)) from None


# ---------------------------------------------------------------- service -------------------------------------------
@app.get("/api/health")
def health():
    public = {k: v for k, v in system2.status().items() if k != "student_url"}
    return {"status": "ok", "feeds": threatintel.feed_status(), "system2": public, "shared_state": jobs.BACKEND}


@app.get("/api/models")
def models():
    """Training/evaluation metrics of the self-hosted models."""
    return system1.metrics()


# ---------------------------------------------------------------- accounts ------------------------------------------
@app.post("/api/auth/signup", status_code=201)
def signup(details: auth.SignUp, request: Request, response: Response):
    auth.require_allowed_origin(request)
    _rate_limit(_client_ip(request), "auth", AUTH_RATE)
    return auth.sign_up(details, response)


@app.post("/api/auth/login")
def login(credentials: auth.Login, request: Request, response: Response):
    """Limited per IP and per account name, so spreading guesses across addresses doesn't help against one account."""
    auth.require_allowed_origin(request)
    _rate_limit(_client_ip(request), "auth", AUTH_RATE)
    _rate_limit(credentials.identifier.strip().lower()[:254], "auth-email", AUTH_RATE)
    return auth.sign_in(credentials, response)


@app.get("/api/auth/username")
def suggest_username(request: Request):
    _rate_limit(_client_ip(request), "username", AUTH_RATE * 3)
    return {"username": auth.generate_username()}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    auth.require_allowed_origin(request)
    return auth.sign_out(request, response)


@app.get("/api/auth/me")
def me(request: Request, response: Response):
    return {"user": auth.account(request, response), "google": auth.google_enabled()}


@app.get("/api/auth/google/start")
def google_start(next: Annotated[str, Query(max_length=512)] = auth.DEFAULT_NEXT):
    return auth.google_start(next)


@app.get("/api/auth/google/callback")
def google_callback(request: Request):
    _rate_limit(_client_ip(request), "auth", AUTH_RATE)
    return auth.google_finish(request)


# ---------------------------------------------------------------- analysis ------------------------------------------
@app.post("/api/analyze", response_model=Report)
async def analyze(req: AnalyzeRequest, request: Request, user: auth.Viewer, fresh: bool = False):
    """Synchronous analysis. Answered from the result cache unless `fresh`; the X-Cache header says which.
    Rate limiting only applies when a new analysis actually runs."""
    report = None if fresh else jobs.cached_report(req.input, req.type, user)
    cache = "HIT" if report is not None else "MISS"
    if report is None:
        _rate_limit(_client_ip(request))
        report = await run_in_threadpool(pipeline.analyze, req.input, req.type, user)
        jobs.remember(req.input, req.type, report, user)
    return JSONResponse(report.model_dump(mode="json"),
                        headers={"X-Cache": cache, "Access-Control-Expose-Headers": "X-Cache"})


@app.post("/api/jobs", response_model=JobInfo, status_code=202)
async def create_job(req: JobRequest, request: Request, user: auth.Viewer):
    """Queue an analysis and return at once; poll GET /api/jobs/{job_id}. A cached result comes back already
    `done` with `cached: true` and the report; an identical input already in progress returns that job."""
    return jobs.submit(req.input, req.type, fresh=req.fresh, on_new_work=lambda: _rate_limit(_client_ip(request)),
                       owner_id=user)


@app.get("/api/jobs/{job_id}", response_model=JobInfo)
async def get_job(job_id: str, user: auth.Viewer):
    """Job status; includes the full `report` once `status` is `done`. 404 for unknown or evicted ids."""
    job = jobs.get(job_id, user)
    if job is None:
        raise HTTPException(404, "job not found")
    return job


@app.post("/api/analyze/email", response_model=Report, openapi_extra={"requestBody": {
    "required": True, "content": {"application/json": {"schema": EmailAnalyzeRequest.model_json_schema()}}}})
async def analyze_email(request: Request, user: auth.Viewer):
    """Analyse a raw email (.eml source): SPF/DKIM/DMARC + alignment, sender identity, deceptive links,
    attachments, Received chain, sender-domain DNS posture, plus the message pipeline on subject + body.

    JSON body {"raw": "<full .eml source>", "live_dns": true}, read with a hard size cap before parsing so an oversized
    upload can't exhaust memory."""
    _rate_limit(_client_ip(request))
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > EMAIL_MAX_BODY_BYTES:
        raise HTTPException(413, f"Email too large (max {EMAIL_MAX_BODY_BYTES} bytes of JSON)")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > EMAIL_MAX_BODY_BYTES:
            raise HTTPException(413, f"Email too large (max {EMAIL_MAX_BODY_BYTES} bytes of JSON)")
    try:
        req = EmailAnalyzeRequest.model_validate_json(bytes(buf))
    except ValidationError as e:
        raise RequestValidationError(e.errors(include_url=False)) from None
    return await run_in_threadpool(email_pipeline.analyze_email, req.raw, req.live_dns, user)


# ---------------------------------------------------------------- reports -------------------------------------------
@app.get("/api/reports")
def reports(user: auth.SignedInUser, limit: Annotated[int, Query(ge=1, le=200)] = 50):
    return store.list_reports(user, min(limit, 200))


@app.get("/api/reports/{report_id}", response_model=Report)
def report(report_id: str, user: auth.Viewer):
    return _report_or_404(report_id, user)


@app.get("/api/reports/{report_id}/canonical", response_class=PlainTextResponse)
def canonical(report_id: str, user: auth.Viewer):
    """Exact bytes that are hashed (sha256) for the on-chain commitment."""
    return store.canonical_json(_report_or_404(report_id, user))


@app.get("/api/reports/{report_id}/verify", response_model=VerifyResponse)
def verify(report_id: str, user: auth.Viewer, hash: str | None = None):
    r = _report_or_404(report_id, user)
    recomputed = store.compute_hash(r)
    ok = recomputed == r.report_hash and (hash is None or hash.lower() == recomputed)
    return VerifyResponse(report_id=report_id, stored_hash=r.report_hash, recomputed_hash=recomputed,
                          provided_hash=hash, integrity_ok=ok)


@app.get("/api/stats")
def stats(user: auth.SignedInUser):
    """Dashboard aggregates for the signed-in user: risk distribution + indicators recurring across their risky reports."""
    return store.stats(user)


# ---------------------------------------------------------------- on-chain anchoring --------------------------------
@app.get("/api/chain/status")
def chain_status(request: Request):
    _rate_limit(_client_ip(request), "chain", CHAIN_RATE)
    return chain.status()


@app.get("/api/chain/lookup")
def chain_lookup(request: Request, domain: Annotated[str, Query(min_length=1, max_length=253)]):
    """On-chain reports for a domain, matched by keccak256 of the normalised domain."""
    _rate_limit(_client_ip(request), "chain", CHAIN_RATE)
    return _chain_call(chain.lookup, domain)


@app.post("/api/reports/{report_id}/anchor", response_model=AnchorInfo)
def anchor_report(report_id: str, request: Request, user: auth.SignedInUser):
    """Commit the report's hash to ThreatRegistry. Spends the server's gas, so it needs an account and is rate-limited
    like an analysis."""
    _rate_limit(_client_ip(request))
    r = _report_or_404(report_id, user)
    if store.compute_hash(r) != r.report_hash:
        raise HTTPException(409, "Report does not match its stored hash; refusing to anchor it")
    return _chain_call(chain.anchor, r)


@app.get("/api/reports/{report_id}/chain-verify", response_model=ChainVerifyResponse)
def chain_verify_report(report_id: str, request: Request, user: auth.Viewer):
    """Recompute the report's hash and compare it with the value committed on-chain."""
    _rate_limit(_client_ip(request), "chain", CHAIN_RATE)
    return _chain_call(chain.verify, _report_or_404(report_id, user))
