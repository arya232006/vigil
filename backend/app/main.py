"""ThreatScope API — AI + cybersecurity investigation engine.

Run: uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.concurrency import run_in_threadpool

from . import pipeline, store
from .checks import threatintel
from .ml import system1, system2
from .schemas import AnalyzeRequest, Report, VerifyResponse

app = FastAPI(title="ThreatScope API", version="1.0",
              description="Self-hosted AI + cybersecurity threat investigation. No third-party AI services.")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
                   allow_methods=["*"], allow_headers=["*"])

RATE = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))
_hits: dict[str, deque] = defaultdict(deque)


@app.on_event("startup")
def _startup():
    threading.Thread(target=threatintel.load, daemon=True).start()
    threading.Thread(target=lambda: (system1._url(), system1._msg()), daemon=True).start()


def _rate_limit(ip: str):
    q = _hits[ip]
    now = time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE:
        raise HTTPException(429, f"Rate limit: {RATE} analyses per minute")
    q.append(now)


@app.post("/api/analyze", response_model=Report)
async def analyze(req: AnalyzeRequest, request: Request, fresh: bool = False):
    # Track A: result cache (?fresh=true bypasses it) + X-Cache header; see _analyze_cached at the end of the file.
    return await _analyze_cached(req, request, fresh)


@app.get("/api/reports")
def reports(limit: int = 50):
    return store.list_reports(min(limit, 200))


@app.get("/api/reports/{report_id}", response_model=Report)
def report(report_id: str):
    r = store.get(report_id)
    if not r:
        raise HTTPException(404, "report not found")
    return r


@app.get("/api/reports/{report_id}/canonical", response_class=PlainTextResponse)
def canonical(report_id: str):
    """Exact bytes that are hashed (sha256) for the on-chain commitment."""
    r = store.get(report_id)
    if not r:
        raise HTTPException(404, "report not found")
    return store.canonical_json(r)


@app.get("/api/reports/{report_id}/verify", response_model=VerifyResponse)
def verify(report_id: str, hash: str | None = None):
    r = store.get(report_id)
    if not r:
        raise HTTPException(404, "report not found")
    recomputed = store.compute_hash(r)
    ok = recomputed == r.report_hash and (hash is None or hash.lower() == recomputed)
    return VerifyResponse(report_id=report_id, stored_hash=r.report_hash, recomputed_hash=recomputed,
                          provided_hash=hash, integrity_ok=ok)


@app.get("/api/stats")
def stats():
    """Dashboard aggregates: risk distribution + indicators recurring across risky reports (campaigns)."""
    return store.stats()


@app.get("/api/health")
def health():
    return {"status": "ok", "feeds": threatintel.feed_status(), "system2": system2.status()}


@app.get("/api/models")
def models():
    """Training/evaluation metrics of the self-hosted models."""
    return system1.metrics()


# --- Track A: jobs ---
# Async analysis jobs + the result cache shared with POST /api/analyze. Implementation: app/jobs.py.
from fastapi.responses import JSONResponse  # noqa: E402

from . import jobs  # noqa: E402
from .schemas import JobInfo, JobRequest  # noqa: E402


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _analyze_cached(req: AnalyzeRequest, request: Request, fresh: bool) -> JSONResponse:
    """Body of POST /api/analyze: answer from the result cache unless fresh, else analyse synchronously.
    Rate limiting only applies when a new analysis actually runs."""
    report = None if fresh else jobs.cached_report(req.input, req.type)
    cache = "HIT" if report is not None else "MISS"
    if report is None:
        _rate_limit(_client_ip(request))
        report = await run_in_threadpool(pipeline.analyze, req.input, req.type)
        jobs.remember(req.input, req.type, report)
    return JSONResponse(report.model_dump(mode="json"),
                        headers={"X-Cache": cache, "Access-Control-Expose-Headers": "X-Cache"})


@app.post("/api/jobs", response_model=JobInfo, status_code=202)
async def create_job(req: JobRequest, request: Request):
    """Queue an analysis and return at once; poll GET /api/jobs/{job_id}. A cached result comes back already
    `done` with `cached: true` and the report; an identical input already in progress returns that job."""
    return jobs.submit(req.input, req.type, fresh=req.fresh, on_new_work=lambda: _rate_limit(_client_ip(request)))


@app.get("/api/jobs/{job_id}", response_model=JobInfo)
async def get_job(job_id: str):
    """Job status; includes the full `report` once `status` is `done`. 404 for unknown or evicted ids."""
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job
