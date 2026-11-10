"""Async jobs + result cache (Track A). Fast and offline: `pipeline.analyze` is replaced by a fake, the AI layer
points at a dead port and reports go to a throwaway SQLite file.
Run from backend/: ../.venv/bin/python -m pytest ../tests/test_jobs.py -q"""
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

# Must happen before any app module is imported: store opens DB_PATH at import time.
_TMP = Path(tempfile.mkdtemp(prefix="vigil-test-jobs-"))
os.environ["DB_PATH"] = str(_TMP / "reports.db")
os.environ["S2_BASE_URL"] = "http://127.0.0.1:9/v1"
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app import jobs, main, pipeline, schemas, store
from fastapi.testclient import TestClient

# conftest.py sets an isolated temp DB before any app import; never touch the production database.
assert "vigil-tests-" in str(store.DB_PATH) or Path(store.DB_PATH) == _TMP / "reports.db", \
    "tests must not use the production reports database"

client = TestClient(main.app)   # no context manager: startup hooks (feed download, model warm-up) never run
FAKE_DELAY = 0.2


def _fake_report(text: str, typ: str) -> schemas.Report:
    level = schemas.RiskLevel.INCONCLUSIVE if "inconclusive" in text else schemas.RiskLevel.LOW
    rep = schemas.Report(report_id=uuid.uuid4().hex[:12], input_type=jobs.resolve_type(text, typ), input=text,
                         analyzed_at=pipeline.now(), risk_level=level, risk_score=5, confidence=0.9,
                         explanation=schemas.Explanation(summary="fake analysis", generated_by="template"))
    rep.report_hash = store.compute_hash(rep)
    store.save(rep, [])
    return rep


@pytest.fixture(autouse=True)
def calls(monkeypatch):
    """Replace the slow pipeline; returns the list of (text, type) it was called with."""
    seen = []

    def fake_analyze(text, typ="auto", owner_id=None):
        seen.append((text, typ))
        time.sleep(FAKE_DELAY)
        if "boom" in text:
            raise RuntimeError("simulated pipeline crash\nTraceback (most recent call last): internal detail")
        return _fake_report(text, typ)

    monkeypatch.setattr(pipeline, "analyze", fake_analyze)
    main._hits.clear()
    yield seen
    main._hits.clear()


def _url() -> str:
    return f"https://t-{uuid.uuid4().hex[:10]}.example/login"


def _submit(inp: str, **extra) -> dict:
    r = client.post("/api/jobs", json={"input": inp, **extra})
    assert r.status_code == 202, r.text
    return r.json()


def _wait(job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = client.get(f"/api/jobs/{job_id}")
        assert r.status_code == 200, r.text
        j = r.json()
        if j["status"] in ("done", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def _wait_mgr(m: jobs.JobManager, job_id: str, timeout: float = 5.0) -> schemas.JobInfo:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        j = m.get(job_id)
        if j.status in ("done", "failed"):
            return j
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_job_lifecycle_queued_to_done(calls):
    url = _url()
    j = _submit(url)
    assert j["status"] in ("queued", "running")
    assert j["cached"] is False and j["report"] is None and j["report_id"] is None
    assert j["input_type"] == "url" and len(j["job_id"]) == 12 and j["created_at"].endswith("+00:00")

    done = _wait(j["job_id"])
    assert done["status"] == "done" and done["error"] is None and done["cached"] is False
    assert done["report"]["report_id"] == done["report_id"] and done["report"]["input"] == url
    assert done["started_at"] >= done["created_at"] and done["finished_at"] >= done["started_at"]
    assert done["elapsed_ms"] >= FAKE_DELAY * 1000 * 0.9
    assert calls == [(url, "auto")]
    # the report is a normal stored report
    assert client.get(f"/api/reports/{done['report_id']}").json()["report_id"] == done["report_id"]


def test_job_waits_in_queue_when_workers_busy():
    m = jobs.JobManager(workers=1)
    try:
        a, b = m.submit(_url()), m.submit(_url())
        assert b.status == "queued" and b.started_at is None
        assert m.get(b.job_id).status == "queued"
        a, b = _wait_mgr(m, a.job_id), _wait_mgr(m, b.job_id)
        assert a.status == b.status == "done"
        assert b.started_at >= a.finished_at
    finally:
        m.shutdown()


def test_cache_hit_on_resubmit(calls):
    tag = uuid.uuid4().hex[:10]
    first = _wait(_submit(f"https://t-{tag}.example/login")["job_id"])

    again = _submit(f"  HTTPS://T-{tag}.EXAMPLE/login ")       # same URL after normalisation
    assert again["status"] == "done" and again["cached"] is True
    assert again["job_id"] != first["job_id"]
    assert again["report_id"] == first["report_id"] and again["report"]["report_id"] == first["report_id"]
    assert again["elapsed_ms"] < 100
    assert _wait(again["job_id"])["cached"] is True              # GET of a cached job works too
    assert len(calls) == 1

    msg = f"Dear customer {tag}, your KYC expires today.\nUpdate now"
    m1 = _wait(_submit(msg)["job_id"])
    m2 = _submit(f"  Dear customer {tag},   your KYC expires today. Update   now ")
    assert m1["input_type"] == "message" and m2["cached"] is True and m2["report_id"] == m1["report_id"]
    assert len(calls) == 2


def test_fresh_bypasses_cache(calls):
    url = _url()
    first = _wait(_submit(url)["job_id"])
    fresh = _submit(url, fresh=True)
    assert fresh["cached"] is False and fresh["status"] in ("queued", "running")
    fresh = _wait(fresh["job_id"])
    assert fresh["status"] == "done" and fresh["report_id"] != first["report_id"]
    assert len(calls) == 2
    # the fresh result replaces the cached one
    assert _submit(url)["report_id"] == fresh["report_id"]


def test_inflight_dedup(calls):
    url = _url()
    a = _submit(url)
    b = _submit(url)
    c = _submit(url, fresh=True)          # in-flight work is already fresh: joins the same job
    assert a["job_id"] == b["job_id"] == c["job_id"]
    assert _wait(a["job_id"])["status"] == "done"
    assert len(calls) == 1


def test_failure_path(calls):
    msg = f"boom {uuid.uuid4().hex}"
    j = _wait(_submit(msg)["job_id"])
    assert j["status"] == "failed" and j["report"] is None and j["report_id"] is None
    assert j["error"] == "RuntimeError: simulated pipeline crash"
    assert "Traceback" not in j["error"] and j["finished_at"]
    # failures are not cached: resubmitting runs again
    again = _submit(msg)
    assert again["cached"] is False and again["job_id"] != j["job_id"]
    assert _wait(again["job_id"])["status"] == "failed"
    assert len(calls) == 2


def test_inconclusive_not_cached(calls):
    url = f"{_url()}?inconclusive"
    _wait(_submit(url)["job_id"])
    assert _submit(url)["cached"] is False


def test_analyze_x_cache_header(calls):
    url = _url()
    r1 = client.post("/api/analyze", json={"input": url})
    assert r1.status_code == 200 and r1.headers["X-Cache"] == "MISS"
    assert "X-Cache" in r1.headers["Access-Control-Expose-Headers"]
    rep = schemas.Report.model_validate(r1.json())                     # unchanged contract: a full Report
    assert rep.input == url and rep.input_type == "url"

    r2 = client.post("/api/analyze", json={"input": url})
    assert r2.headers["X-Cache"] == "HIT" and r2.json()["report_id"] == rep.report_id

    r3 = client.post("/api/analyze?fresh=true", json={"input": url})
    assert r3.headers["X-Cache"] == "MISS" and r3.json()["report_id"] != rep.report_id
    assert len(calls) == 2

    # one cache for both APIs
    j = _submit(url)
    assert j["cached"] is True and j["report_id"] == r3.json()["report_id"]
    assert len(calls) == 2


def test_rate_limit_only_on_real_work(monkeypatch, calls):
    monkeypatch.setattr(main, "RATE", 1)
    url = _url()
    _wait(_submit(url)["job_id"])                                       # uses the only slot
    assert _submit(url)["cached"] is True                               # cache hit: no 429
    assert client.post("/api/analyze", json={"input": url}).headers["X-Cache"] == "HIT"
    assert client.post("/api/jobs", json={"input": _url()}).status_code == 429
    assert client.post("/api/analyze", json={"input": _url()}).status_code == 429
    assert len(calls) == 1


def test_unknown_job_404():
    r = client.get("/api/jobs/doesnotexist")
    assert r.status_code == 404 and r.json()["detail"] == "job not found"


def test_cache_ttl_expiry(monkeypatch, calls):
    monkeypatch.setattr(jobs.manager, "ttl_url", 0.3)
    url = _url()
    _wait(_submit(url)["job_id"])
    assert _submit(url)["cached"] is True
    time.sleep(0.35)
    assert _submit(url)["cached"] is False


def test_oldest_finished_jobs_evicted():
    m = jobs.JobManager(workers=1, max_jobs=3)
    try:
        url = _url()
        first = _wait_mgr(m, m.submit(url).job_id)
        hits = [m.submit(url) for _ in range(4)]                      # cache hits: done immediately
        assert all(h.cached for h in hits)
        assert m.get(first.job_id) is None and m.get(hits[0].job_id) is None
        assert [m.get(h.job_id).job_id for h in hits[1:]] == [h.job_id for h in hits[1:]]
    finally:
        m.shutdown()


def test_cache_key_normalisation():
    k = jobs.cache_key
    assert k("Example.COM", "auto") == k("  example.com ", "auto")
    assert k("hxxp://evil[.]com/login", "auto") == k("http://evil.com/login", "auto")
    assert k("example.com", "auto") != k("example.com", "domain")             # requested type is part of the key
    assert k("hello   there\nfriend", "auto") == k("hello there friend", "auto")
    assert k("hello there", "auto") != k("Hello there", "auto")
    assert k("ftp://X.Y/", "url") == "url|url|ftp://x.y/"                      # BlockedTarget fallback
