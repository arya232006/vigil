"""Shared state across API instances: rate limits and jobs in a real, throwaway Redis server.

Skipped when the redis package or the redis-server binary isn't installed.
"""
import shutil
import socket
import subprocess
import threading
import time
import uuid

import pytest

redis = pytest.importorskip("redis")
SERVER = shutil.which("redis-server")
pytestmark = pytest.mark.skipif(SERVER is None, reason="redis-server is not installed")

from app import jobs, main, pipeline, schemas, shared, store
from fastapi.testclient import TestClient


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    proc = subprocess.Popen([SERVER, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    r = redis.Redis(port=port, decode_responses=True)
    for _ in range(50):
        try:
            r.ping()
            break
        except redis.ConnectionError:
            time.sleep(0.1)
    yield r
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def r(server):
    server.flushall()
    return server


def _dead_redis():
    return redis.Redis(port=_free_port(), socket_connect_timeout=0.2, socket_timeout=0.2, decode_responses=True)


@pytest.fixture
def analyses(monkeypatch):
    """A fake pipeline that waits for `release`, so tests can submit while an analysis is still running."""
    calls, release = [], threading.Event()

    def fake(text, typ="auto", owner_id=None):
        calls.append(text)
        release.wait(5)
        if "boom" in text:
            raise RuntimeError("simulated crash")
        rep = schemas.Report(report_id=uuid.uuid4().hex[:12], input_type=jobs.resolve_type(text, typ), input=text,
                             analyzed_at=pipeline.now(), risk_level=schemas.RiskLevel.LOW, risk_score=5,
                             confidence=0.9, explanation=schemas.Explanation(summary="s", generated_by="template"))
        rep.report_hash = store.compute_hash(rep)
        store.save(rep, [], owner_id)
        return rep
    monkeypatch.setattr(pipeline, "analyze", fake)
    return calls, release


def _url():
    return f"https://{uuid.uuid4().hex[:10]}.example/"


def _wait(manager, job_id, viewer=None):
    for _ in range(200):
        info = manager.get(job_id, viewer)
        if info and info.status in ("done", "failed"):
            return info
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_rate_limit_is_shared_between_instances(r):
    results = [shared.allow("test", "1.2.3.4", 3, redis_client=r) for _ in range(4)]
    assert results == [True, True, True, False]
    assert shared.allow("test", "5.6.7.8", 3, redis_client=r) is True       # other clients are unaffected


def test_rate_limit_keys_hold_no_raw_identifiers(r):
    shared.allow("auth-email", "person@example.com", 5, redis_client=r)
    assert all("person" not in k for k in r.keys("*"))


def test_rate_limit_falls_back_when_redis_is_down():
    assert shared.allow("test", "1.2.3.4", 3, redis_client=_dead_redis()) is None


def test_api_rate_limit_holds_when_requests_land_on_different_instances(r, monkeypatch):
    monkeypatch.setattr(shared, "client", lambda: r)
    codes = []
    for _ in range(main.AUTH_RATE * 3 + 1):
        main._hits.clear()                                  # forget the per-process count, as a fresh instance would
        codes.append(TestClient(main.app).get("/api/auth/username").status_code)
    assert set(codes[:-1]) == {200} and codes[-1] == 429


def test_job_started_on_one_instance_is_visible_on_another(r, analyses):
    calls, release = analyses
    a, b = jobs.RedisJobManager(r), jobs.RedisJobManager(r)
    job = a.submit(_url())
    assert b.get(job.job_id).status in ("queued", "running")
    release.set()
    done = _wait(b, job.job_id)
    assert done.status == "done" and done.report is not None and len(calls) == 1


def test_same_input_on_two_instances_runs_once(r, analyses):
    calls, release = analyses
    a, b = jobs.RedisJobManager(r), jobs.RedisJobManager(r)
    url = _url()
    first, second = a.submit(url), b.submit(url)
    assert first.job_id == second.job_id
    release.set()
    _wait(a, first.job_id)
    assert calls == [url]


def test_result_cache_is_shared(r, analyses):
    calls, release = analyses
    release.set()
    a, b = jobs.RedisJobManager(r), jobs.RedisJobManager(r)
    url = _url()
    _wait(a, a.submit(url).job_id)
    again = b.submit(url)
    assert again.cached is True and again.status == "done" and calls == [url]


def test_rate_limit_is_charged_only_for_new_work(r, analyses):
    _, release = analyses
    release.set()
    charged = []
    a = jobs.RedisJobManager(r)
    url = _url()
    _wait(a, a.submit(url, on_new_work=lambda: charged.append(1)).job_id)
    a.submit(url, on_new_work=lambda: charged.append(1))
    assert charged == [1]


def test_another_users_job_is_hidden_on_every_instance(r, analyses):
    _, release = analyses
    release.set()
    a, b = jobs.RedisJobManager(r), jobs.RedisJobManager(r)
    job = a.submit(_url(), owner_id="usr_a")
    _wait(a, job.job_id, "usr_a")
    assert b.get(job.job_id, "usr_b") is None and b.get(job.job_id) is None
    assert b.get(job.job_id, "usr_a").status == "done"


def test_failed_job_reports_a_short_error_and_frees_the_input(r, analyses):
    calls, release = analyses
    release.set()
    a = jobs.RedisJobManager(r)
    url = f"https://boom-{uuid.uuid4().hex[:6]}.example/"
    failed = _wait(a, a.submit(url).job_id)
    assert failed.status == "failed" and failed.error == "RuntimeError: simulated crash"
    assert not r.keys(shared.key("inflight", "*"))
    _wait(a, a.submit(url).job_id)
    assert calls == [url, url]


def test_unreachable_redis_returns_503(monkeypatch):
    monkeypatch.setattr(jobs, "manager", jobs.RedisJobManager(_dead_redis()))
    r = TestClient(main.app).post("/api/jobs", json={"input": _url()})
    assert r.status_code == 503 and "unavailable" in r.json()["detail"]
