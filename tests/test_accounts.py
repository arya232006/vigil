"""Accounts: Clerk token verification and per-user report access (no network: signing keys are local)."""
import base64
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import auth, jobs, main, pipeline, store
from app.schemas import Explanation, Report, RiskLevel

HOST = "clerk.vigil.test"
ISSUER = f"https://{HOST}"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client = TestClient(main.app)


@pytest.fixture(autouse=True)
def clerk(monkeypatch):
    encoded = base64.b64encode(f"{HOST}$".encode()).decode().rstrip("=")
    monkeypatch.setenv("CLERK_PUBLISHABLE_KEY", f"pk_test_{encoded}")
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.setattr(auth, "_signing_key", lambda token, issuer: KEY.public_key())
    main._hits.clear()


def _token(sub="user_a", key=KEY, issuer=ISSUER, exp_in=60, **extra):
    now = int(time.time())
    return jwt.encode({"sub": sub, "iss": issuer, "iat": now - 1, "exp": now + exp_in, **extra}, key, algorithm="RS256")


def _as(user):
    return {"Authorization": f"Bearer {_token(user)}"}


def _report(owner, indicators=(), level=RiskLevel.HIGH):
    r = Report(report_id=uuid.uuid4().hex[:12], input_type="domain", input=f"{uuid.uuid4().hex[:6]}.example",
               analyzed_at=pipeline.now(), risk_level=level, risk_score=80, confidence=0.9,
               explanation=Explanation(summary="s", generated_by="template"))
    r.report_hash = store.compute_hash(r)
    store.save(r, list(indicators), owner)
    return r


def _user():
    return f"user_{uuid.uuid4().hex[:8]}"


@pytest.mark.parametrize("token", [
    lambda: _token(exp_in=-60),
    lambda: _token(key=OTHER_KEY),
    lambda: _token(issuer="https://evil.test"),
    lambda: "not-a-token",
])
def test_bad_tokens_are_rejected_not_treated_as_guests(token):
    r = client.post("/api/jobs", json={"input": "https://x.example/"}, headers={"Authorization": f"Bearer {token()}"})
    assert r.status_code == 401


def test_non_bearer_header_is_rejected():
    assert client.get("/api/stats", headers={"Authorization": "Basic abc"}).status_code == 401


def test_unsigned_token_is_rejected():
    now = int(time.time())
    forged = jwt.encode({"sub": "user_a", "iss": ISSUER, "iat": now, "exp": now + 60}, "", algorithm="none")
    assert client.get("/api/stats", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_wrong_authorized_party_is_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://vigil.test")
    bad = {"Authorization": f"Bearer {_token(azp='https://evil.test')}"}
    good = {"Authorization": f"Bearer {_token(azp='https://vigil.test')}"}
    assert client.get("/api/stats", headers=bad).status_code == 401
    assert client.get("/api/stats", headers=good).status_code == 200


def test_token_without_server_config_fails_closed(monkeypatch):
    monkeypatch.delenv("CLERK_PUBLISHABLE_KEY")
    assert client.post("/api/jobs", json={"input": "https://x.example/"}, headers=_as("user_a")).status_code == 503


@pytest.mark.parametrize("path", ["/api/reports", "/api/stats"])
def test_personal_endpoints_need_sign_in(path):
    assert client.get(path).status_code == 401


def test_history_contains_only_own_reports():
    a, b = _user(), _user()
    mine, theirs = _report(a), _report(b)
    _report(None)
    ids = [r["report_id"] for r in client.get("/api/reports", headers=_as(a)).json()]
    assert ids == [mine.report_id] and theirs.report_id not in ids


def test_stats_count_only_own_reports():
    a, b = _user(), _user()
    domain = ("domain", f"{uuid.uuid4().hex[:8]}.example")
    _report(a, [domain]), _report(a, [domain]), _report(b, [domain])
    stats = client.get("/api/stats", headers=_as(a)).json()
    assert stats["total_reports"] == 2
    assert stats["recurring_indicators"]["domain"] == [{"value": domain[1], "reports": 2}]


@pytest.mark.parametrize("suffix", ["", "/canonical", "/verify"])
def test_owned_report_opens_only_for_owner(suffix):
    a, b = _user(), _user()
    r = _report(a)
    url = f"/api/reports/{r.report_id}{suffix}"
    assert client.get(url, headers=_as(a)).status_code == 200
    assert client.get(url, headers=_as(b)).status_code == 404
    assert client.get(url).status_code == 404


def test_guest_report_opens_with_the_link():
    r = _report(None)
    assert client.get(f"/api/reports/{r.report_id}").status_code == 200
    assert client.get(f"/api/reports/{r.report_id}", headers=_as(_user())).status_code == 200


def test_owner_is_not_part_of_the_report_or_its_hash():
    owner = _user()
    r = _report(owner)
    assert owner not in client.get(f"/api/reports/{r.report_id}/canonical", headers=_as(owner)).text
    assert store.compute_hash(store.get(r.report_id)) == r.report_hash


def test_guests_cannot_anchor():
    assert client.post(f"/api/reports/{_report(None).report_id}/anchor").status_code == 401


def test_anchoring_another_users_report_is_refused():
    r = _report(_user())
    assert client.post(f"/api/reports/{r.report_id}/anchor", headers=_as(_user())).status_code == 404


def test_correlation_hides_other_users_report_ids():
    a, b = _user(), _user()
    shared = ("ip", uuid.uuid4().hex)
    own, other, guest = _report(a, [shared]), _report(b, [shared]), _report(None, [shared])
    links = pipeline._correlate("new", [shared], owner_id=a)
    ids = {c.report_id for c in links}
    assert len(links) == 3 and {own.report_id, guest.report_id, ""} == ids and other.report_id not in ids
    assert all(c.shared == [f"ip:{shared[1]}"] for c in links)


def test_guest_correlation_hides_owned_reports():
    shared = ("ip", uuid.uuid4().hex)
    _report(_user(), [shared])
    assert [c.report_id for c in pipeline._correlate("new", [shared])] == [""]


@pytest.fixture
def analyses(monkeypatch):
    calls = []

    def fake(text, typ="auto", owner_id=None):
        calls.append(owner_id)
        r = Report(report_id=uuid.uuid4().hex[:12], input_type="url", input=text, analyzed_at=pipeline.now(),
                   risk_level=RiskLevel.LOW, risk_score=5, confidence=0.9,
                   explanation=Explanation(summary="s", generated_by="template"))
        r.report_hash = store.compute_hash(r)
        store.save(r, [], owner_id)
        return r
    monkeypatch.setattr(pipeline, "analyze", fake)
    return calls


def _wait(job_id, headers):
    for _ in range(100):
        job = client.get(f"/api/jobs/{job_id}", headers=headers).json()
        if job.get("status") in ("done", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_each_user_gets_their_own_saved_copy(analyses):
    a, b, url = _user(), _user(), f"https://{uuid.uuid4().hex[:8]}.example/"
    job_a = client.post("/api/jobs", json={"input": url}, headers=_as(a)).json()
    report_a = _wait(job_a["job_id"], _as(a))["report_id"]
    job_b = client.post("/api/jobs", json={"input": url}, headers=_as(b)).json()
    report_b = _wait(job_b["job_id"], _as(b))["report_id"]
    assert report_a != report_b and set(analyses) == {a, b}
    assert [r["report_id"] for r in client.get("/api/reports", headers=_as(b)).json()] == [report_b]


def test_repeat_scan_by_same_user_uses_the_cache(analyses):
    a, url = _user(), f"https://{uuid.uuid4().hex[:8]}.example/"
    first = client.post("/api/jobs", json={"input": url}, headers=_as(a)).json()
    _wait(first["job_id"], _as(a))
    again = client.post("/api/jobs", json={"input": url}, headers=_as(a)).json()
    assert again["cached"] is True and analyses == [a]


def test_job_of_another_user_is_not_found(analyses):
    a, b = _user(), _user()
    job = client.post("/api/jobs", json={"input": f"https://{uuid.uuid4().hex[:8]}.example/"}, headers=_as(a)).json()
    _wait(job["job_id"], _as(a))
    assert client.get(f"/api/jobs/{job['job_id']}", headers=_as(b)).status_code == 404
    assert client.get(f"/api/jobs/{job['job_id']}").status_code == 404
    assert jobs.get(job["job_id"]) is None


def test_guest_scan_is_saved_without_an_owner(analyses):
    job = client.post("/api/jobs", json={"input": f"https://{uuid.uuid4().hex[:8]}.example/"}).json()
    assert _wait(job["job_id"], {})["report_id"] and analyses == [None]
