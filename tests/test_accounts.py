"""Accounts: password sign-in, sessions, and per-user report access."""
import hashlib
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from app import auth, jobs, main, pipeline, store
from app.schemas import Explanation, Report, RiskLevel
from fastapi.testclient import TestClient

ORIGIN = "http://localhost:3000"
PASSWORD = "correct horse battery"
client = TestClient(main.app)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.delenv("FRONTEND_URL", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)
    main._hits.clear()


def _session(user):
    token = uuid.uuid4().hex
    now = int(time.time())
    store.create_session(hashlib.sha256(token.encode()).hexdigest(), user, now, now + 60)
    return token


def _as(user):
    return {"Cookie": f"{auth.COOKIE}={_session(user)}", "Origin": ORIGIN}


def _report(owner, indicators=(), level=RiskLevel.HIGH):
    r = Report(report_id=uuid.uuid4().hex[:12], input_type="domain", input=f"{uuid.uuid4().hex[:6]}.example",
               analyzed_at=pipeline.now(), risk_level=level, risk_score=80, confidence=0.9,
               explanation=Explanation(summary="s", generated_by="template"))
    r.report_hash = store.compute_hash(r)
    store.save(r, list(indicators), owner)
    return r


def _user():
    return store.create_user(f"{uuid.uuid4().hex}@example.com", "unused", 0)


def _email():
    return f"{uuid.uuid4().hex[:10]}@example.com"


def _browser():
    """Its own cookie jar, so sign-ins here can't leak into other tests."""
    return TestClient(main.app, headers={"Origin": ORIGIN})


def _signup(browser, email, password=PASSWORD):
    return browser.post("/api/auth/signup", json={"email": email, "password": password})


def test_sign_up_starts_a_session_with_a_protected_cookie():
    browser, email = _browser(), _email()
    r = _signup(browser, email)
    assert r.status_code == 201 and r.json()["user"]["email"] == email
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert browser.get("/api/auth/me").json()["user"]["email"] == email
    assert browser.get("/api/stats").status_code == 200


def test_password_and_token_are_never_stored_in_the_clear():
    browser, email = _browser(), _email()
    _signup(browser, email)
    stored = store.find_user(email)[1]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored
    token = browser.cookies[auth.COOKIE]
    assert not store._db.query("SELECT 1 FROM sessions WHERE token_hash=?", (token,))


def test_email_is_case_insensitive_and_unique():
    email = _email()
    assert _signup(_browser(), email).status_code == 201
    assert _signup(_browser(), email.upper()).status_code == 409
    login = _browser().post("/api/auth/login", json={"identifier": email.upper(), "password": PASSWORD})
    assert login.status_code == 200


@pytest.mark.parametrize("email,password", [("not-an-email", PASSWORD), ("a@b", PASSWORD), ("x@example.com", "short"),
                                            ("x@example.com", "x" * 129)])
def test_bad_sign_up_details_are_refused(email, password):
    assert _signup(_browser(), email, password).status_code == 400


def test_wrong_password_and_unknown_email_look_the_same():
    email = _email()
    _signup(_browser(), email)
    wrong = _browser().post("/api/auth/login", json={"identifier": email, "password": "wrong password here"})
    unknown = _browser().post("/api/auth/login", json={"identifier": _email(), "password": PASSWORD})
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json()
    assert "set-cookie" not in wrong.headers


def test_sign_out_ends_the_session_on_the_server():
    browser = _browser()
    _signup(browser, _email())
    token = browser.cookies[auth.COOKIE]
    assert browser.post("/api/auth/logout").status_code == 200
    replay = {"Cookie": f"{auth.COOKIE}={token}"}
    assert client.get("/api/stats", headers=replay).status_code == 401


def test_expired_session_is_rejected():
    user, token = _user(), uuid.uuid4().hex
    store.create_session(hashlib.sha256(token.encode()).hexdigest(), user, 1, int(time.time()) - 1)
    assert client.get("/api/stats", headers={"Cookie": f"{auth.COOKIE}={token}"}).status_code == 401


def test_bad_cookie_is_rejected_and_cleared_not_treated_as_a_guest():
    r = client.post("/api/jobs", json={"input": "https://x.example/"},
                    headers={"Cookie": f"{auth.COOKIE}=forged", "Origin": ORIGIN})
    assert r.status_code == 401 and auth.COOKIE in r.headers["set-cookie"]


def test_session_check_clears_a_stale_cookie_without_an_error():
    r = client.get("/api/auth/me", headers={"Cookie": f"{auth.COOKIE}=stale"})
    assert r.status_code == 200 and r.json()["user"] is None and auth.COOKIE in r.headers["set-cookie"]


def test_guest_session_check_is_empty():
    assert TestClient(main.app).get("/api/auth/me").json() == {"user": None, "google": False}


@pytest.mark.parametrize("origin", ["https://evil.test", None])
def test_cookie_post_from_another_site_is_refused(origin):
    headers = _as(_user())
    headers.pop("Origin")
    if origin:
        headers["Origin"] = origin
    assert client.post("/api/jobs", json={"input": "https://x.example/"}, headers=headers).status_code == 403


@pytest.mark.parametrize("path", ["signup", "login", "logout"])
def test_account_actions_need_an_allowed_origin(path):
    r = TestClient(main.app, headers={"Origin": "https://evil.test"}).post(
        f"/api/auth/{path}", json={"identifier": _email(), "email": _email(), "password": PASSWORD})
    assert r.status_code == 403


def test_wildcard_origin_is_never_allowed(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "*")
    assert auth.allowed_origins() == []


def test_https_site_gets_a_secure_cookie(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://vigil.test")
    r = TestClient(main.app, headers={"Origin": "https://vigil.test"}).post(
        "/api/auth/signup", json={"email": _email(), "password": PASSWORD})
    assert r.status_code == 201 and "secure" in r.headers["set-cookie"].lower()


def test_password_guessing_is_rate_limited():
    browser, email = _browser(), _email()
    codes = [browser.post("/api/auth/login", json={"identifier": email, "password": "wrong password"}).status_code
             for _ in range(main.AUTH_RATE + 1)]
    assert codes[:-1] == [401] * main.AUTH_RATE and codes[-1] == 429


def _username():
    return f"user-{uuid.uuid4().hex[:12]}"


def test_username_account_signs_in_with_its_username():
    browser, name = _browser(), _username()
    r = browser.post("/api/auth/signup", json={"username": name.upper(), "password": PASSWORD})
    assert r.status_code == 201 and r.json()["user"] == {"id": r.json()["user"]["id"], "email": None, "username": name}
    assert browser.get("/api/auth/me").json()["user"]["username"] == name
    login = _browser().post("/api/auth/login", json={"identifier": f" {name.upper()} ", "password": PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["username"] == name


def test_username_is_unique_ignoring_case():
    name = _username()
    assert _browser().post("/api/auth/signup", json={"username": name, "password": PASSWORD}).status_code == 201
    taken = _browser().post("/api/auth/signup", json={"username": name.upper(), "password": PASSWORD})
    assert taken.status_code == 409 and "username" in taken.json()["detail"]


def test_many_username_accounts_can_have_no_email():
    for _ in range(2):
        assert _browser().post("/api/auth/signup", json={"username": _username(), "password": PASSWORD}).status_code == 201


@pytest.mark.parametrize("body", [{}, {"email": "a@example.com", "username": "valid-name"}])
def test_sign_up_needs_exactly_one_of_email_or_username(body):
    assert _browser().post("/api/auth/signup", json={**body, "password": PASSWORD}).status_code == 400


@pytest.mark.parametrize("name", ["ab", "x" * 31, "has space", "has@sign", "-edge", "edge_", "semi;colon"])
def test_bad_usernames_are_refused(name):
    assert _browser().post("/api/auth/signup", json={"username": name, "password": PASSWORD}).status_code == 400


def test_wrong_password_for_username_looks_like_unknown_account():
    name = _username()
    _browser().post("/api/auth/signup", json={"username": name, "password": PASSWORD})
    wrong = _browser().post("/api/auth/login", json={"identifier": name, "password": "wrong password here"})
    unknown = _browser().post("/api/auth/login", json={"identifier": _username(), "password": PASSWORD})
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json()


def test_generated_username_is_valid_and_can_be_used():
    browser = _browser()
    name = browser.get("/api/auth/username").json()["username"]
    assert auth.USERNAME.fullmatch(name)
    assert browser.post("/api/auth/signup", json={"username": name, "password": PASSWORD}).status_code == 201


def test_generator_skips_taken_names(monkeypatch):
    seen = iter([True, True, False])
    monkeypatch.setattr(store, "username_taken", lambda name: next(seen))
    assert auth.USERNAME.fullmatch(auth.generate_username())


def test_generator_gives_up_cleanly_when_everything_is_taken(monkeypatch):
    monkeypatch.setattr(store, "username_taken", lambda name: True)
    assert client.get("/api/auth/username").status_code == 503


def test_username_generation_is_rate_limited():
    codes = [client.get("/api/auth/username").status_code for _ in range(main.AUTH_RATE * 3 + 1)]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}


def test_old_user_table_migrates_and_keeps_its_accounts(tmp_path):
    db = store._SqliteDb(tmp_path / "old.db")
    db.query("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, "
             "created_at BIGINT NOT NULL, google_sub TEXT UNIQUE)")
    db.query("INSERT INTO users VALUES ('usr_1', 'old@example.com', 'hash', 5, 'sub')")
    store._migrate_users(db)
    store._migrate_users(db)                                # safe to run on every start
    assert db.query("SELECT id, email, username, password_hash, created_at, google_sub FROM users") == [
        ("usr_1", "old@example.com", None, "hash", 5, "sub")]
    db.query("INSERT INTO users (id, username, password_hash, created_at) VALUES ('usr_2', 'new-name', 'h', 6)")
    assert len(db.query("SELECT 1 FROM users")) == 2


class _GoogleReply:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


@pytest.fixture
def google(monkeypatch):
    """Google's two server-side replies, replaced so no test touches the network."""
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "client-secret")
    identity = {}
    sent = {}

    class FakeClient:
        def __init__(self, **_):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def post(self, url, data):
            sent.update(data)
            return _GoogleReply({"access_token": "access"})

        def get(self, url, headers):
            return _GoogleReply(identity)
    monkeypatch.setattr(auth.httpx, "Client", FakeClient)
    return identity, sent


def _google_login(browser, next_path="/history"):
    start = browser.get("/api/auth/google/start", params={"next": next_path}, follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return browser.get("/api/auth/google/callback", params={"state": state, "code": "abc"}, follow_redirects=False)


def test_google_start_uses_pkce_and_only_asks_for_email(google):
    r = _browser().get("/api/auth/google/start", follow_redirects=False)
    query = parse_qs(urlparse(r.headers["location"]).query)
    assert r.status_code == 303 and r.headers["location"].startswith(auth.GOOGLE_AUTH)
    assert query["scope"] == ["openid email"] and query["code_challenge_method"] == ["S256"] and query["state"]
    assert "client-secret" not in r.headers["location"]


def test_google_sign_in_creates_a_session_and_returns_to_the_page(google):
    identity, sent = google
    email = _email()
    identity.update(sub=uuid.uuid4().hex, email=email.upper(), email_verified=True)
    browser = _browser()
    r = _google_login(browser)
    assert r.status_code == 303 and r.headers["location"] == f"{ORIGIN}/history" and sent["code_verifier"]
    assert browser.get("/api/auth/me").json()["user"]["email"] == email


def test_repeat_google_sign_in_is_the_same_account(google):
    identity, _ = google
    identity.update(sub=uuid.uuid4().hex, email=_email(), email_verified=True)
    a, b = _browser(), _browser()
    _google_login(a), _google_login(b)
    assert a.get("/api/auth/me").json()["user"]["id"] == b.get("/api/auth/me").json()["user"]["id"]


def test_google_link_locks_out_whoever_registered_the_email_first(google):
    identity, _ = google
    email = _email()
    squatter = _browser()
    _signup(squatter, email)
    identity.update(sub=uuid.uuid4().hex, email=email, email_verified=True)
    _google_login(_browser())
    assert squatter.get("/api/stats").status_code == 401
    assert _browser().post("/api/auth/login", json={"identifier": email, "password": PASSWORD}).status_code == 401


def test_unverified_google_email_is_refused(google):
    identity, _ = google
    identity.update(sub=uuid.uuid4().hex, email=_email(), email_verified=False)
    r = _google_login(_browser())
    assert r.headers["location"].endswith("/sign-in?error=google") and auth.COOKIE not in r.cookies


def test_google_callback_with_wrong_state_is_refused(google):
    browser = _browser()
    browser.get("/api/auth/google/start", follow_redirects=False)
    r = browser.get("/api/auth/google/callback", params={"state": "forged", "code": "abc"}, follow_redirects=False)
    assert r.headers["location"].endswith("/sign-in?error=google")


def test_google_callback_without_the_cookie_is_refused(google):
    r = _browser().get("/api/auth/google/callback", params={"state": "x", "code": "abc"}, follow_redirects=False)
    assert r.headers["location"].endswith("/sign-in?error=google")


@pytest.mark.parametrize("target", ["https://evil.test/", "//evil.test", "/\\\\evil.test"])
def test_google_never_redirects_off_site(google, target):
    identity, _ = google
    identity.update(sub=uuid.uuid4().hex, email=_email(), email_verified=True)
    assert _google_login(_browser(), target).headers["location"] == f"{ORIGIN}/investigate"


def test_google_is_off_without_configuration():
    assert _browser().get("/api/auth/google/start", follow_redirects=False).status_code == 404


def test_password_cannot_open_a_google_only_account(google):
    identity, _ = google
    email = _email()
    identity.update(sub=uuid.uuid4().hex, email=email, email_verified=True)
    _google_login(_browser())
    assert _browser().post("/api/auth/login", json={"identifier": email, "password": ""}).status_code == 401


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
