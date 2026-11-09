"""External threat-intel sources count as consulted only when they actually answer (no network needed)."""
import httpx
import pytest

from app.checks import threatintel

URL, HOST = "https://bad.example/login", "bad.example"
URLHAUS_KEY, GSB_KEY = "urlhaus-secret", "gsb-secret"
LOCAL = "OpenPhish feed (local copy)"


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", URLHAUS_KEY)
    monkeypatch.setenv("GSB_API_KEY", GSB_KEY)


def _respond(monkeypatch, urlhaus, gsb):
    """urlhaus/gsb are (status, json) tuples, or an exception to raise."""
    def post(url, **_):
        answer = urlhaus if "urlhaus" in url else gsb
        if isinstance(answer, Exception):
            raise answer
        status, body = answer
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(threatintel.httpx, "post", post)


def test_sources_listed_when_both_answer(keys, monkeypatch):
    _respond(monkeypatch, (200, {"query_status": "no_results"}), (200, {}))
    findings, sources, unavailable = threatintel.lookup(URL, HOST)
    assert not findings and not unavailable
    assert sources == [LOCAL, "URLhaus API", "Google Safe Browsing"]


def test_matches_still_produce_findings(keys, monkeypatch):
    _respond(monkeypatch, (200, {"query_status": "ok", "url_status": "online", "threat": "malware_download"}),
             (200, {"matches": [{"threatType": "MALWARE"}]}))
    findings, _, unavailable = threatintel.lookup(URL, HOST)
    assert {f.source for f in findings} == {"URLhaus malware URL database", "Google Safe Browsing"}
    assert not unavailable


def test_rejected_keys_are_reported_not_counted(keys, monkeypatch):
    _respond(monkeypatch, (401, {"query_status": "unknown_auth_key"}), (400, {"error": {"message": "API key not valid"}}))
    findings, sources, unavailable = threatintel.lookup(URL, HOST)
    assert not findings and sources == [LOCAL]
    assert unavailable == ["URLhaus API (HTTP 401)", "Google Safe Browsing (HTTP 400)"]


def test_timeout_is_reported_not_counted(keys, monkeypatch):
    _respond(monkeypatch, httpx.ReadTimeout("slow"), httpx.ConnectError("no route"))
    _, sources, unavailable = threatintel.lookup(URL, HOST)
    assert sources == [LOCAL]
    assert unavailable == ["URLhaus API (timed out)", "Google Safe Browsing (request failed)"]


def test_urlhaus_unfinished_lookup_is_not_counted(keys, monkeypatch):
    _respond(monkeypatch, (200, {"query_status": "invalid_url"}), (200, {}))
    _, sources, unavailable = threatintel.lookup(URL, HOST)
    assert sources == [LOCAL, "Google Safe Browsing"]
    assert unavailable == ["URLhaus API (unexpected response)"]


def test_failure_text_never_contains_the_key(keys, monkeypatch):
    _respond(monkeypatch, (403, {}), httpx.ConnectError(f"cannot reach https://x/?key={GSB_KEY}"))
    _, sources, unavailable = threatintel.lookup(URL, HOST)
    assert URLHAUS_KEY not in str(sources + unavailable) and GSB_KEY not in str(sources + unavailable)


def test_unconfigured_sources_are_not_mentioned(monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    monkeypatch.delenv("GSB_API_KEY", raising=False)
    assert threatintel.lookup(URL, HOST)[1:] == ([LOCAL], [])
