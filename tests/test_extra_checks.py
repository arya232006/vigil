"""Embedded redirect parameters, passive exposure detection, report retention (no network needed)."""
import datetime as dt

from app import store
from app.checks import domain, page
from app.checks.fetcher import FetchResult, Hop
from app.schemas import Explanation, Report, RiskLevel


def _titles(findings):
    return {f.title for f in findings}


def test_embedded_redirect_param_flagged():
    _, f = domain.analyze("203.0.113.7", "/login?next=https%3A%2F%2Fsecure-paypa1.top%2Fsignin")
    assert "Embedded redirect to another site" in _titles(f)


def test_same_site_redirect_param_not_flagged():
    _, f = domain.analyze("203.0.113.7", "/login?next=/dashboard")
    assert "Embedded redirect to another site" not in _titles(f)


def _page(html, url="https://example.org/files/"):
    return FetchResult(hops=[Hop(url=url, status=200, ip="203.0.113.7")], final_url=url, status=200,
                       headers={"content-type": "text/html"}, body=html.encode(), content_type="text/html",
                       truncated=False)


def test_directory_listing_and_sensitive_links():
    html = ("<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1>"
            "<a href='/.env'>.env</a><a href='db_backup.sql.gz'>dump</a></body></html>")
    _, f = page.analyze(_page(html), "example.org", "example.org")
    t = _titles(f)
    assert "Open directory listing" in t and "Page links to sensitive files" in t


def test_debug_page_detected():
    html = "<html><title>Error</title><body>Traceback (most recent call last):\n  File app.py</body></html>"
    _, f = page.analyze(_page(html, "https://example.org/"), "example.org", "example.org")
    assert "Debug or error details exposed" in _titles(f)


def test_normal_page_has_no_exposure_findings():
    html = "<html><title>Welcome</title><body><a href='/about'>About</a></body></html>"
    _, f = page.analyze(_page(html, "https://example.org/"), "example.org", "example.org")
    assert not {"Open directory listing", "Page links to sensitive files", "Debug or error details exposed"} & _titles(f)


def test_retention_purges_old_reports(monkeypatch):
    old = Report(report_id="oldreport001", input_type="message", input="old text",
                 analyzed_at=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)).isoformat(timespec="seconds"),
                 risk_level=RiskLevel.LOW, risk_score=0, confidence=1.0,
                 explanation=Explanation(summary="x", generated_by="template"))
    monkeypatch.setattr(store, "RETENTION_DAYS", 0)
    store.save(old, [("domain", "old.example")])
    assert store.get("oldreport001") is not None
    monkeypatch.setattr(store, "RETENTION_DAYS", 7)
    assert store.purge_expired() >= 1 and store.get("oldreport001") is None
