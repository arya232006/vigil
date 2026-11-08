"""Email (.eml) analysis tests: individual checks + end-to-end on fixtures (no network, no AI).
Run from backend/: python -m pytest ../tests/test_email.py -q"""
import os
import sys
import tempfile
import uuid
from pathlib import Path

# Must be set BEFORE importing app modules: temp report DB, dead-port AI endpoints.
os.environ.setdefault("DB_PATH", str(Path(tempfile.mkdtemp()) / "test_email.db"))
os.environ["S2_BASE_URL"] = "http://127.0.0.1:9/v1"
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest  # noqa: E402

from app import email_pipeline, pipeline  # noqa: E402
from app.checks import email_auth as ea  # noqa: E402
from app.checks.message import HARMFUL, detect_tactics, extract_indicators  # noqa: E402
from app.schemas import Explanation, Finding, Report, RiskLevel, Severity  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def eml(name: str) -> str:
    return (FIX / name).read_text()


@pytest.fixture
def fake_body(monkeypatch):
    """Fast stand-in for pipeline.analyze_message: rule engine only, saved like a real report."""
    seen = []

    def fake(text):
        seen.append(text)
        t = detect_tactics(text)
        harm = bool(set(t) & HARMFUL)
        fs = [Finding(id="", module="message", title=k, severity=Severity.HIGH if k in HARMFUL else Severity.LOW,
                      description=v, evidence={"tactic": k, "quote": v}, source="rule engine") for k, v in t.items()]
        r = Report(report_id=uuid.uuid4().hex[:12], input_type="message", input=text, analyzed_at=pipeline.now(),
                   risk_level=RiskLevel.SUSPICIOUS if harm else RiskLevel.LOW, risk_score=40 if harm else 5,
                   confidence=0.8, findings=fs, indicators=extract_indicators(text),
                   explanation=Explanation(summary="fake", generated_by="template"))
        return pipeline._finalize(r, [])

    monkeypatch.setattr(pipeline, "analyze_message", fake)
    return seen


def titles(findings):
    return " | ".join(f.title for f in findings)


# ---------------------------------------------------------------- end-to-end ---------------------------------
def test_legit_newsletter_not_high(fake_body):
    r = email_pipeline.analyze_email(eml("newsletter_legit.eml"), live_dns=False)
    assert r.input_type == "email" and r.risk_level == RiskLevel.LOW
    assert r.email.auth.dmarc == "pass" and r.email.auth.dkim_aligned and r.email.auth.spf_aligned
    assert "DKIM body hash verified locally" in titles(r.findings)
    assert not [f for f in r.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert r.email.dmarc_policy == "not_checked"
    assert r.linked_reports and r.email.body_report_id == r.linked_reports[0]


def test_bank_phishing_high_risk(fake_body):
    raw = eml("phishing_bank.eml")
    r = email_pipeline.analyze_email(raw, live_dns=False)
    assert r.risk_level == RiskLevel.HIGH and r.risk_score >= 60
    t = titles(r.findings)
    for expected in ("DMARC authentication failed", "Display name impersonates 'hdfc'", "Look-alike sender domain",
                     "Replies are diverted to a free webmail account", "Link text shows a different destination",
                     "Dangerous attachment: statement.pdf.html"):
        assert expected in t, expected
    # the forged lower Authentication-Results header (dmarc=pass for hdfcbank.com) must be ignored
    assert r.email.auth.dmarc == "fail" and r.email.auth.authserv_id == "mx.recipient-mail.example"
    mm = r.email.link_mismatches[0]
    assert mm.text_domain == "netbanking.hdfcbank.com" and mm.href_domain == "hdfc-bank-secure-login.top"
    att = r.email.attachments[0]
    assert att.risky and att.detected_type == "html" and any("double extension" in x for x in att.reasons)
    # body analysed with the REAL link destination; privacy: raw email not stored in input
    assert "hdfc-bank-secure-login.top" in fake_body[-1] and "otp" in fake_body[-1].lower()
    assert "Authentication-Results" not in r.input and len(r.input) <= 300
    assert any(f.module == "message" and f.evidence.get("tactic") == "otp_request" for f in r.findings)
    assert [f.id for f in r.findings] == [f"F{i}" for i in range(1, len(r.findings) + 1)]
    assert r.report_hash.startswith("0x")


def test_bec_ceo_fraud_flagged(fake_body):
    r = email_pipeline.analyze_email(eml("bec_ceo_fraud.eml"), live_dns=False)
    assert r.risk_level in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH)
    assert "Executive identity claimed from a free webmail account" in titles(r.findings)
    assert r.email.sender_is_freemail and r.email.auth.dmarc == "pass"
    assert any("escalated" in c.detail for c in r.checks if c.name == "risk_engine" and c.detail)


def test_unparseable_input_does_not_crash(fake_body):
    r = email_pipeline.analyze_email("just some text without headers", live_dns=False)
    assert r.input_type == "email"


# ---------------------------------------------------------------- authentication ----------------------------
def test_parse_auth_results_strips_comments():
    a = ea.parse_auth_results("mx.example.net; spf=pass (domain of a@b.com; designates 1.2.3.4) "
                              "smtp.mailfrom=a@b.com; dkim=fail header.d=b.com; dmarc=fail (p=REJECT) header.from=b.com")
    by = {r["method"]: r for r in a["results"]}
    assert a["authserv_id"] == "mx.example.net"
    assert by["spf"]["result"] == "pass" and by["spf"]["props"]["smtp.mailfrom"] == "a@b.com"
    assert by["dkim"]["result"] == "fail" and by["dmarc"]["comment"] == "p=REJECT"


def test_alignment_failure_without_dmarc_verdict():
    raw = ("Authentication-Results: mx.r.example; spf=pass smtp.mailfrom=bounce@mailer-x.net; "
           "dkim=pass header.d=mailer-x.net\nFrom: Shop <hello@shop-example.com>\nSubject: hi\n\nbody\n")
    summary, fs = ea.auth_findings(ea.parse(raw))
    assert summary["spf_aligned"] is False and summary["dkim_aligned"] is False
    assert any("No aligned SPF/DKIM pass" in f.title and f.severity == Severity.MEDIUM for f in fs)


def test_trusted_authserv_id_env(monkeypatch):
    raw = ("Authentication-Results: attacker.example; dmarc=pass header.from=bank.com\n"
           "Authentication-Results: mx.mine.example; dmarc=fail header.from=bank.com\n"
           "From: a@bank.com\n\nx\n")
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_IDS", "mx.mine.example")
    summary, _ = ea.auth_findings(ea.parse(raw))
    assert summary["dmarc"] == "fail"


def test_dkim_body_hash_rfc6376_vector():
    # RFC 6376 Appendix A.2 example body, simple canonicalisation
    body = "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n\r\n"
    assert ea.dkim_body_hash(body, "simple") == "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="


def test_dns_posture_with_fake_resolver():
    recs = {"_dmarc.shop-example.com": ("missing", []), "shop-example.com": ("ok", ["v=spf1 +all"])}
    info, fs, checks = ea.dns_findings("shop-example.com", True, lambda n: recs.get(n, ("missing", [])))
    assert info["dmarc"]["status"] == "missing" and info["spf"]["all"] == "+all"
    assert "No valid DMARC policy" in titles(fs) and "authorises every server" in titles(fs)
    info, fs, checks = ea.dns_findings("x.com", True, lambda n: ("unavailable", []))
    assert {c.status for c in checks} == {"unavailable"} and not fs
    assert ea.dmarc_record("a.b.com", lambda n: ("ok", ["v=DMARC1; p=reject; sp=quarantine"])
                           if n == "_dmarc.b.com" else ("missing", []))["effective_policy"] == "quarantine"


# ---------------------------------------------------------------- identity ----------------------------------
def _identity(headers: str):
    return titles(ea.identity_findings(ea.parse(headers + "\nSubject: x\n\nbody\n")))


def test_display_name_shows_other_address():
    assert "Display name impersonates" in _identity('From: "support@paypal.com" <x@random-host.net>')


def test_display_brand_on_official_domain_ok():
    assert _identity('From: "PayPal" <service@paypal.com>') == ""


def test_person_named_like_brand_not_flagged():
    assert "impersonates" not in _identity('From: "Bhim Singh" <bhim.singh@gmail.com>')


def test_lookalike_sender_domain():
    assert "Look-alike sender domain imitating 'paypal'" in _identity("From: PayPal <service@paypa1.com>")


def test_multiple_from_addresses():
    assert "multiple From" in _identity("From: a@bank.com, b@evil.example")


def test_reply_to_other_domain():
    t = _identity("From: Shop <a@shop-example.com>\nReply-To: billing@other-example.net")
    assert "Reply-To domain differs" in t


# ---------------------------------------------------------------- links & attachments -----------------------
def test_link_text_mismatch_and_ip_links():
    scan = ea.scan_html('<a href="http://203.0.113.9/login">Sign in</a>'
                        '<a href="https://evil.example.net/x">www.paypal.com</a>'
                        '<a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.org'
                        '%2F&data=1">https://amazon.in</a>')
    t = titles(ea.link_findings(scan.links, scan))
    assert "Link text shows a different destination (2 links)" in t and "raw IP addresses" in t
    assert "example.org" in [ln.reg for ln in scan.links]                # Safe Links unwrapped
    assert "203.0.113.9" in scan.text or "http://203.0.113.9/login" in scan.text


def test_tracker_mismatch_is_low():
    scan = ea.scan_html('<a href="https://x.list-manage.com/track/click?u=1">www.example.com</a>')
    fs = ea.link_findings(scan.links, scan)
    assert fs[0].severity == Severity.LOW


def test_password_form_in_email():
    scan = ea.scan_html('<form action="https://evil.example/p"><input type="password"></form>')
    assert any(f.severity == Severity.HIGH and "password form" in f.title for f in ea.link_findings([], scan))


@pytest.mark.parametrize("name,ctype,data,sev,reason", [
    ("invoice.pdf.exe", "application/octet-stream", b"MZ\x90\x00", Severity.HIGH, "double extension"),
    ("report.js", "application/javascript", b"var a=1", Severity.HIGH, "executable / script"),
    ("photo.jpg", "image/jpeg", b"MZ\x90\x00", Severity.HIGH, "content is actually EXE"),
    ("doc‮xcod.exe", "application/octet-stream", b"MZ", Severity.HIGH, "right-to-left override"),
    ("archive.zip", "application/zip", b"PK\x03\x04", Severity.MEDIUM, "archive"),
    ("Q3.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", b"PK\x03\x04", Severity.MEDIUM, "macro"),
    ("scan.pdf", "image/png", b"%PDF-1.7", Severity.MEDIUM, "does not match"),
    ("notes.pdf", "application/pdf", b"%PDF-1.7", Severity.INFO, None),
])
def test_attachment_assessment(name, ctype, data, sev, reason):
    a = ea.assess_attachment(name, ctype, data)
    assert a.severity == sev, a.reasons
    if reason:
        assert any(reason in r for r in a.reasons), a.reasons
    assert len(a.sha256) == 64


def test_received_chain_origin():
    raw = ("Received: from mx.r.example (mx.r.example [10.0.0.5]) by inbox.r.example; Mon, 2 Nov 2026 09:00:00 +0000\n"
           "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.r.example "
           "with ESMTPS; Mon, 2 Nov 2026 08:59:59 +0000\nFrom: a@b.com\n\nx\n")
    hops, origin, fs = ea.received_findings(ea.parse(raw))
    assert len(hops) == 2 and origin == "209.85.220.41" and fs[0].severity == Severity.INFO


# ---------------------------------------------------------------- risk combination --------------------------
def _ef(sev, cat="context"):
    return Finding(id="", module="email", title=cat, severity=sev, description="d", evidence={"category": cat},
                   source="t")


def test_combine_levels():
    L = RiskLevel
    assert email_pipeline.combine_levels(L.LOW, L.SUSPICIOUS) == L.SUSPICIOUS
    assert email_pipeline.combine_levels(L.HIGH, L.CONFIRMED) == L.CONFIRMED
    assert email_pipeline.combine_levels(L.INCONCLUSIVE, L.LOW) == L.LOW
    assert email_pipeline.combine_levels(L.INCONCLUSIVE, L.INCONCLUSIVE) == L.INCONCLUSIVE


def test_email_level_rules_and_escalation():
    lv, *_ = email_pipeline.assess([_ef(Severity.CRITICAL)], RiskLevel.LOW, 0, set(), 0.8)
    assert lv == RiskLevel.HIGH
    lv, *_ = email_pipeline.assess([_ef(Severity.MEDIUM), _ef(Severity.MEDIUM)], RiskLevel.LOW, 0, set(), 0.8)
    assert lv == RiskLevel.SUSPICIOUS
    lv, score, *_ = email_pipeline.assess([_ef(Severity.MEDIUM, "identity_spoof")], RiskLevel.LOW, 5,
                                          {"otp_request"}, 0.8)
    assert lv == RiskLevel.HIGH and score >= 60                     # spoof + harmful ask → escalated
    lv, *_ = email_pipeline.assess([_ef(Severity.LOW, "auth_weak")], RiskLevel.LOW, 5, {"otp_request"}, 0.8)
    assert lv == RiskLevel.LOW                                      # weak signal alone does not escalate


# ---------------------------------------------------------------- API endpoint ------------------------------
def test_email_endpoint(fake_body, monkeypatch):
    from fastapi.testclient import TestClient
    from app import main
    monkeypatch.setattr(main, "_hits", main.defaultdict(main.deque))
    c = TestClient(main.app)
    r = c.post("/api/analyze/email", json={"raw": eml("phishing_bank.eml"), "live_dns": False})
    assert r.status_code == 200 and r.json()["input_type"] == "email" and r.json()["email"]["auth"]["dmarc"] == "fail"
    assert c.post("/api/analyze/email", json={"nope": 1}).status_code == 422
    monkeypatch.setattr(main, "EMAIL_MAX_BODY_BYTES", 1000)
    assert c.post("/api/analyze/email", json={"raw": "x" * 5000}).status_code == 413
