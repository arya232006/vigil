"""Registrar and redirect-hop correlation: weak evidence must not link reports by itself."""
import uuid

from app import pipeline, store
from app.schemas import Explanation, RedirectHop, Report, RiskLevel, TargetInfo


def _stored(indicators, level=RiskLevel.HIGH):
    report = Report(report_id=uuid.uuid4().hex[:12], input_type="domain", input="x.example",
                    analyzed_at="2026-11-09T10:00:00+00:00", risk_level=level, risk_score=80, confidence=0.9,
                    explanation=Explanation(summary="s", generated_by="template"))
    report.report_hash = store.compute_hash(report)
    store.save(report, indicators)
    return report.report_id


def _token():
    return uuid.uuid4().hex[:10]


def test_shared_registrar_alone_does_not_link_reports():
    registrar = ("registrar", f"registrar-{_token()}")
    earlier = _stored([registrar])
    assert earlier not in {c.report_id for c in pipeline._correlate("new", [registrar])}


def test_registrar_is_shown_alongside_stronger_evidence():
    registrar, ip = ("registrar", f"registrar-{_token()}"), ("ip", f"ip-{_token()}")
    earlier = _stored([registrar, ip])
    link = next(c for c in pipeline._correlate("new", [registrar, ip]) if c.report_id == earlier)
    assert f"registrar:{registrar[1]}" in link.shared and f"ip:{ip[1]}" in link.shared


def test_shared_redirect_hop_links_reports():
    hop = ("redirect", f"{_token()}.example")
    earlier = _stored([hop])
    assert earlier in {c.report_id for c in pipeline._correlate("new", [hop])}


def test_infrastructure_indicators_keep_only_meaningful_hops():
    target = TargetInfo(submitted="start.example", registrar=" Example Registrar, Inc. ",
                        final_url="https://landing.example/page",
                        redirect_chain=[RedirectHop(url="https://start.example/"), RedirectHop(url="https://bit.ly/x"),
                                        RedirectHop(url="https://tracker-relay.example/go"),
                                        RedirectHop(url="https://landing.example/page")])
    assert pipeline._infrastructure_indicators(target, "start.example") == [
        ("registrar", "example registrar, inc."), ("redirect", "tracker-relay.example")]


def test_payment_codes_are_analysed_as_messages_not_websites():
    assert pipeline.detect_type("upi://pay?pa=refund.desk@ybl&am=1") == "message"
    assert pipeline.detect_type("https://example.org/a") == "url"
    assert pipeline.detect_type("hxxps://example[.]org") == "url"
    assert pipeline.detect_type("example.org") == "domain"
