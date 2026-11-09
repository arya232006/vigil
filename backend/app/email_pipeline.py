"""Email (.eml) investigation: header authentication, sender identity, links and attachments
(`checks/email_auth.py`), then subject + body go through the existing message pipeline (rule engine, self-hosted
AI, link investigation). The email-level risk is combined here; `risk.py` is untouched.

Privacy: the report's `input` holds only sender + subject, never the raw message.
"""
from __future__ import annotations

import uuid

from . import pipeline
from .checks import email_auth as ea
from .checks import threatintel
from .checks.message import HARMFUL, detect_tactics
from .schemas import (CheckStatus, EmailAttachment, EmailAuthResult, EmailInfo, Explanation, Finding, Indicators,
                      LinkMismatch, Report, RiskLevel, Severity)

MAX_BODY_CHARS = 12_000
LEVEL_ORDER = {RiskLevel.LOW: 0, RiskLevel.SUSPICIOUS: 1, RiskLevel.HIGH: 2, RiskLevel.CONFIRMED: 3}
POINTS = {Severity.CRITICAL: 45, Severity.HIGH: 22, Severity.MEDIUM: 9, Severity.LOW: 3, Severity.INFO: 0}
SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
ESCALATING = {"auth_failure", "identity_spoof"}          # finding categories that, with a harmful ask, mean fraud
SCORE_BAND = {RiskLevel.LOW: (0, 24), RiskLevel.SUSPICIOUS: (25, 59), RiskLevel.HIGH: (60, 100),
              RiskLevel.CONFIRMED: (90, 100), RiskLevel.INCONCLUSIVE: (0, 59)}
REPORT_ADVICE = ("Report it with your mail app's 'Report phishing' button (in India also at cybercrime.gov.in or "
                 "the 1930 helpline), then delete it.")


def combine_levels(*levels: RiskLevel) -> RiskLevel:
    """More severe of the levels (low < suspicious < high < confirmed); inconclusive only if all are."""
    known = [lv for lv in levels if lv in LEVEL_ORDER]
    return max(known, key=LEVEL_ORDER.__getitem__) if known else RiskLevel.INCONCLUSIVE


def email_level(findings: list[Finding], headers_ok: bool = True) -> tuple[RiskLevel, str]:
    crit = sum(f.severity == Severity.CRITICAL for f in findings)
    high = sum(f.severity == Severity.HIGH for f in findings)
    med = sum(f.severity == Severity.MEDIUM for f in findings)
    why = f"{crit} critical / {high} high / {med} medium email indicator(s)"
    if crit or high >= 2:
        return RiskLevel.HIGH, why
    if high or med >= 2:
        return RiskLevel.SUSPICIOUS, why
    if not headers_ok:
        return RiskLevel.INCONCLUSIVE, why + "; no usable sender / authentication headers"
    return RiskLevel.LOW, why


def assess(email_findings: list[Finding], body_level: RiskLevel, body_score: int, tactics: set[str],
           coverage: float, headers_ok: bool = True) -> tuple[RiskLevel, int, float, list[str]]:
    """Deterministic email risk: (level, score 0-100, confidence 0-1, reasoning trail)."""
    lvl_e, why = email_level(email_findings, headers_ok)
    trail = [f"email checks: {why} → {lvl_e.value}", f"body report: {body_level.value} (score {body_score})"]
    level = combine_levels(lvl_e, body_level)
    trail.append(f"combined (more severe wins) → {level.value}")
    triggers = [f for f in email_findings if f.evidence.get("category") in ESCALATING
                and SEV_RANK[f.severity] >= SEV_RANK[Severity.MEDIUM]]
    harmful = sorted(set(tactics) & HARMFUL)
    escalated = bool(triggers and harmful) and LEVEL_ORDER.get(level, -1) < LEVEL_ORDER[RiskLevel.HIGH]
    if escalated:
        level = RiskLevel.HIGH
        trail.append(f"escalated: '{triggers[0].title}' + harmful request in the body ({', '.join(harmful)}) "
                     "→ high_risk")
    score = max(min(100, sum(POINTS[f.severity] for f in email_findings)), body_score)
    if escalated:
        score = max(score, 70)
    lo, hi = SCORE_BAND[level]
    score = max(lo, min(hi, score))
    conf = coverage
    if level in (RiskLevel.HIGH, RiskLevel.CONFIRMED) and lvl_e in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH) \
            and body_level in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH, RiskLevel.CONFIRMED):
        conf += 0.05
        trail.append("header and body analyses independently agree")
    if level == RiskLevel.CONFIRMED:
        conf = max(conf, 0.95)
    return level, score, round(min(conf, 0.99), 2), trail


def _coverage(ec: ea.EmailChecks, body: Report | None) -> float:
    """Evidence coverage: sender parsed, server auth results present, DNS posture obtained, body analysed."""
    answered = ("ok", "missing", "invalid")
    parts = [(1.0, 1.0 if ec.parsed.from_addr else 0.0),
             (2.0, 1.0 if ec.auth.get("source") else 0.0),
             (0.5, 1.0 if ec.dns["dmarc"].get("status") in answered else 0.0),
             (0.5, 1.0 if ec.dns["spf"].get("status") in answered else 0.0),
             (2.0, body.confidence if body else 0.0)]
    return sum(w * v for w, v in parts) / sum(w for w, _ in parts)


def _dmarc_policy(dns_info: dict) -> str:
    d = dns_info.get("dmarc", {})
    st = d.get("status")
    if st == "ok":
        return d.get("effective_policy") or "none"
    return {"skipped": "not_checked"}.get(st, st or "not_checked")


def _input_summary(p: ea.Parsed) -> str:
    who = f"{p.from_display} <{p.from_addr}>" if p.from_display else (p.from_addr or "unknown sender")
    return f"Email from {who} | Subject: {p.subject or '(none)'}"[:300]


def _failed_report(rid: str, err: Exception, owner_id: str | None = None) -> Report:
    f = Finding(id="F1", module="email", title="Email could not be parsed", severity=Severity.INFO,
                description=f"{type(err).__name__}: {str(err)[:200]}", evidence={}, source="Email parser")
    rep = Report(report_id=rid, input_type="email", input="Unparseable email", analyzed_at=pipeline.now(),
                 risk_level=RiskLevel.INCONCLUSIVE, risk_score=0, confidence=0.0, findings=[f],
                 checks=[CheckStatus(name="email_parse", status="failed", detail=str(err)[:200])],
                 explanation=Explanation(summary="The email could not be parsed. "
                                         + pipeline.LEVEL_ADVICE[RiskLevel.INCONCLUSIVE], generated_by="template"),
                 recommendations=[pipeline.LEVEL_ADVICE[RiskLevel.INCONCLUSIVE]],
                 limitations=pipeline.BASE_LIMITATIONS[:1])
    return pipeline._finalize(rep, [], owner_id=owner_id)


def analyze_email(raw: str, live_dns: bool = True, owner_id: str | None = None) -> Report:
    rid = uuid.uuid4().hex[:12]
    try:
        ec = ea.run_all(raw, live_dns=live_dns, rank_fn=threatintel.tranco_rank)
    except Exception as e:                       # never 500 on hostile input; report what happened
        return _failed_report(rid, e, owner_id)
    p = ec.parsed
    checks = list(ec.checks)
    limitations = pipeline.BASE_LIMITATIONS[:1] + [
        "Authentication-Results and Received headers added before your provider's server can be forged; only the "
        "receiving server's own header is trusted.",
        "Passing SPF / DKIM / DMARC proves which domain sent the email, not that the domain is trustworthy.",
        "Attachments were inspected statically (name, declared type, magic bytes, SHA-256); they were not opened, "
        "executed or virus-scanned.",
    ]
    if not live_dns:
        limitations.append("Live DNS checks (the sender domain's DMARC / SPF records) were disabled.")
    elif "unavailable" in (ec.dns["dmarc"].get("status"), ec.dns["spf"].get("status")):
        limitations.append("DNS lookups for the sender domain failed or timed out; DMARC / SPF posture is partial.")

    # ---- body: reuse the message pipeline (rule engine + self-hosted AI + up to 3 link investigations)
    text = f"{p.subject}\n\n{ec.body_text}".strip()[:MAX_BODY_CHARS]
    body: Report | None = None
    if text:
        try:
            body = pipeline.analyze_message(text, owner_id)
            checks.append(CheckStatus(name="body_analysis", status="ok",
                                      detail=f"report {body.report_id}: {body.risk_level.value} "
                                             f"(score {body.risk_score}), {len(body.findings)} finding(s)"))
            checks += [CheckStatus(name=f"body_{c.name}", status=c.status, detail=c.detail) for c in body.checks]
        except Exception as e:
            checks.append(CheckStatus(name="body_analysis", status="failed", detail=f"{type(e).__name__}: {e}"[:200]))
            limitations.append("The body analysis (rules / AI / link investigation) failed; only header, link and "
                               "attachment checks contributed.")
    else:
        checks.append(CheckStatus(name="body_analysis", status="skipped", detail="no subject or body text"))

    body_findings = []
    for f in (body.findings if body else []):
        if f.module == "correlation":            # this report computes its own correlations
            continue
        c = f.model_copy(deep=True)
        c.evidence = {**c.evidence, "from_report": body.report_id}
        body_findings.append(c)
    tactics = set(detect_tactics(text)) | {f.evidence.get("tactic") for f in body_findings
                                          if f.module == "message" and f.evidence.get("tactic")}

    headers_ok = bool(p.from_addr or p.received or ec.auth.get("source"))
    level, score, conf, trail = assess(ec.findings, body.risk_level if body else RiskLevel.INCONCLUSIVE,
                                       body.risk_score if body else 0, tactics, _coverage(ec, body), headers_ok)
    checks.append(CheckStatus(name="risk_engine", status="ok", detail=" | ".join(trail)[:500]))
    findings = pipeline._number(ec.findings + body_findings)

    # ---- structured email section + indicators
    web = [ln for ln in ec.links if ln.host]
    link_domains = list(dict.fromkeys(ln.reg for ln in web))
    reply_domains = [ea._domain_of(r) for r in p.reply_to]
    from_org = ea.org_domain(p.from_domain) if p.from_domain else ""
    info = EmailInfo(
        from_address=p.from_addr or None, from_domain=p.from_domain or None, display_name=p.from_display or None,
        reply_to=p.reply_to, return_path=p.return_path or None, sender=p.sender or None, subject=p.subject or None,
        date=p.date or None, message_id=p.message_id or None, sender_is_freemail=from_org in ea.FREE_MAIL,
        auth=EmailAuthResult(**ec.auth), dmarc_policy=_dmarc_policy(ec.dns),
        spf_record=ec.dns["spf"].get("record"), received_hops=len(ec.hops), origin_ip=ec.origin_ip,
        body_source=ec.body_source, link_count=len(web), link_domains=link_domains[:20],
        link_mismatches=[LinkMismatch(text=ln.text[:200], href=ln.href[:500], text_domain=ln.text_domain,
                                      href_domain=ln.reg)
                         for ln in web if ln.text_reg and ln.reg and ln.text_reg != ln.reg][:20],
        attachments=[EmailAttachment(filename=a.filename, content_type=a.content_type, size=a.size, sha256=a.sha256,
                                     detected_type=a.detected_type, risky=a.risky, reasons=a.reasons)
                     for a in ec.attachments],
        body_report_id=body.report_id if body else None)
    b_ind = body.indicators if body and body.indicators else Indicators()
    emails = list(dict.fromkeys(e for e in [p.from_addr.lower(), *p.reply_to, p.return_path, *b_ind.emails] if e))
    indicators = Indicators(
        urls=list(dict.fromkeys([ln.href for ln in web] + b_ind.urls))[:20],
        domains=list(dict.fromkeys(d for d in [p.from_domain, *reply_domains, *link_domains, *b_ind.domains] if d))[:30],
        emails=emails[:20], phones=b_ind.phones, upi_ids=b_ind.upi_ids)

    def corr_domain(d: str) -> bool:      # shared webmail / ESP / real brand domains would link unrelated reports
        o = ea.org_domain(d)
        return bool(o) and o not in ea.FREE_MAIL and o not in ea.TRACKERS and not ea.is_official(d)
    inds = [("email", e) for e in emails]
    inds += [("domain", o) for o in dict.fromkeys(ea.org_domain(d) for d in [p.from_domain, *reply_domains,
                                                                            *link_domains] if d and corr_domain(d))]
    inds += [("ip", ec.origin_ip)] if ec.origin_ip else []
    inds += [("sha256", a.sha256) for a in ec.attachments if a.size]
    inds += [("phone", ph[-10:]) for ph in b_ind.phones] + [("upi", u.lower()) for u in b_ind.upi_ids]

    recs = [pipeline.LEVEL_ADVICE[level]]
    if level in (RiskLevel.HIGH, RiskLevel.CONFIRMED):
        recs.append(REPORT_ADVICE)
    recs += [f.recommendation for f in findings if f.recommendation
             and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    recs = list(dict.fromkeys(recs))[:7]

    report = Report(report_id=rid, input_type="email", input=_input_summary(p), analyzed_at=pipeline.now(),
                    risk_level=level, risk_score=score, confidence=conf, findings=findings, checks=checks,
                    indicators=indicators, model_scores=body.model_scores if body else [],
                    linked_reports=([body.report_id] + body.linked_reports) if body else [],
                    explanation=pipeline._explain(level, findings, p.subject or info.from_address or "email"),   # vigil-s2; template fallback
                    recommendations=recs, limitations=limitations, email=info)
    return pipeline._finalize(report, inds, owner_id=owner_id)
