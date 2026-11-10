"""Investigation pipeline: Submit → Investigate → Analyse → Assess risk → Report (+ hash for on-chain registry)."""
from __future__ import annotations

import datetime as dt
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from . import risk, store
from .checks import domain as domain_chk
from .checks import page as page_chk
from .checks import threatintel, tls
from .checks.fetcher import BlockedTarget, UnresolvableHost, is_public_ip, normalize_url, safe_fetch
from .checks.message import detect_tactics, extract_indicators
from .ml import system1, system2
from .ml.url_features import SHORTENERS, _extract, is_ip
from .schemas import (
    CheckStatus,
    Correlation,
    Explanation,
    Finding,
    Indicators,
    ModelScore,
    RedirectHop,
    Report,
    RiskLevel,
    Severity,
    TargetInfo,
)

POOL = ThreadPoolExecutor(16)
SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
BASE_LIMITATIONS = [
    "Automated checks can miss new or targeted attacks; a low-risk result is not a guarantee of safety.",
    "A valid HTTPS certificate only proves an encrypted connection, not that the website is legitimate.",
    "Only passive, non-intrusive checks were performed; no exploitation or active scanning.",
]
LEVEL_ADVICE = {
    RiskLevel.CONFIRMED: "Do not open this link or reply. Report it and delete it.",
    RiskLevel.HIGH: "Do not enter passwords, OTPs, card or bank details. Verify through the organisation's official app or number.",
    RiskLevel.SUSPICIOUS: "Be careful: verify the sender or website through an official channel before acting.",
    RiskLevel.LOW: "No significant threats found, but stay alert and never share OTPs or passwords.",
    RiskLevel.INCONCLUSIVE: "We could not gather enough evidence. Treat it with caution until verified.",
}


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def detect_type(text: str) -> str:
    t = text.strip()
    scheme = t.split("://", 1)[0].lower() if "://" in t else ""
    if scheme and scheme not in ("http", "https", "hxxp", "hxxps"):      # e.g. upi://pay?pa=...: nothing to fetch
        return "message"
    if " " not in t and "\n" not in t and ("." in t or "://" in t):
        return "url" if ("/" in t or "://" in t) else "domain"
    return "message"


def reg_domain(host: str) -> str:
    return _extract(host).top_domain_under_public_suffix or host


def _number(findings: list[Finding]) -> list[Finding]:
    findings.sort(key=lambda f: SEV_ORDER[f.severity])
    for i, f in enumerate(findings, 1):
        f.id = f"F{i}"
    return findings


def _compact(findings: list[Finding]) -> list[dict]:
    return [{"id": f.id, "severity": f.severity.value, "title": f.title, "detail": f.description[:220],
             "source": f.source[:80]} for f in findings if f.severity != Severity.INFO][:14]


def _template_explanation(level: RiskLevel, findings: list[Finding], subject: str) -> Explanation:
    top = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)][:4]
    head = {
        RiskLevel.CONFIRMED: "This is a known malicious destination.",
        RiskLevel.HIGH: "Several strong warning signs were found.",
        RiskLevel.SUSPICIOUS: "Some warning signs need your attention.",
        RiskLevel.LOW: "No significant warning signs were found in the checks we ran.",
        RiskLevel.INCONCLUSIVE: "We could not collect enough evidence to decide.",
    }[level]
    return Explanation(summary=f"{head} {LEVEL_ADVICE[level]}",
                       key_points=[f"[{f.id}] {f.title}: {f.description}" for f in top], generated_by="template")


def _explain(level: RiskLevel, findings: list[Finding], subject: str) -> Explanation:
    out, used = system2.explain(level.value, _compact(findings), subject)
    if not out:
        return _template_explanation(level, findings, subject)
    pts = [f"{kp['text']} [{', '.join(kp['finding_ids'])}]" for kp in out["key_points"]]
    return Explanation(summary=out["summary"], key_points=pts + out.get("advice", [])[:2], generated_by=used)


# Thousands of unrelated sites share a registrar, so it can support a link but never create one on its own.
WEAK_LINK_PREFIXES = ("registrar:",)


def _infrastructure_indicators(target: TargetInfo, own_domain: str) -> list[tuple[str, str]]:
    """Registrar and the sites a link was redirected through. Public URL shorteners are skipped: sharing one says
    nothing about who is behind either link."""
    inds = [("registrar", target.registrar.strip().lower())] if target.registrar else []
    final = reg_domain(urlsplit(target.final_url).hostname or "") if target.final_url else ""
    for hop in target.redirect_chain:
        domain = reg_domain(urlsplit(hop.url).hostname or "")
        if domain and domain not in (own_domain, final) and domain not in SHORTENERS:
            inds.append(("redirect", domain))
    return inds


def _correlate(report_id: str, inds: list[tuple[str, str]], extra: dict[str, list[str]] | None = None,
               owner_id: str | None = None) -> list[Correlation]:
    rel = store.find_related(inds, exclude_id=report_id)
    rel = {rid: shared for rid, shared in rel.items() if not all(k.startswith(WEAK_LINK_PREFIXES) for k in shared)}
    for rid, shared in (extra or {}).items():
        rel.setdefault(rid, []).extend(shared)
    out = []
    for rid, shared in sorted(rel.items(), key=lambda kv: -len(kv[1]))[:10]:
        s = store.summary(rid)
        if s:
            # Another user's report stays private: only the indicators this report also contains are shown.
            shown_id = rid if s[2] in (None, owner_id) else ""
            out.append(Correlation(report_id=shown_id, shared=shared[:6], risk_level=RiskLevel(s[0]), analyzed_at=s[1]))
    return out


def _finalize(report: Report, inds: list[tuple[str, str]], extra: dict[str, list[str]] | None = None,
              owner_id: str | None = None) -> Report:
    report.correlations = [c for c in _correlate(report.report_id, inds, extra, owner_id)
                           if c.report_id not in report.linked_reports]       # own sub-reports aren't "earlier"
    if report.correlations:
        bad = [c for c in report.correlations if c.risk_level in (RiskLevel.HIGH, RiskLevel.CONFIRMED)]
        report.findings.append(Finding(
            id=f"F{len(report.findings) + 1}", module="correlation",
            title=f"Linked to {len(report.correlations)} earlier report(s)",
            severity=Severity.MEDIUM if bad else Severity.INFO,
            description=f"Shares infrastructure or indicators with previous reports ({len(bad)} rated high/confirmed).",
            evidence={"related": [c.model_dump() for c in report.correlations[:5]]},
            source="Vigil report history (deterministic indicator matching)"))
    report.report_hash = store.compute_hash(report)
    store.save(report, inds, owner_id)
    return report


# ---------------------------------------------------------------- URL / domain -----------------------
def analyze_url(raw: str, input_type: str = "url", depth: int = 0, owner_id: str | None = None) -> Report:
    rid = uuid.uuid4().hex[:12]
    findings: list[Finding] = []
    checks: list[CheckStatus] = []
    limitations = list(BASE_LIMITATIONS)
    try:
        url = normalize_url(raw)
        h0 = (urlsplit(url).hostname or "").strip("[]")
        if is_ip(h0) and not is_public_ip(h0):
            raise BlockedTarget(f"{h0} is a private/internal address; not analysed (SSRF protection)")
    except BlockedTarget as e:
        f = Finding(id="F1", module="url", title="Target not analysed", severity=Severity.INFO, description=str(e),
                    evidence={"input": raw[:300]}, source="Input validation / SSRF protection")
        rep = Report(report_id=rid, input_type=input_type, input=raw, analyzed_at=now(),
                     risk_level=RiskLevel.INCONCLUSIVE, risk_score=0, confidence=0.0, findings=[f],
                     checks=[CheckStatus(name="input_validation", status="failed", detail=str(e))],
                     explanation=Explanation(summary=f"This input cannot be analysed safely: {e}.", generated_by="template"),
                     recommendations=[LEVEL_ADVICE[RiskLevel.INCONCLUSIVE]], limitations=limitations)
        return _finalize(rep, [], owner_id=owner_id)

    sp = urlsplit(url)
    host = sp.hostname or ""
    reg = reg_domain(host)
    rank = threatintel.tranco_rank(reg)
    try:
        raw_netloc = urlsplit(raw.strip() if "://" in raw else "http://" + raw.strip()).netloc
    except ValueError:                                # defanged input such as hxxp://evil[.]example
        raw_netloc = ""
    if "@" in raw_netloc:
        shown = raw_netloc.rsplit("@", 1)[0]
        findings.append(Finding(
            id="", module="url", title="Link hides its real destination with '@'", severity=Severity.HIGH,
            description=f"Everything before '@' ('{shown[:80]}') is ignored by browsers; the link really goes to {host}.",
            evidence={"displayed_part": shown[:200], "real_host": host}, source="URL structure analysis",
            impact="Classic trick to make a link look like a trusted site.", recommendation="Do not open this link."))
    target = TargetInfo(submitted=raw, normalized_url=url, hostname=host, registered_domain=reg)

    f_fetch = POOL.submit(safe_fetch, url)
    f_dom = POOL.submit(domain_chk.analyze, host, f"{sp.path}?{sp.query}", rank)
    f_ti = POOL.submit(threatintel.lookup, url, host)
    f_ml = POOL.submit(system1.url_score, host)

    url_ml = None
    try:
        url_ml = f_ml.result()
        checks.append(CheckStatus(name="system1_url_model", status="ok", detail=f"p(phishing)={url_ml.probability}"))
        popular = bool(rank and rank <= 20_000)
        if url_ml.probability >= 0.5 and not (popular and url_ml.probability < 0.9):
            findings.append(Finding(
                id="", module="ml", title="AI model: domain resembles phishing infrastructure",
                severity=Severity.HIGH if url_ml.probability >= 0.85 else Severity.MEDIUM,
                description=f"Our self-hosted System-1 classifier estimates a {url_ml.probability:.0%} (calibrated) "
                            f"probability that this hostname is phishing-related.",
                evidence=url_ml.details | {"probability": url_ml.probability}, source=url_ml.model,
                limitations="Statistical estimate from the hostname only; not proof on its own."))
    except Exception as e:  # model failure must not break the report
        checks.append(CheckStatus(name="system1_url_model", status="failed", detail=str(e)[:200]))

    try:
        dinfo, dfind = f_dom.result()
        findings += dfind
        target.domain_created = dinfo.get("domain_created")
        target.domain_age_days = dinfo.get("domain_age_days")
        target.registrar = dinfo.get("registrar")
        rd_ok = dinfo.get("rdap", {}).get("available", False)
        checks.append(CheckStatus(name="domain_analysis", status="ok",
                                  detail=f"RDAP {'ok' if rd_ok else 'unavailable'}; Tranco rank {rank or 'not in top 200k'}"))
        if not rd_ok:
            limitations.append("Domain registration data (RDAP) was unavailable for this domain.")
    except Exception as e:
        checks.append(CheckStatus(name="domain_analysis", status="failed", detail=str(e)[:200]))

    ti_find, ti_src, ti_down = f_ti.result()
    findings += ti_find
    checks.append(CheckStatus(name="threat_intel", status="ok",
                              detail="; ".join(ti_src + [f"unavailable: {s}" for s in ti_down])))
    limitations += [f"{s} could not be checked, so this link was not compared against it." for s in ti_down]

    fetch_ok = False
    tls_info = None
    try:
        res = f_fetch.result()
        target.redirect_chain = [RedirectHop(url=h.url, status=h.status, ip=h.ip) for h in res.hops]
        target.ip_addresses = sorted({h.ip for h in res.hops if h.ip})
        target.final_url = res.final_url
        if res.error:
            checks.append(CheckStatus(name="website_fetch", status="failed", detail=res.error[:200]))
            limitations.append("The website could not be fully retrieved; page-content checks were limited.")
        else:
            fetch_ok = True
            checks.append(CheckStatus(name="website_fetch", status="ok",
                                      detail=f"HTTP {res.status}, {len(res.hops)} hop(s), {res.elapsed_ms} ms"))
        final_host = urlsplit(res.final_url).hostname or host
        final_reg = reg_domain(final_host)
        domains_in_chain = list(dict.fromkeys(reg_domain(urlsplit(h.url).hostname or "") for h in res.hops))
        if len(domains_in_chain) > 1:
            sev = Severity.MEDIUM if final_reg != reg else Severity.LOW
            findings.append(Finding(
                id="", module="redirect", title=f"Redirects across {len(domains_in_chain)} domains", severity=sev,
                description=f"The link passes through {' → '.join(domains_in_chain)} before landing on {final_reg}.",
                evidence={"chain": [h.url for h in res.hops]}, source="Redirect-chain tracing (each hop SSRF-validated)",
                impact="Redirect chains are used to hide the real destination from users and filters."))
            if final_reg != reg:
                ti2, _, ti2_down = threatintel.lookup(res.final_url, final_host)
                findings += ti2
                limitations += [f"{s} could not be checked for the final destination {final_host}." for s in ti2_down]
                ml2 = system1.url_score(final_host)
                if ml2.probability >= 0.5:
                    findings.append(Finding(
                        id="", module="ml", title=f"AI model: final destination {final_host} resembles phishing",
                        severity=Severity.HIGH if ml2.probability >= 0.85 else Severity.MEDIUM,
                        description=f"System-1 estimates {ml2.probability:.0%} phishing probability for the landing host.",
                        evidence=ml2.details | {"probability": ml2.probability}, source=ml2.model))
                dinfo2, dfind2 = domain_chk.analyze(final_host, "", threatintel.tranco_rank(final_reg))
                for f in dfind2:
                    f.title = f"Destination: {f.title}"
                findings += dfind2
        if fetch_ok:
            pinfo, pfind = page_chk.analyze(res, final_host, final_reg)
            findings += pfind
            target.page_title = pinfo.get("title")
            checks.append(CheckStatus(name="page_and_headers", status="ok",
                                      detail=f"{pinfo.get('forms', 0)} forms, {pinfo.get('password_fields', 0)} password fields"))
        if res.final_url.startswith("https://") and res.hops:
            tls_info, tfind, tdetail = tls.analyze(final_host, res.hops[-1].ip, final_reg)
            findings += tfind
            checks.append(CheckStatus(name="tls_certificate", status="ok" if tls_info.verdict != "unavailable" else "failed",
                                      detail=tdetail[:300]))
        else:
            checks.append(CheckStatus(name="tls_certificate", status="skipped", detail="site not served over HTTPS"))
    except UnresolvableHost as e:
        checks.append(CheckStatus(name="website_fetch", status="failed", detail=str(e)[:200]))
        findings.append(Finding(id="", module="url", title="Website unreachable (domain does not resolve)",
                                severity=Severity.INFO, description="The domain has no DNS records right now. It may have "
                                "been taken down, may not be live yet, or the link is mistyped.", evidence={"url": url},
                                source="DNS resolution"))
        limitations.append("The site could not be reached, so page-content and certificate checks did not run.")
    except BlockedTarget as e:
        checks.append(CheckStatus(name="website_fetch", status="failed", detail=str(e)))
        findings.append(Finding(id="", module="url", title="Destination blocked by SSRF protection", severity=Severity.MEDIUM,
                                description=str(e), evidence={"url": url}, source="SSRF guard",
                                impact="Links resolving to internal addresses can be used to attack networks."))
    except Exception as e:
        checks.append(CheckStatus(name="website_fetch", status="failed", detail=f"{type(e).__name__}: {str(e)[:150]}"))

    ran = [c for c in checks if c.status != "skipped"]
    coverage = sum(c.status == "ok" for c in ran) / max(len(ran), 1)
    tls_failed = url.startswith("https://") and any(c.name == "tls_certificate" and c.status == "failed" for c in checks)
    if tls_failed:
        coverage *= 0.7                      # certificate trust is a key check for HTTPS sites
        limitations.append("The TLS certificate check could not complete, so certificate trust was NOT verified.")
    findings = _number(findings)
    level, score, conf, trail = risk.classify_url(findings, url_ml, coverage, rank,
                                                  tls_info.verdict if tls_info else None)
    checks.append(CheckStatus(name="risk_engine", status="ok", detail=" | ".join(trail)[:500]))

    recs = list(dict.fromkeys([LEVEL_ADVICE[level]] + [f.recommendation for f in findings if f.recommendation
                                                       and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]))[:6]
    report = Report(report_id=rid, input_type=input_type, input=raw, analyzed_at=now(), risk_level=level,
                    risk_score=score, confidence=conf, findings=findings, checks=checks, target=target, tls=tls_info,
                    model_scores=[m for m in [url_ml] if m],
                    explanation=_explain(level, findings, url) if depth == 0 else _template_explanation(level, findings, url),
                    recommendations=recs, limitations=limitations)
    inds = [("domain", reg), ("host", host)] + [("ip", ip) for ip in target.ip_addresses]
    if target.final_url:
        inds.append(("domain", reg_domain(urlsplit(target.final_url).hostname or "")))
    if tls_info and tls_info.chain:
        inds.append(("cert", tls_info.chain[0]["sha256"]))
    inds += _infrastructure_indicators(target, reg)
    return _finalize(report, inds, owner_id=owner_id)


# ---------------------------------------------------------------- Message ---------------------------
def _shingles(t: str) -> set[str]:
    t = re.sub(r"\d", "0", re.sub(r"\s+", " ", t.lower()))
    return {t[i:i + 5] for i in range(max(len(t) - 4, 1))}


def analyze_message(text: str, owner_id: str | None = None) -> Report:
    rid = uuid.uuid4().hex[:12]
    checks: list[CheckStatus] = []
    findings: list[Finding] = []
    inds: Indicators = extract_indicators(text)
    rules = detect_tactics(text)

    f_links = [POOL.submit(analyze_url, u, "url", 1, owner_id) for u in inds.urls[:3]]

    # System-1 first (milliseconds); the router decides whether System-2 reasoning is needed.
    s1 = None
    try:
        s1 = system1.msg_score(text)
        checks.append(CheckStatus(name="system1_message_model", status="ok", detail=f"p={s1.probability}"))
    except Exception as e:
        checks.append(CheckStatus(name="system1_message_model", status="failed", detail=str(e)[:200]))
    has_ioc = bool(inds.urls or inds.emails or inds.phones or inds.upi_ids)
    tau = system2.router_threshold()
    fast_path = (system2.ROUTER_ENABLED and tau is not None and s1 is not None and not rules and not has_ioc
                 and s1.probability < tau)
    checks.append(CheckStatus(name="router", status="ok", detail=(
        f"fast path: System-1 p={s1.probability:.4f} < {tau}, no rule tactics, no links/contacts → System-2 not needed"
        if fast_path else "System-2 invoked (risk signals present or System-1 not confident)")))

    if fast_path:
        s2, s2_model, s2_ms = None, "router: fast path", 0
        checks.append(CheckStatus(name="system2_reasoning_model", status="skipped",
                                  detail="not needed: confidently benign by System-1 and rules"))
    else:
        s2, s2_model, s2_ms = system2.analyze_message(text)
        checks.append(CheckStatus(name="system2_reasoning_model", status="ok" if s2 else "failed",
                                  detail=f"{s2_model}, {s2_ms} ms" + (
                                      f", calibrated p(unsafe)={s2.get('p_unsafe')}"
                                      f", dropped {s2.get('ungrounded_evidence_dropped', 0)} ungrounded quotes"
                                      if s2 else "")))
    checks.append(CheckStatus(name="rule_engine", status="ok", detail=f"{len(rules)} tactic(s) matched"))

    sub_reports = []
    for fl in f_links:
        try:
            sub_reports.append(fl.result())
        except Exception as e:
            checks.append(CheckStatus(name="link_analysis", status="failed", detail=str(e)[:150]))
    if inds.urls:
        checks.append(CheckStatus(name="link_analysis", status="ok", detail=f"{len(sub_reports)} link(s) investigated"))

    labels = {
        "otp_request": ("Asks for an OTP / verification code", Severity.HIGH),
        "credential_request": ("Asks for passwords, PINs or card details", Severity.HIGH),
        "payment_request": ("Requests a payment", Severity.MEDIUM),
        "upfront_fee": ("Demands an upfront fee to release money/prize/job", Severity.HIGH),
        "remote_access": ("Asks to install remote-access software", Severity.HIGH),
        "personal_info_request": ("Asks for personal / KYC / bank information", Severity.MEDIUM),
        "urgency": ("Creates time pressure", Severity.LOW),
        "fear_threat": ("Uses threats (block, arrest, disconnection)", Severity.MEDIUM),
        "reward_lure": ("Promises prizes, cashback or guaranteed returns", Severity.MEDIUM),
        "authority_impersonation": ("Invokes authorities (police, CBI, RBI, tax, customs)", Severity.MEDIUM),
        "secrecy": ("Asks you to keep it secret", Severity.MEDIUM),
        "instruction_injection": ("Contains instructions aimed at AI/security tools", Severity.HIGH),
        "link_click": ("Pushes you to click a link", Severity.LOW),
    }
    s2_ev = {e["tactic"]: e["quote"] for e in (s2 or {}).get("evidence", []) if e.get("tactic")}
    for tactic in sorted(set(rules) | set(s2_ev)):
        title, sev = labels.get(tactic, (tactic.replace("_", " ").capitalize(), Severity.LOW))
        quote = rules.get(tactic) or s2_ev.get(tactic)
        srcs = [s for s, ok in (("rule engine", tactic in rules), ("System-2 model", tactic in s2_ev)) if ok]
        findings.append(Finding(id="", module="message", title=title, severity=sev,
                                description=f"Evidence: “{quote}”", evidence={"tactic": tactic, "quote": quote,
                                                                               "detected_by": srcs},
                                source=" + ".join(srcs) + (" (independent agreement)" if len(srcs) == 2 else "")))
    if s2 and s2.get("impersonated_entity") and s2.get("verdict") != "legitimate":
        findings.append(Finding(id="", module="message", title=f"Claims to be from {s2['impersonated_entity']}",
                                severity=Severity.MEDIUM if s2.get("verdict") == "scam" else Severity.LOW,
                                description="The sender identity cannot be verified from the message itself.",
                                evidence={"entity": s2["impersonated_entity"], "scam_type": s2.get("scam_type")},
                                source=f"System-2 model ({s2_model})"))
    if s1 and s1.probability >= 0.5:
        findings.append(Finding(id="", module="ml", title="Wording resembles known scam messages",
                                severity=Severity.LOW,
                                description=f"System-1 language model: {s1.probability:.0%} similarity to scam/spam "
                                            f"wording (key terms: {', '.join(s1.details.get('top_terms', [])[:4])}).",
                                evidence=s1.details | {"probability": s1.probability}, source=s1.model,
                                limitations="Language similarity is not proof of fraud."))
    for sr in sub_reports:
        if sr.risk_level != RiskLevel.LOW:
            sev = {RiskLevel.CONFIRMED: Severity.CRITICAL, RiskLevel.HIGH: Severity.HIGH,
                   RiskLevel.SUSPICIOUS: Severity.MEDIUM}.get(sr.risk_level, Severity.LOW)
            findings.append(Finding(id="", module="url", title=f"Link {sr.target.registered_domain if sr.target else sr.input} "
                                    f"assessed as {sr.risk_level.value.replace('_', ' ')}", severity=sev,
                                    description=f"Linked report {sr.report_id}: " +
                                                "; ".join(f.title for f in sr.findings[:3]),
                                    evidence={"linked_report": sr.report_id, "url": sr.input,
                                              "risk_score": sr.risk_score}, source="Vigil URL investigation"))

    # Near-duplicate wording with earlier message reports (campaign detection)
    sh = _shingles(text)
    similar = []
    for rid2, body in store.recent_messages(300):
        if rid2 == rid:
            continue
        o = _shingles(body)
        j = len(sh & o) / max(len(sh | o), 1)
        if j >= 0.45:
            similar.append((rid2, round(j, 2)))

    ran = [c for c in checks if c.status != "skipped"]
    coverage = sum(c.status == "ok" for c in ran) / max(len(ran), 1)
    findings = _number(findings)
    level, score, conf, trail = risk.classify_message(rules, s2, s1, [r.risk_level for r in sub_reports], coverage)
    checks.append(CheckStatus(name="risk_engine", status="ok", detail=" | ".join(trail)[:500]))

    if s2 and s2.get("explanation"):
        expl = Explanation(summary=f"{s2['explanation']} {LEVEL_ADVICE[level]}",
                           key_points=[f"[{f.id}] {f.title} — {f.description}" for f in findings
                                       if f.severity != Severity.INFO][:6], generated_by=s2_model)
    else:
        expl = _template_explanation(level, findings, text[:200])
        if fast_path:
            expl.generated_by = "system1:fast-path"     # confidently benign: System-2 was not needed
    report = Report(report_id=rid, input_type="message", input=text, analyzed_at=now(), risk_level=level,
                    risk_score=score, confidence=conf, findings=findings, checks=checks, indicators=inds,
                    model_scores=[m for m in [s1] if m] + ([] if not s2 else [
                        ModelScore(
                            model=s2_model, label=s2["verdict"],
                            probability=s2["p_unsafe"] if s2.get("p_unsafe") is not None else
                            (1.0 if s2["verdict"] == "scam" else 0.5 if s2["verdict"] == "suspicious" else 0.0),
                            details={k: s2.get(k) for k in ("scam_type", "impersonated_entity", "tactics",
                                                            "requested_action", "verdict_probs")})]),
                    linked_reports=[r.report_id for r in sub_reports], explanation=expl,
                    recommendations=[LEVEL_ADVICE[level]] + (["Never share OTPs, PINs or passwords — no genuine bank or "
                                                              "company asks for them."] if level != RiskLevel.LOW else []),
                    limitations=BASE_LIMITATIONS[:1] + ["Message sender identity cannot be verified from text alone."])
    ind_list = ([("domain", reg_domain(d)) for d in inds.domains] + [("email", e.lower()) for e in inds.emails] +
                [("phone", p[-10:]) for p in inds.phones] + [("upi", u.lower()) for u in inds.upi_ids])
    if s2 and s2.get("impersonated_entity") and s2.get("verdict") != "legitimate":
        ind_list.append(("entity", s2["impersonated_entity"].lower().strip()))
    return _finalize(report, ind_list, {r: [f"similar_wording:{j}"] for r, j in similar}, owner_id)


def analyze(text: str, typ: str = "auto", owner_id: str | None = None) -> Report:
    t = detect_type(text) if typ == "auto" else typ
    return analyze_message(text, owner_id) if t == "message" else analyze_url(text.strip(), t, owner_id=owner_id)
