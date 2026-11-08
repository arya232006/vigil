"""Deterministic, explainable risk engine. The AI never decides the class on its own.

Classes (from the brief):
  confirmed_malicious - authoritative threat intelligence match (or a linked URL that is confirmed)
  high_risk           - multiple significant indicators
  suspicious          - one or more indicators need investigation
  low_risk            - no significant indicators in the checks that ran
  inconclusive        - not enough checks could run
"""
from __future__ import annotations

from .schemas import Finding, ModelScore, RiskLevel, Severity

PRESSURE_TACTICS = {"urgency", "fear_threat", "reward_lure", "authority_impersonation", "secrecy",
                    "instruction_injection"}
POINTS = {Severity.CRITICAL: 45, Severity.HIGH: 22, Severity.MEDIUM: 9, Severity.LOW: 3, Severity.INFO: 0}
# Findings about the site's own hygiene (headers, cookies) don't make a site malicious.
HYGIENE_MODULES = {"headers"}


def _score(findings: list[Finding]) -> int:
    pts = 0
    for f in findings:
        p = POINTS[f.severity]
        if f.module in HYGIENE_MODULES:
            p = min(p, 3)
        pts += p
    return pts


def classify_url(findings: list[Finding], url_ml: ModelScore | None, coverage: float, tranco_rank: int | None,
                 tls_verdict: str | None) -> tuple[RiskLevel, int, float, list[str]]:
    """Returns (level, score 0-100, confidence 0-1, reasoning trail)."""
    trail: list[str] = []
    threat = [f for f in findings if f.module not in HYGIENE_MODULES]
    crit = [f for f in threat if f.severity == Severity.CRITICAL]
    high = [f for f in threat if f.severity == Severity.HIGH]
    med = [f for f in threat if f.severity == Severity.MEDIUM]
    pts = _score(findings)

    ml_p = url_ml.probability if url_ml else None
    if ml_p is not None:
        ml_pts = int(round(max(0.0, ml_p - 0.3) / 0.7 * 25))       # 0..25 points above p=0.3
        if tranco_rank and tranco_rank <= 20_000:
            ml_pts = min(ml_pts, 4)
            trail.append(f"popular domain (Tranco #{tranco_rank}): model weight reduced")
        pts += ml_pts
        trail.append(f"System-1 URL model p(phishing)={ml_p:.2f} → +{ml_pts}")
    if tranco_rank and tranco_rank <= 20_000 and not crit:
        pts = max(0, pts - 10)
    score = max(0, min(100, pts))

    ti = [f for f in crit if f.module == "threat_intel"]
    if ti:
        level = RiskLevel.CONFIRMED
        trail.append("authoritative threat-intelligence match → confirmed_malicious")
    elif crit or len(high) >= 2 or (high and (ml_p or 0) >= 0.7) or score >= 60:
        level = RiskLevel.HIGH
        trail.append(f"{len(crit)} critical / {len(high)} high indicators, score {score} → high_risk")
    elif high or len(med) >= 2 or (ml_p or 0) >= 0.6 or score >= 22:
        level = RiskLevel.SUSPICIOUS
        trail.append(f"{len(high)} high / {len(med)} medium indicators, score {score} → suspicious")
    elif coverage < 0.5:
        level = RiskLevel.INCONCLUSIVE
        trail.append(f"only {coverage:.0%} of checks completed → inconclusive")
    else:
        level = RiskLevel.LOW
        trail.append("no significant indicators in completed checks → low_risk (not a guarantee of safety)")

    # Confidence = evidence coverage, nudged by agreement between independent signals.
    conf = coverage
    if level in (RiskLevel.CONFIRMED,):
        conf = max(conf, 0.95)
    elif ml_p is not None:
        agree = (ml_p >= 0.5) == (level in (RiskLevel.HIGH, RiskLevel.SUSPICIOUS))
        conf = conf * (1.0 if agree else 0.85)
    return level, score, round(min(conf, 0.99), 2), trail


def classify_message(rule_tactics: dict[str, str], s2: dict | None, s1: ModelScore | None,
                     linked_levels: list[RiskLevel], coverage: float) -> tuple[RiskLevel, int, float, list[str]]:
    from .checks.message import HARMFUL
    trail: list[str] = []
    s2_tactics = set(s2.get("tactics", [])) if s2 else set()
    grounded = {e.get("tactic") for e in (s2 or {}).get("evidence", [])}
    harmful_rules = set(rule_tactics) & HARMFUL
    harmful_s2 = (s2_tactics & grounded) & HARMFUL
    pressure = (set(rule_tactics) | s2_tactics) & {"urgency", "fear_threat", "reward_lure", "authority_impersonation",
                                                   "secrecy", "instruction_injection"}
    s2_verdict = (s2 or {}).get("verdict")
    s1_p = s1.probability if s1 else 0.0

    score = 0
    score += 25 * len(harmful_rules | harmful_s2)
    score += 8 * len(pressure)
    score += {"scam": 25, "suspicious": 10}.get(s2_verdict, 0)
    score += int(10 * s1_p)
    if "instruction_injection" in rule_tactics:
        score += 20
    score = min(100, score)
    trail.append(f"rule tactics={sorted(rule_tactics)}; S2 verdict={s2_verdict} tactics={sorted(s2_tactics)}; "
                 f"S1 p={s1_p:.2f}")

    if RiskLevel.CONFIRMED in linked_levels:
        level = RiskLevel.CONFIRMED
        trail.append("contains a link confirmed malicious by threat intelligence")
    elif RiskLevel.HIGH in linked_levels and (harmful_rules or harmful_s2 or s2_verdict == "scam"):
        level = RiskLevel.HIGH
        trail.append("high-risk link combined with scam behaviour")
    elif ((harmful_rules and (pressure or s2_verdict == "scam") and s2_verdict != "legitimate")
          or (harmful_s2 and s2_verdict == "scam" and (pressure or harmful_rules))):
        level = RiskLevel.HIGH
        trail.append("harmful request + manipulation tactics (evidence-backed)")
    elif "instruction_injection" in rule_tactics:
        level = RiskLevel.HIGH
        trail.append("message attempts to manipulate AI analysis")
    elif s2_verdict == "scam" and (
            (s1_p >= 0.8 and len(grounded | set(rule_tactics)) >= 2)
            or (len(grounded) >= 2 and (grounded | set(rule_tactics)) & PRESSURE_TACTICS)):
        # Tuned on the validation set only: an AI scam verdict escalates when it is corroborated, either by
        # System-1 plus >=2 evidence-backed tactics, or by >=2 quoted tactics that include manipulation.
        level = RiskLevel.HIGH
        trail.append("AI scam verdict corroborated by independent evidence (>=2 evidence-backed tactics)")
    elif harmful_rules or harmful_s2 or s2_verdict == "scam" or RiskLevel.HIGH in linked_levels \
            or RiskLevel.SUSPICIOUS in linked_levels:
        level = RiskLevel.SUSPICIOUS
        trail.append("one significant indicator; needs verification")
    elif s2_verdict == "suspicious" or (s1_p >= 0.8 and pressure):
        level = RiskLevel.SUSPICIOUS
        trail.append("scam-like language without a harmful request (language alone is not proof)")
    elif s2 is None and coverage < 0.5:
        level = RiskLevel.INCONCLUSIVE
        trail.append("AI analysis unavailable and too few checks")
    else:
        level = RiskLevel.LOW
        if s1_p >= 0.5:
            trail.append("System-1 flagged wording, but no harmful request or deception evidence → low_risk")
        else:
            trail.append("no harmful request, deception or malicious links found")
    conf = coverage
    if s2 and s2_verdict and ((s2_verdict == "scam") == (level in (RiskLevel.HIGH, RiskLevel.CONFIRMED))):
        conf = min(0.99, conf + 0.05)
    return level, score, round(min(conf, 0.99), 2), trail
