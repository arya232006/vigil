"""Email (.eml) security checks: authentication (SPF / DKIM / DMARC + alignment), sender identity, deceptive
links, dangerous attachments, Received chain and the sender domain's DNS posture.

Every check is a pure function that returns evidence-backed `Finding`s (module "email"); only `txt_lookup`
touches the network, and only when `live_dns=True`.

Trust model (RFC 8601 §5): Authentication-Results headers can be written by anyone *before* the message reaches
the recipient's server. We trust only the topmost header (added by the receiving server) and others carrying the
same authserv-id, or - when configured - only the ids listed in EMAIL_TRUSTED_AUTHSERV_IDS.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import dns.resolver

from ..ml.url_features import BRANDS, SUSPICIOUS_TLDS, _extract, brand_match, is_ip
from ..schemas import CheckStatus, Finding, Severity
from .domain import OFFICIAL

# ---------------------------------------------------------------- reference data ------------------------------
FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "ymail.com", "rocketmail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "proton.me", "protonmail.com", "pm.me", "zohomail.com", "zohomail.in", "gmx.com", "gmx.net",
    "gmx.de", "mail.com", "yandex.com", "yandex.ru", "mail.ru", "tutanota.com", "tuta.io", "rediffmail.com",
    "qq.com", "163.com", "126.com", "inbox.com", "fastmail.com", "hey.com", "duck.com",
}
# Official sending domains missing from checks/domain.py OFFICIAL (brands in BRANDS without an entry, plus
# well-known transactional domains of brands that are listed).
EXTRA_OFFICIAL = {
    "outlook": ["outlook.com", "microsoft.com"], "office365": ["microsoft.com", "office365.com", "office.com"],
    "microsoft": ["office.com", "microsoft365.com"], "twitter": ["twitter.com", "x.com"],
    "telegram": ["telegram.org"], "ups": ["ups.com"], "usps": ["usps.com", "usps.gov"], "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "gpay": ["google.com"], "google": ["youtube.com"], "bhim": ["npci.org.in", "bhimupi.org.in"],
    "npci": ["npci.org.in"], "myntra": ["myntra.com"], "aadhaar": ["uidai.gov.in"],
    "yono": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"], "facebook": ["facebookmail.com", "meta.com"], "instagram": ["facebookmail.com"],
    "whatsapp": ["facebookmail.com"], "hdfc": ["hdfcbank.net", "hdfc.bank.in"],
    "hdfcbank": ["hdfcbank.net", "hdfc.bank.in"], "icici": ["icici.bank.in"], "icicibank": ["icici.bank.in"],
    "axisbank": ["axis.bank.in"], "kotak": ["kotak.bank.in", "kotak.com"], "amazon": ["amazon.co.uk", "amazon.de"],
    "apple": ["icloud.com"], "paypal": ["paypal.co.uk", "paypal.in"], "linkedin": ["linkedin.cn"],
}
# Email service providers' click trackers and mail-security link rewriters: a mismatch between the visible text
# and one of these hosts is normal for newsletters (the final destination is simply hidden).
TRACKERS = {
    "list-manage.com", "mailchimp.com", "mcusercontent.com", "sendgrid.net", "hubspotlinks.com", "hubspot.com",
    "mandrillapp.com", "mailgun.org", "mailgun.net", "sparkpostmail.com", "awstrack.me", "rs6.net",
    "exacttarget.com", "createsend.com", "createsend1.com", "cmail19.com", "cmail20.com", "klclick.com",
    "klclick1.com", "klaviyo.com", "mailjet.com", "sendibt3.com", "brevo.com", "sendinblue.com", "mkt.com",
    "constantcontact.com", "postmarkapp.com", "urldefense.com", "urldefense.proofpoint.com", "mimecast.com",
    "mimecastprotect.com", "safe-links.com", "substack.com", "beehiiv.com", "convertkit-mail.com", "ck.page",
}
EXEC_RX = re.compile(r"\b(ceo|cfo|coo|cto|ciso|managing director|executive director|director|president|"
                     r"chairman|chairperson|founder|co-founder|vice president|vp|head of|owner|principal|"
                     r"partner)\b", re.I)
ORG_RX = re.compile(r"\b(support|team|help ?desk|service desk|it|hr|human resources|payroll|finance|accounts?|"
                    r"billing|admin|administrator|security|customer care|customer service|bank|department|dept|"
                    r"ltd|limited|pvt|inc|llc|corp|corporation|company|official|notifications?|alerts?|"
                    r"no-?reply|helpline|government|ministry)\b", re.I)
EMAIL_RX = re.compile(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
DOMAIN_TOKEN_RX = re.compile(r"(?i)(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b")
URLISH_RX = re.compile(r"(?i)^(?:(?:https?|hxxps?)://)?(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z]{2,24}(?::\d+)?(?:[/?#]\S*)?$")
# Brand tokens that are also common personal names: only a claim when the display name is just the brand or
# adds organisational context ("Chase Bank", "BHIM UPI"), not "Chase Smith" / "Bhim Singh".
AMBIGUOUS_BRANDS = {"bhim", "kotak", "chase", "apple", "jio", "steam", "ups", "adobe", "amazon"}
BRAND_CONTEXT_RX = re.compile(r"\b(bank|banking|team|support|alerts?|service|services|account|accounts|official|"
                              r"customer|care|security|notification|notifications|india|pay|payments?|upi|id|"
                              r"mahindra|card|cards|online|help|store|prime|update|billing|verify|inc|ltd)\b", re.I)
COMMON_TLDS = SUSPICIOUS_TLDS | {"com", "net", "org", "in", "io", "co", "uk", "us", "gov", "edu", "biz", "me",
                                 "app", "ai", "dev", "de", "fr", "au", "ca", "sg", "ae", "bank", "page"}
EXTRA_SUFFIXES = ("bank.in",)                 # restricted registries missing from the bundled public-suffix list

EXEC_EXT = {"exe", "scr", "com", "pif", "cpl", "msi", "dll", "js", "jse", "vbs", "vbe", "wsf", "wsh", "bat",
            "cmd", "ps1", "jar", "hta", "lnk", "reg", "apk", "msc", "appx", "msix", "url"}
CONTAINER_EXT = {"iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "ace", "cab", "arj"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "one"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png",
             "gif", "mp3", "mp4", "odt"}
EXT_FAMILY = {"pdf": "pdf", "doc": "ole", "xls": "ole", "ppt": "ole", "msi": "ole", "msg": "ole",
              **{e: "zip" for e in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "zip", "jar", "apk", "odt",
                                    "ods", "epub", "xlam", "appx", "msix")},
              **{e: "exe" for e in ("exe", "dll", "scr", "com", "cpl", "sys")},
              **{e: "html" for e in ("html", "htm", "shtml", "xhtml", "hta")}, "svg": "svg",
              "jpg": "jpeg", "jpeg": "jpeg", "png": "png", "gif": "gif", "rar": "rar", "7z": "7z", "iso": "iso"}
EXPECTED_CT = {
    "pdf": {"application/pdf"}, "doc": {"application/msword"}, "xls": {"application/vnd.ms-excel"},
    "ppt": {"application/vnd.ms-powerpoint"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "jpg": {"image/jpeg", "image/jpg", "image/pjpeg"}, "jpeg": {"image/jpeg", "image/jpg", "image/pjpeg"},
    "png": {"image/png"}, "gif": {"image/gif"}, "txt": {"text/plain"}, "svg": {"image/svg+xml"},
    "csv": {"text/csv", "text/plain", "application/vnd.ms-excel", "text/comma-separated-values"},
    "html": {"text/html"}, "htm": {"text/html"}, "zip": {"application/zip", "application/x-zip-compressed",
                                                         "application/x-zip"},
    "exe": {"application/x-msdownload", "application/x-dosexec", "application/vnd.microsoft.portable-executable",
            "application/x-msdos-program", "application/exe", "application/x-exe"},
}
GENERIC_CT = {"application/octet-stream", "application/x-download", "application/force-download",
              "binary/octet-stream", "application/unknown", "application/binary", "application/x-unknown"}
SAFE_LOOKING_CT = ("application/pdf", "image/", "text/plain", "application/msword", "application/vnd.ms-excel",
                   "application/vnd.openxmlformats-officedocument")

HDR_LIMIT = 50                                   # max occurrences of a repeated header we inspect
MAX_ATTACHMENTS = 30
_DNS_POOL = ThreadPoolExecutor(4)


def org_domain(host: str) -> str:
    """Organisational (registered) domain used for DMARC-style relaxed alignment."""
    host = (host or "").lower().strip(".[] ")
    for sfx in EXTRA_SUFFIXES:
        if host.endswith("." + sfx) and host.count(".") >= sfx.count(".") + 1:
            return ".".join(host.split(".")[-(sfx.count(".") + 2):])
    return _extract(host).top_domain_under_public_suffix or host


def official_domains(brand: str) -> list[str]:
    return list(dict.fromkeys(OFFICIAL.get(brand, []) + EXTRA_OFFICIAL.get(brand, [])))


ALL_OFFICIAL = {d for b in set(OFFICIAL) | set(EXTRA_OFFICIAL) for d in official_domains(b)}


def _under(domain: str, parents) -> bool:
    d = (domain or "").lower().strip(".")
    return any(d == p or d.endswith("." + p) for p in parents)


def is_official(domain: str, brand: str | None = None) -> bool:
    """True if `domain` is (a subdomain of) an official domain of `brand` (or of any known brand)."""
    if org_domain(domain) in FREE_MAIL:           # a consumer mailbox is never a brand's official sender
        return False
    return _under(domain, official_domains(brand) if brand else ALL_OFFICIAL)


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().strip(".[] ") if "@" in (addr or "") else ""


def _ip_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _f(title: str, sev: Severity, desc: str, evidence: dict, source: str, category: str, impact: str | None = None,
       rec: str | None = None, lim: str | None = None) -> Finding:
    """`evidence.category` drives the email risk combination (auth_failure / identity_spoof escalate)."""
    return Finding(id="", module="email", title=title, severity=sev, description=desc,
                   evidence={"category": category, **evidence}, source=source, impact=impact, recommendation=rec,
                   limitations=lim)


# ---------------------------------------------------------------- parsing -------------------------------------
@dataclass
class Parsed:
    msg: EmailMessage
    raw: str
    from_headers: int = 0
    from_addrs: list[tuple[str, str]] = field(default_factory=list)       # (display name, address)
    from_defects: list[str] = field(default_factory=list)
    from_display: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    sender: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received: list[str] = field(default_factory=list)                   # top (newest) → bottom (oldest)
    auth_results: list[str] = field(default_factory=list)
    arc_auth_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signatures: list[dict[str, str]] = field(default_factory=list)


def _clean(v: str) -> str:
    return re.sub(r"\s+", " ", v or "").strip()


def _all(msg: EmailMessage, name: str) -> list[str]:
    try:
        vals = [str(v) for v in (msg.get_all(name) or [])]
    except Exception:                     # malformed header the structured parser cannot handle
        vals = [v for k, v in msg.raw_items() if k.lower() == name.lower()]
    return [_clean(v) for v in vals[:HDR_LIMIT]]


def _addresses(msg: EmailMessage, name: str) -> tuple[list[tuple[str, str]], list[str], int]:
    out: list[tuple[str, str]] = []
    defects: list[str] = []
    try:
        hdrs = msg.get_all(name) or []
    except Exception:
        hdrs = [v for k, v in msg.raw_items() if k.lower() == name.lower()]
    for h in hdrs[:HDR_LIMIT]:
        try:
            out += [(_clean(a.display_name), (a.addr_spec or "").strip()) for a in h.addresses]
            defects += [f"{type(d).__name__}: {d}" for d in getattr(h, "defects", [])]
        except Exception:
            out += [(_clean(n), a.strip()) for n, a in getaddresses([str(h)])]
    out = [(n, a) for n, a in out if "@" in a and a != "<>"]
    return out, defects, len(hdrs)


def parse_dkim_signature(value: str) -> dict[str, str]:
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            tags[k] = re.sub(r"\s+", "", v) if k in ("b", "bh", "h") else v.strip()
    return tags


def parse(raw: str) -> Parsed:
    msg = message_from_string(raw, policy=policy.default)
    p = Parsed(msg=msg, raw=raw)
    p.from_addrs, p.from_defects, p.from_headers = _addresses(msg, "From")
    if p.from_addrs:
        p.from_display, p.from_addr = p.from_addrs[0]
        p.from_domain = _domain_of(p.from_addr)
    p.reply_to = [a.lower() for _, a in _addresses(msg, "Reply-To")[0]]
    rp = (_all(msg, "Return-Path") or [""])[0]
    m = re.search(r"<\s*([^<>\s]*)\s*>", rp)
    p.return_path = (m.group(1) if m else rp).strip().lower()
    p.sender = next((a.lower() for _, a in _addresses(msg, "Sender")[0]), "")
    p.subject = (_all(msg, "Subject") or [""])[0][:500]
    p.date = (_all(msg, "Date") or [""])[0][:100]
    p.message_id = (_all(msg, "Message-ID") or [""])[0][:300]
    p.received = _all(msg, "Received")
    p.auth_results = _all(msg, "Authentication-Results")
    p.arc_auth_results = _all(msg, "ARC-Authentication-Results")
    p.received_spf = _all(msg, "Received-SPF")
    p.dkim_signatures = [parse_dkim_signature(v) for v in _all(msg, "DKIM-Signature")]
    return p


# ---------------------------------------------------------------- authentication ------------------------------
_COMMENT = re.compile(r"\([^()]*\)")


def _strip_comments(s: str) -> str:
    prev = None
    while prev != s:
        prev, s = s, _COMMENT.sub(" ", s)
    return s


def parse_auth_results(value: str) -> dict:
    """RFC 8601 Authentication-Results (also ARC-Authentication-Results, whose `i=N;` prefix is recorded)."""
    v = _clean(value)
    instance = None
    m = re.match(r"i\s*=\s*(\d+)\s*;", v)
    if m:
        instance, v = int(m.group(1)), v[m.end():]
    comments = {mm.group(1).lower(): mm.group(2) for mm in
                re.finditer(r"\b([a-z0-9_-]+)\s*=\s*[a-z0-9_-]+\s*\(([^()]*)\)", v, re.I)}
    parts = [x.strip() for x in _strip_comments(v).split(";")]
    head = parts[0].split()
    out = {"authserv_id": head[0].lower() if head else "", "instance": instance, "results": []}
    for part in parts[1:]:
        mm = re.match(r"([a-z0-9_.-]+)\s*=\s*([a-z0-9_-]+)", part, re.I)
        if not mm:
            continue
        props = {k.lower(): val.strip('"') for k, val in
                 re.findall(r"([a-z]+\.[a-z0-9_.-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)", part, re.I)}
        method = mm.group(1).lower()
        out["results"].append({"method": method, "result": mm.group(2).lower(), "props": props,
                               "comment": comments.get(method, "")[:200]})
    return out


def _trusted_ids() -> set[str]:
    return {x.strip().lower() for x in os.getenv("EMAIL_TRUSTED_AUTHSERV_IDS", "").split(",") if x.strip()}


def select_auth_results(p: Parsed, trusted_ids: set[str] | None = None) -> tuple[list[dict], str, dict]:
    """(results, source description, evidence about all A-R headers). Per method, the topmost result wins."""
    trusted_ids = _trusted_ids() if trusted_ids is None else trusted_ids
    parsed = [parse_auth_results(v) for v in p.auth_results]
    ids = [a["authserv_id"] for a in parsed]
    ev = {"authentication_results_headers": len(parsed), "authserv_ids": list(dict.fromkeys(ids))[:6]}
    if trusted_ids:
        chosen = [a for a in parsed if a["authserv_id"] in trusted_ids]
        src = f"Authentication-Results from trusted authserv-id(s) {sorted(trusted_ids)}"
    elif parsed:
        chosen = [a for a in parsed if a["authserv_id"] == parsed[0]["authserv_id"]]
        src = f"topmost Authentication-Results header (added by {parsed[0]['authserv_id'] or 'unknown'})"
        if len(chosen) < len(parsed):
            ev["ignored_headers_from_other_servers"] = len(parsed) - len(chosen)
    else:
        chosen = []
    if not chosen and p.arc_auth_results:
        arcs = sorted((parse_auth_results(v) for v in p.arc_auth_results), key=lambda a: -(a["instance"] or 0))
        chosen = arcs[:1]
        src = f"ARC-Authentication-Results i={arcs[0]['instance']} ({arcs[0]['authserv_id']}, intermediary's view)"
    if not chosen:
        return [], "", ev
    results, seen = [], set()
    for a in chosen:
        for r in a["results"]:
            if r["method"] == "dkim" or r["method"] not in seen:     # several DKIM signatures may be reported
                results.append(r | {"authserv_id": a["authserv_id"]})
                seen.add(r["method"])
    return results, src, ev


def _result_domain(r: dict, *props: str) -> str:
    for k in props:
        v = r["props"].get(k, "")
        if v:
            return _domain_of(v) if "@" in v else v.lower().strip(".")
    return ""


def auth_findings(p: Parsed, trusted_ids: set[str] | None = None) -> tuple[dict, list[Finding]]:
    """SPF / DKIM / DMARC verdicts recorded by the receiving server + DMARC-style relaxed alignment."""
    findings: list[Finding] = []
    results, src, ev = select_auth_results(p, trusted_ids)
    summary = {"spf": None, "dkim": None, "dmarc": None, "arc": None, "spf_domain": None, "dkim_domains": [],
               "spf_aligned": None, "dkim_aligned": None, "authserv_id": None, "source": src or None}
    by = {}
    for r in results:
        by.setdefault(r["method"], []).append(r)
    spf_src = src
    if "spf" not in by and p.received_spf:                       # fall back to the Received-SPF trace header
        rs = p.received_spf[0]
        m = re.match(r"\s*([a-z]+)", rs, re.I)
        env = re.search(r"envelope-from\s*=\s*\"?([^\";\s]+)", rs, re.I)
        if m:
            by["spf"] = [{"method": "spf", "result": m.group(1).lower(), "comment": "",
                          "props": {"smtp.mailfrom": env.group(1) if env else ""}}]
            spf_src = (src + " + " if src else "") + "topmost Received-SPF header"
    if not by:
        findings.append(_f(
            "No authentication results in the headers", Severity.LOW,
            "The email carries no Authentication-Results, ARC or Received-SPF header, so SPF / DKIM / DMARC "
            "verdicts from the receiving server cannot be checked.", ev, "Header analysis (RFC 8601)", "auth_unknown",
            lim="Common when an .eml is exported without full headers or the message never crossed a server that "
                "records authentication results. Use your mail client's 'Show original' to export the full source."))
        return summary, findings

    from_org = org_domain(p.from_domain)
    summary["authserv_id"] = (results[0]["authserv_id"] if results else None)
    spf = by.get("spf", [None])[0]
    if spf:
        summary["spf"] = spf["result"]
        summary["spf_domain"] = (_result_domain(spf, "smtp.mailfrom", "smtp.helo") or _domain_of(p.return_path)
                                 or None)
        summary["spf_aligned"] = bool(spf["result"] == "pass" and summary["spf_domain"] and from_org
                                      and org_domain(summary["spf_domain"]) == from_org)
    dk = by.get("dkim", [])
    if dk:
        passing = [r for r in dk if r["result"] == "pass"]
        summary["dkim"] = "pass" if passing else dk[0]["result"]
        summary["dkim_domains"] = list(dict.fromkeys(
            d for d in (_result_domain(r, "header.d", "header.i") for r in passing) if d))
        summary["dkim_aligned"] = bool(from_org and any(org_domain(d) == from_org for d in summary["dkim_domains"]))
    elif p.dkim_signatures:
        summary["dkim"] = "not_reported"
    dmarc = by.get("dmarc", [None])[0]
    if dmarc:
        summary["dmarc"] = dmarc["result"]
    arc = by.get("arc", [None])[0]
    if arc:
        summary["arc"] = arc["result"]

    detail = {**ev, "spf": summary["spf"], "spf_domain": summary["spf_domain"], "dkim": summary["dkim"],
              "dkim_domains": summary["dkim_domains"], "dmarc": summary["dmarc"], "arc": summary["arc"],
              "from_domain": p.from_domain, "spf_aligned": summary["spf_aligned"],
              "dkim_aligned": summary["dkim_aligned"],
              "dkim_signature_domains": [s.get("d", "") for s in p.dkim_signatures][:5]}
    if dmarc and dmarc.get("comment"):
        detail["dmarc_comment"] = dmarc["comment"]
    hdr_lim = ("Authentication results are taken from headers. Headers added before the message reached the "
               "receiving server can be forged, so only the receiving server's own header is trusted.")
    source = f"{spf_src or src} (RFC 7208 SPF / RFC 6376 DKIM / RFC 7489 DMARC)"
    who = p.from_domain or "the sender domain"

    if summary["dmarc"] == "fail":
        forwarded = summary["arc"] == "pass"
        findings.append(_f(
            f"DMARC authentication failed for {who}", Severity.MEDIUM if forwarded else Severity.HIGH,
            f"The receiving server reported dmarc=fail: neither SPF nor DKIM produced a pass aligned with the From "
            f"domain {who}, so nothing proves this email was really sent by {who}."
            + (" An ARC seal reports the original authentication passed before forwarding, which can explain the "
               "failure." if forwarded else ""), detail, source, "auth_failure",
            "Spoofed sender addresses are the core of phishing and business-email-compromise attacks.",
            "Treat the sender as unverified: do not act on the request without confirming via an official channel.",
            hdr_lim))
    elif summary["dmarc"] in ("none", "temperror", "permerror", "neutral", "policy"):
        findings.append(_f(
            f"No conclusive DMARC verdict for {who} (dmarc={summary['dmarc']})", Severity.LOW,
            "The receiving server could not reach a DMARC pass for the From domain; the sender identity is not "
            "verified.", detail, source, "auth_weak", lim=hdr_lim))
    elif summary["dmarc"] is None and (summary["spf"] or summary["dkim"]):
        aligned = summary["spf_aligned"] or summary["dkim_aligned"]
        if not aligned:
            findings.append(_f(
                f"No aligned SPF/DKIM pass for {who} (DMARC would fail)", Severity.MEDIUM,
                f"The receiving server did not evaluate DMARC. Evaluating its SPF/DKIM results ourselves, none passed "
                f"for a domain aligned with the From domain {who} (RFC 7489 relaxed alignment).", detail, source,
                "auth_failure", "The visible sender address is not authenticated.",
                "Verify the sender through an official channel before acting.", hdr_lim))

    superseded = summary["dmarc"] == "pass"     # an aligned pass makes individual SPF/DKIM misses irrelevant
    if superseded:
        pass
    elif summary["spf"] == "fail":
        findings.append(_f(
            f"SPF failed: sending server not authorised by {summary['spf_domain'] or 'the envelope domain'}",
            Severity.MEDIUM, "The SPF record of the envelope-sender domain does not list the server that delivered "
            "this email (hard fail).", detail, source, "auth_failure", lim=hdr_lim))
    elif summary["spf"] in ("softfail", "neutral", "none", "permerror", "temperror"):
        findings.append(_f(
            f"SPF did not pass (spf={summary['spf']})", Severity.LOW,
            {"softfail": "The envelope-sender domain marks the delivering server as 'probably not authorised' (~all).",
             "neutral": "The envelope-sender domain makes no assertion about the delivering server.",
             "none": "The envelope-sender domain publishes no SPF record.",
             }.get(summary["spf"], "SPF evaluation errored, so the delivering server is not verified."),
            detail, source, "auth_weak", lim=hdr_lim))
    if superseded:
        pass
    elif summary["dkim"] == "fail":
        findings.append(_f(
            "DKIM signature failed verification", Severity.MEDIUM,
            "A DKIM signature is present but the receiving server could not verify it: the message was altered "
            "after signing or the signature is forged.", detail, source, "auth_failure", lim=hdr_lim))
    elif summary["dkim"] in ("none", "neutral", "permerror", "temperror", "policy"):
        findings.append(_f(
            f"Message is not validly DKIM-signed (dkim={summary['dkim']})", Severity.LOW,
            "No valid cryptographic signature ties this message to the sender's domain.", detail, source,
            "auth_weak", lim=hdr_lim))
    elif summary["dkim"] == "pass" and not summary["dkim_aligned"] and summary["dmarc"] != "pass":
        findings.append(_f(
            f"DKIM signed by a different domain ({', '.join(summary['dkim_domains'][:2]) or 'unknown'})",
            Severity.LOW, f"The valid DKIM signature belongs to a domain that is not aligned with the From domain "
            f"{who}. Common for bulk-mail services, but it does not authenticate the visible sender.", detail,
            source, "auth_alignment", lim=hdr_lim))

    if summary["dmarc"] == "pass" or (summary["dmarc"] is None and (summary["spf_aligned"] or summary["dkim_aligned"])):
        findings.append(_f(
            f"Sender domain authenticated ({who})", Severity.INFO,
            f"{'DMARC passed' if summary['dmarc'] == 'pass' else 'An aligned SPF/DKIM pass was recorded'} for "
            f"{who}: the message was authorised by that domain. This does NOT prove the domain is trustworthy - "
            "attackers routinely authenticate their own look-alike domains.", detail, source, "auth_pass",
            lim=hdr_lim))
    return summary, findings


# ---------------------------------------------------------------- DKIM body hash (local, offline) ------------
def split_raw(raw: str) -> tuple[str, str]:
    m = re.search(r"\r?\n\r?\n", raw)
    return (raw[:m.start()], raw[m.end():]) if m else (raw, "")


def dkim_body_hash(body: str, canon: str = "simple", algo: str = "sha256", length: int | None = None) -> str:
    """RFC 6376 §3.4.3/§3.4.4 body canonicalisation + hash (base64), as found in the bh= tag."""
    lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if canon == "relaxed":
        lines = [re.sub(r"[ \t]+", " ", ln).rstrip(" ") for ln in lines]
    while lines and lines[-1] == "":
        lines.pop()
    data = ("\r\n".join(lines) + "\r\n") if lines else ("" if canon == "relaxed" else "\r\n")
    b = data.encode("utf-8", "surrogateescape")
    if length is not None:
        b = b[:length]
    h = hashlib.sha1 if algo.endswith("sha1") else hashlib.sha256
    return base64.b64encode(h(b).digest()).decode()


def dkim_body_findings(p: Parsed) -> list[Finding]:
    if not p.dkim_signatures:
        return []
    _, body = split_raw(p.raw)
    checked = []
    for s in p.dkim_signatures[:3]:
        if not s.get("bh"):
            continue
        canon = (s.get("c") or "simple/simple").lower().split("/")
        body_c = canon[1] if len(canon) > 1 else "simple"
        try:
            length = int(s["l"]) if s.get("l") else None
        except ValueError:
            length = None
        computed = dkim_body_hash(body, body_c, s.get("a", "rsa-sha256").lower(), length)
        checked.append({"d": s.get("d", ""), "s": s.get("s", ""), "canonicalization": body_c,
                        "bh_declared": s["bh"], "bh_computed": computed, "match": computed == s["bh"],
                        "l_tag": length})
    if not checked:
        return []
    lim = ("Only the body hash was recomputed; the RSA/Ed25519 signature over the headers was not verified "
           "(that needs the signer's DNS key). Copy-paste, forwarding or re-encoding of the .eml can also change "
           "the body.")
    ev = {"signatures": checked}
    if any(c["match"] for c in checked):
        d = next(c["d"] for c in checked if c["match"])
        return [_f(f"DKIM body hash verified locally (d={d})", Severity.INFO,
                   "We recomputed the canonicalised body hash and it matches the bh= value of the DKIM signature: the "
                   "body is unchanged since it was signed.", ev, "Local DKIM body-hash recomputation (RFC 6376 §3.7)",
                   "integrity", lim=lim)]
    partial = any(c["l_tag"] is not None for c in checked)
    return [_f("DKIM body hash does not match the signature", Severity.LOW,
               "The canonicalised body we computed differs from the bh= value in the DKIM signature, so the body was "
               "modified after signing (or the signature is forged)."
               + (" The signature uses an l= length limit, which lets anyone append content." if partial else ""),
               ev, "Local DKIM body-hash recomputation (RFC 6376 §3.7)", "integrity", lim=lim)]


# ---------------------------------------------------------------- DNS posture (live) --------------------------
def txt_lookup(name: str, timeout: float = 3.0) -> tuple[str, list[str]]:
    """('ok', records) | ('missing', []) for NXDOMAIN/NoAnswer | ('unavailable', []) on timeout/SERVFAIL."""
    try:
        res = dns.resolver.Resolver()
        res.lifetime = timeout
        res.timeout = timeout
        ans = res.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "missing", []
    except Exception:                          # timeout, SERVFAIL, no resolver configured...
        return "unavailable", []
    return "ok", [b"".join(r.strings).decode("utf-8", "replace") for r in ans][:20]


def _tags(rec: str) -> dict[str, str]:
    return {k.strip().lower(): v.strip() for k, v in (t.split("=", 1) for t in rec.split(";") if "=" in t)}


def dmarc_record(domain: str, lookup: Callable = txt_lookup) -> dict:
    out = {"status": "missing", "queried": [], "record": None, "policy": None, "subdomain_policy": None,
           "pct": None, "effective_policy": None}
    org = org_domain(domain)
    for name in dict.fromkeys([domain, org]):
        if not name:
            continue
        out["queried"].append(f"_dmarc.{name}")
        st, recs = lookup(f"_dmarc.{name}")
        dm = [r for r in recs if r.strip().lower().startswith("v=dmarc1")]
        if st == "unavailable":
            out["status"] = "unavailable"
            return out
        if len(dm) > 1:
            out.update(status="invalid", record=" | ".join(dm)[:400])
            return out
        if dm:
            t = _tags(dm[0])
            out.update(status="ok", record=dm[0][:400], policy=(t.get("p") or "").lower() or None,
                       subdomain_policy=(t.get("sp") or "").lower() or None, pct=t.get("pct"))
            sub_lookup = name != domain
            out["effective_policy"] = (out["subdomain_policy"] if sub_lookup and out["subdomain_policy"]
                                       else out["policy"])
            return out
    return out


def spf_record(domain: str, lookup: Callable = txt_lookup) -> dict:
    st, recs = lookup(domain)
    spf = [r for r in recs if r.strip().lower().startswith("v=spf1")]
    out = {"status": st if st == "unavailable" else ("ok" if spf else "missing"), "record": None, "all": None}
    if len(spf) > 1:
        out.update(status="invalid", record=" | ".join(spf)[:400])
    elif spf:
        m = re.search(r"(?:^|\s)([+~?-]?)all\b", spf[0], re.I)
        out.update(record=spf[0][:400], all=(m.group(1) or "+") + "all" if m else None)
    return out


def dns_findings(domain: str, live_dns: bool = True, lookup: Callable = txt_lookup
                 ) -> tuple[dict, list[Finding], list[CheckStatus]]:
    info = {"dmarc": {"status": "skipped"}, "spf": {"status": "skipped"}}
    if not domain:
        return info, [], [CheckStatus(name="dns_dmarc", status="skipped", detail="no sender domain"),
                          CheckStatus(name="dns_spf", status="skipped", detail="no sender domain")]
    if not live_dns:
        return info, [], [CheckStatus(name="dns_dmarc", status="skipped", detail="live DNS disabled"),
                          CheckStatus(name="dns_spf", status="skipped", detail="live DNS disabled")]
    fd, fs = _DNS_POOL.submit(dmarc_record, domain, lookup), _DNS_POOL.submit(spf_record, domain, lookup)
    try:
        info["dmarc"] = fd.result(timeout=10)
    except Exception:
        info["dmarc"] = {"status": "unavailable"}
    try:
        info["spf"] = fs.result(timeout=10)
    except Exception:
        info["spf"] = {"status": "unavailable"}
    d, s = info["dmarc"], info["spf"]

    def st(x):
        return "unavailable" if x["status"] == "unavailable" else "ok"
    checks = [CheckStatus(name="dns_dmarc", status=st(d), detail=f"{d['status']}: {d.get('record') or '-'}"[:300]),
              CheckStatus(name="dns_spf", status=st(s), detail=f"{s['status']}: {s.get('record') or '-'}"[:300])]
    findings: list[Finding] = []
    org = org_domain(domain)
    if org in FREE_MAIL:                 # a webmail provider's posture says nothing about this particular sender
        return info, findings, checks
    src = "Live DNS TXT lookup (dnspython, 3 s timeout)"
    if d["status"] in ("missing", "invalid"):
        findings.append(_f(
            f"No valid DMARC policy published for {org}", Severity.LOW,
            f"{' / '.join(d['queried'])} has {'no' if d['status'] == 'missing' else 'more than one (invalid)'} DMARC "
            "record, so receiving servers get no instruction to reject mail that spoofs this domain.",
            {"dns": d}, src, "posture", rec="Organisations should publish DMARC with p=quarantine or p=reject."))
    elif d["status"] == "ok" and d["effective_policy"] in (None, "none"):
        findings.append(_f(
            f"DMARC policy for {org} is monitor-only (p=none)", Severity.LOW,
            "The domain publishes DMARC but asks receivers to take no action on spoofed mail.", {"dns": d}, src,
            "posture"))
    elif d["status"] == "ok":
        findings.append(_f(
            f"DMARC policy p={d['effective_policy']} published for {org}", Severity.INFO,
            "Receivers are instructed to quarantine/reject unauthenticated mail claiming this domain.", {"dns": d},
            src, "posture"))
    if s["status"] in ("missing", "invalid"):
        findings.append(_f(
            f"No valid SPF record for {domain}", Severity.LOW,
            f"{domain} publishes {'no' if s['status'] == 'missing' else 'multiple (invalid)'} SPF record(s); any "
            "server can claim to send its mail.", {"dns": s}, src, "posture"))
    elif s["status"] == "ok" and s["all"] == "+all":
        findings.append(_f(
            f"SPF record for {domain} authorises every server (+all)", Severity.MEDIUM,
            "An SPF record ending in +all lets any server on the Internet pass SPF for this domain.", {"dns": s},
            src, "posture"))
    return info, findings, checks


# ---------------------------------------------------------------- sender identity -----------------------------
def brands_in(text: str) -> list[str]:
    low = (text or "").lower()
    tokens = re.findall(r"[a-z0-9]+", low)
    joined = "".join(tokens)
    hits = [b for b in BRANDS if b in tokens]
    hits += [b for b in BRANDS if len(b) >= 6 and b in joined and b not in hits]
    context = len(tokens) == 1 or bool(BRAND_CONTEXT_RX.search(low))
    return [b for b in hits if b not in AMBIGUOUS_BRANDS or context]


def sender_domain_findings(domain: str, rank_fn: Callable[[str], int | None] | None = None) -> list[Finding]:
    """Look-alike / brand-embedding / IDN / high-abuse-TLD checks on the From domain."""
    out: list[Finding] = []
    if not domain or is_ip(domain.strip("[]")):
        return out
    ext = _extract(domain)
    reg, label, sub = org_domain(domain), ext.domain.lower(), ext.subdomain.lower()
    if reg in FREE_MAIL or is_official(domain):
        return out
    rank = rank_fn(reg) if rank_fn else None
    src = "Edit-distance + homoglyph analysis of the sender domain"
    if "xn--" in domain:
        try:
            uni = domain.encode("ascii").decode("idna")
        except UnicodeError:
            uni = domain
        out.append(_f("Internationalised (punycode) sender domain", Severity.MEDIUM,
                      f"The sender domain displays as '{uni}'. Look-alike Unicode characters can imitate a known "
                      "domain.", {"punycode": domain, "unicode": uni}, "IDN / homograph analysis", "identity_spoof"))
    if not (rank and rank <= 50_000):              # popular real domains are not typosquats of each other
        brand, dist = brand_match(label)
        max_d = 1 if brand and len(brand) <= 5 else 2
        if brand and dist == 0 and label == brand:
            out.append(_f(f"Brand name '{brand}' on an unofficial sender domain", Severity.HIGH,
                          f"The email comes from {reg}, which uses the brand name '{brand}' but is not one of its "
                          f"official domains ({', '.join(official_domains(brand)) or 'unknown'}).",
                          {"sender_domain": domain, "registered_domain": reg, "brand": brand,
                           "official_domains": official_domains(brand)}, src, "identity_spoof",
                          "Recipients trust the familiar name and act on the request.",
                          "Do not reply or click; contact the organisation through its official website or app.",
                          "The official-domain list is curated and may be incomplete."))
        elif brand and dist <= max_d and len(label) >= 4:
            out.append(_f(f"Look-alike sender domain imitating '{brand}'", Severity.HIGH,
                          f"The sender domain {reg} differs from the brand '{brand}' by {dist} character edit(s) "
                          f"(after folding look-alike characters such as 0→o, rn→m).",
                          {"sender_domain": domain, "registered_domain": reg, "brand": brand, "edit_distance": dist,
                           "official_domains": official_domains(brand)}, src, "identity_spoof",
                          "Typosquatted sender domains are made to pass a quick glance - and can still pass SPF/DKIM.",
                          "Do not reply or click; the real organisation does not use this domain.",
                          "The official-domain list is curated and may be incomplete."))
        else:
            tokens = set(re.split(r"[-._\d]+", f"{label}.{sub}"))
            hits = [b for b in BRANDS if b in tokens or (len(b) >= 5 and (b in label or b in sub))]
            if hits:
                out.append(_f(f"Sender domain embeds the brand name '{hits[0]}'", Severity.HIGH,
                              f"The sender domain {domain} contains '{hits[0]}' but is registered as {reg}, not an "
                              f"official {hits[0]} domain.",
                              {"sender_domain": domain, "registered_domain": reg, "brands": hits,
                               "official_domains": official_domains(hits[0])}, "Brand / official-domain comparison",
                              "identity_spoof", "Impersonation of a trusted organisation.",
                              "Do not reply or click; verify through the organisation's official channel.",
                              "The official-domain list is curated and may be incomplete."))
    if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        out.append(_f(f"Sender domain on a high-abuse TLD (.{ext.suffix})", Severity.LOW,
                      f".{ext.suffix} domains are cheap and disproportionately used for abuse; this alone proves "
                      "nothing.", {"sender_domain": domain, "tld": ext.suffix}, "TLD abuse statistics (heuristic)",
                      "context"))
    return out


def identity_findings(p: Parsed, auth: dict | None = None, rank_fn: Callable | None = None) -> list[Finding]:
    """From-header integrity, display-name spoofing, look-alike domains, free-mail impersonation, Reply-To and
    Return-Path divergence."""
    auth = auth or {}
    out: list[Finding] = []
    src_hdr = "Sender-identity analysis of From / Reply-To / Return-Path headers"
    if p.from_headers > 1 or len(p.from_addrs) > 1:
        out.append(_f("Ambiguous sender: multiple From headers / addresses", Severity.HIGH,
                      f"The message has {p.from_headers} From header(s) carrying {len(p.from_addrs)} address(es). "
                      "Mail servers and mail apps may each pick a different one, a known technique to pass "
                      "authentication for one domain while displaying another.",
                      {"from_addresses": [a for _, a in p.from_addrs][:5], "from_headers": p.from_headers},
                      src_hdr + " (cf. 'Composition Kills', USENIX Security 2020)", "identity_spoof",
                      "The displayed sender may not be the authenticated one.", "Treat the sender as unverified."))
    elif p.from_defects and any("InvalidHeaderDefect" in d for d in p.from_defects):
        out.append(_f("Malformed From header", Severity.MEDIUM,
                      "The From header does not parse cleanly; malformed addresses are used to make parsers "
                      "disagree about who the sender is.", {"defects": p.from_defects[:5],
                                                            "parsed_from": p.from_addr}, src_hdr, "identity_spoof"))
    if not p.from_addr:
        out.append(_f("No valid From address", Severity.MEDIUM, "The sender address is missing or unparseable.",
                      {"from_headers": p.from_headers}, src_hdr, "identity_spoof"))
        return out

    dom, org = p.from_domain, org_domain(p.from_domain)
    free = org in FREE_MAIL
    local = p.from_addr.split("@", 1)[0]
    display = p.from_display

    # Display-name spoofing: an address / domain or a brand in the display name that the sender does not own.
    reasons, ev = [], {"display_name": display, "from_address": p.from_addr}
    shown = [e.lower() for e in EMAIL_RX.findall(display) if e.lower() != p.from_addr.lower()]
    if shown:
        reasons.append(f"the display name shows the address {shown[0]}, but the real sender is {p.from_addr}")
        ev["address_in_display_name"] = shown[0]
    else:
        doms = [d.lower() for d in DOMAIN_TOKEN_RX.findall(display)
                if _extract(d).suffix.split(".")[-1].lower() in COMMON_TLDS and org_domain(d) != org]
        if doms:
            reasons.append(f"the display name shows the domain {doms[0]}, but the email comes from {dom}")
            ev["domain_in_display_name"] = doms[0]
    claimed = brands_in(display) + [b for b in brands_in(local.replace(".", " ").replace("_", " ").replace("-", " "))
                                    if free]
    claimed = list(dict.fromkeys(claimed))
    brand_spoof = bool(claimed) and not any(is_official(dom, b) for b in claimed)
    if brand_spoof:
        offi = official_domains(claimed[0])
        reasons.append(f"it presents itself as '{claimed[0]}' but {dom} is "
                       + ("a free webmail account" if free else "not an official domain")
                       + (f" (official: {', '.join(offi)})" if offi else ""))
        ev.update(claimed_brands=claimed, official_domains=offi, sender_is_freemail=free)
    if reasons:
        out.append(_f(
            ("Display name impersonates " + (f"'{claimed[0]}'" if brand_spoof else "another sender"))
            + (" from a free webmail account" if free and brand_spoof else ""),
            Severity.HIGH, "Display-name spoofing: " + "; ".join(reasons) + ".", ev, src_hdr, "identity_spoof",
            "Most mail apps show only the display name, so recipients believe the claimed identity.",
            "Check the actual sender address; contact the organisation through its official channel.",
            "Brand detection uses a curated brand / official-domain list and may miss or over-match names."))

    out += sender_domain_findings(dom, rank_fn)

    if free and not brand_spoof:
        role = EXEC_RX.search(display) or EXEC_RX.search(local.replace(".", " ").replace("_", " "))
        org_claim = ORG_RX.search(display)
        if role:
            out.append(_f(
                f"Executive identity claimed from a free webmail account ({org})", Severity.HIGH,
                f"The display name '{display or local}' claims a senior role ('{role.group(0)}') but the message comes "
                f"from a personal {org} address. CEO-fraud / business email compromise (BEC) relies on exactly this.",
                {"display_name": display, "from_address": p.from_addr, "role_claim": role.group(0),
                 "provider": org}, src_hdr, "identity_spoof",
                "BEC is one of the costliest email frauds (fake urgent wire transfers, gift cards, payroll changes).",
                "Call the executive on a known number before making any payment or sharing data."))
        elif org_claim:
            out.append(_f(
                f"Organisation name used on a free webmail account ({org})", Severity.MEDIUM,
                f"The display name '{display}' suggests an organisation or department ('{org_claim.group(0)}'), but "
                f"the sender is a personal {org} account. Real organisations send from their own domain.",
                {"display_name": display, "from_address": p.from_addr, "claim": org_claim.group(0), "provider": org},
                src_hdr, "identity_spoof"))

    for rt in p.reply_to[:3]:
        rdom, rorg = _domain_of(rt), org_domain(_domain_of(rt))
        if not rdom or rt == p.from_addr.lower() or (rorg == org and not free):
            continue
        rfree = rorg in FREE_MAIL
        if rfree or (free and rorg == org):
            out.append(_f(
                f"Replies are diverted to a {'free webmail' if rfree else 'different'} account ({rt})", Severity.HIGH,
                f"The email is sent as {p.from_addr} but Reply-To sends your answer to {rt}. Attackers do this so "
                "the conversation continues on an account they control.",
                {"from": p.from_addr, "reply_to": rt, "reply_to_is_freemail": rfree}, src_hdr, "identity_spoof",
                "Any reply (documents, codes, payment confirmations) goes to a third party.",
                "Do not reply; write to the organisation's known address instead."))
        else:
            out.append(_f(
                f"Reply-To domain differs from the sender ({rorg} vs {org})", Severity.MEDIUM,
                f"Replies go to {rt}, a different organisation than the From domain {dom}.",
                {"from": p.from_addr, "reply_to": rt}, src_hdr, "identity_spoof",
                rec="Check that the reply address belongs to the claimed sender before replying."))

    rp_dom = _domain_of(p.return_path)
    if rp_dom and org_domain(rp_dom) != org and not auth.get("dkim_aligned"):
        out.append(_f(
            f"Envelope sender (Return-Path) domain differs: {org_domain(rp_dom)}", Severity.LOW,
            f"The bounce address {p.return_path} belongs to a different domain than the From address and no "
            "aligned DKIM signature links the two. Normal for some mailing services; also typical of spoofing.",
            {"return_path": p.return_path, "from": p.from_addr}, src_hdr, "identity_weak"))
    return out


# ---------------------------------------------------------------- body, links, HTML ---------------------------
@dataclass
class Link:
    href: str
    text: str
    host: str = ""
    reg: str = ""
    scheme: str = ""
    text_domain: str = ""
    text_reg: str = ""
    unwrapped_from: str = ""


@dataclass
class HtmlScan:
    text: str = ""
    links: list[Link] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    password_inputs: int = 0


def _unwrap(url: str) -> tuple[str, str]:
    """Undo Microsoft Safe Links / Google redirect wrapping → (real url, wrapper host or '')."""
    try:
        sp = urlsplit(url)
    except ValueError:
        return url, ""
    host = (sp.hostname or "").lower()
    q = None
    if host.endswith("safelinks.protection.outlook.com"):
        q = parse_qs(sp.query).get("url")
    elif host in ("google.com", "www.google.com") and sp.path == "/url":
        qs = parse_qs(sp.query)
        q = qs.get("q") or qs.get("url")
    if q and q[0].lower().startswith(("http://", "https://")):
        return q[0], host
    return url, ""


def _host(url: str) -> tuple[str, str]:
    try:
        sp = urlsplit(url)
        return (sp.hostname or "").lower().strip("[]"), sp.scheme.lower()
    except ValueError:
        return "", ""


def text_domain(text: str) -> str:
    """Domain the visible link text *claims*, if the text is (or contains) a URL / bare domain."""
    t = (text or "").strip().strip("<>()[].,;:!\"'")
    cand = ""
    if URLISH_RX.match(t):
        cand = re.sub(r"(?i)^(?:https?|hxxps?)://", "", t)
    else:
        m = re.search(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+", t)
        if m:
            cand = re.sub(r"(?i)^https?://", "", m.group(0))
    if not cand:
        return ""
    h = re.split(r"[/?#:]", cand, maxsplit=1)[0].lower().strip(".")
    ext = _extract(h)
    return h if (ext.suffix and ext.domain) or is_ip(h) else ""


def make_link(href: str, text: str) -> Link:
    href = re.sub(r"[\r\n\t]", "", (href or "").strip())
    real, wrapper = _unwrap(href)
    host, scheme = _host(real)
    ln = Link(href=real[:1000], text=re.sub(r"\s+", " ", text or "").strip()[:300], host=host, scheme=scheme,
              unwrapped_from=wrapper)
    ln.reg = host if is_ip(host) else org_domain(host) if host else ""
    ln.text_domain = text_domain(ln.text)
    ln.text_reg = (ln.text_domain if is_ip(ln.text_domain) else org_domain(ln.text_domain)) if ln.text_domain else ""
    return ln


class _HTMLScanner(HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "blockquote",
             "hr", "section", "article", "header", "footer"}
    SKIP = {"script", "style", "title", "noscript", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = HtmlScan()
        self._buf: list[str] = []
        self._a: dict | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "a":
            self._close_a()
            self._a = {"href": a.get("href", ""), "text": []}
        elif tag == "area" and a.get("href"):
            self.out.links.append(make_link(a["href"], a.get("alt", "")))
        elif tag == "img" and self._a is not None and a.get("alt"):
            self._a["text"].append(" " + a["alt"] + " ")
        elif tag == "form":
            self.out.forms.append(a.get("action", "")[:500])
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.out.password_inputs += 1
        if tag in self.BLOCK:
            self._emit("\n")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag == "a":
            self._close_a()
        if tag in self.BLOCK:
            self._emit("\n")

    def handle_data(self, data):
        if self._skip:
            return
        if self._a is not None:
            self._a["text"].append(data)
        else:
            self._emit(data)

    def _emit(self, s):
        self._buf.append(s)

    def _close_a(self):
        if self._a is None:
            return
        a, self._a = self._a, None
        text = "".join(a["text"])
        if not a["href"]:
            self._emit(text)
            return
        ln = make_link(a["href"], text)
        self.out.links.append(ln)
        # Render for the text analysers: URL-looking anchor text is replaced by the REAL destination, so the
        # message pipeline investigates where the link actually goes; other anchors become "text <href>".
        if ln.host and ln.scheme in ("http", "https", ""):
            self._emit(f" {ln.href} " if ln.text_domain or not ln.text.strip() else f"{ln.text} <{ln.href}>")
        else:
            self._emit(ln.text)

    def finish(self) -> HtmlScan:
        self.close()
        self._close_a()
        lines = [re.sub(r"[ \t ]+", " ", ln).strip() for ln in "".join(self._buf).split("\n")]
        self.out.text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
        return self.out


def scan_html(html: str) -> HtmlScan:
    s = _HTMLScanner()
    try:
        s.feed(html)
    except Exception:                 # html.parser is lenient; never let odd markup break the analysis
        pass
    return s.finish()


def _content(part) -> str:
    try:
        c = part.get_content()
        return c if isinstance(c, str) else c.decode("utf-8", "replace")
    except Exception:
        data = part.get_payload(decode=True) or b""
        if not isinstance(data, bytes):
            return str(data)
        try:
            return data.decode(part.get_content_charset() or "utf-8", "replace")
        except LookupError:                    # unknown charset label
            return data.decode("utf-8", "replace")


def _is_attachment(part) -> bool:
    try:
        return bool(part.get_filename()) or part.get_content_disposition() == "attachment"
    except Exception:
        return part.get_content_disposition() == "attachment"


def extract_body(msg: EmailMessage) -> tuple[str, HtmlScan, str]:
    """(text the recipient sees, merged HTML scan, which part was used). HTML is preferred over text/plain
    because that is what mail apps render, and phishing often puts a harmless placeholder in text/plain."""
    html_parts, plain_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or _is_attachment(part):
            continue
        ct = part.get_content_type()
        if ct == "text/html":
            html_parts.append(_content(part))
        elif ct == "text/plain":
            plain_parts.append(_content(part))
    scan = HtmlScan()
    for h in html_parts[:5]:
        s = scan_html(h[:1_000_000])
        scan.links += s.links
        scan.forms += s.forms
        scan.password_inputs += s.password_inputs
        scan.text += ("\n\n" if scan.text else "") + s.text
    plain = "\n\n".join(p.strip() for p in plain_parts[:5]).strip()
    if scan.text.strip():
        return scan.text, scan, "text/html"
    return plain, scan, "text/plain" if plain else "none"


def plain_links(text: str) -> list[Link]:
    return [make_link(u.rstrip(".,;:!?)"), "") for u in re.findall(r"(?i)\bhttps?://[^\s<>\"']+", text or "")][:50]


def link_findings(links: list[Link], scan: HtmlScan | None = None) -> list[Finding]:
    out: list[Finding] = []
    web = [ln for ln in links if ln.host]
    src = "HTML anchor analysis (visible text vs. real href)"
    deceptive, tracked = [], []
    for ln in web:
        if ln.text_reg and ln.reg and ln.text_reg != ln.reg:
            item = {"text": ln.text[:200], "href": ln.href[:300], "text_domain": ln.text_domain,
                    "href_domain": ln.reg, "unwrapped_from": ln.unwrapped_from or None}
            (tracked if ln.reg in TRACKERS else deceptive).append(item)
    if deceptive:
        official = [m for m in deceptive if is_official(m["text_domain"])]
        out.append(_f(
            f"Link text shows a different destination ({len(deceptive)} link{'s' * (len(deceptive) > 1)})",
            Severity.HIGH,
            f"The link displayed as '{deceptive[0]['text_domain']}' actually opens {deceptive[0]['href_domain']}."
            + (f" The displayed address belongs to a real organisation ({official[0]['text_domain']}); the "
               "destination does not." if official else ""),
            {"mismatches": deceptive[:10]}, src, "deceptive_link",
            "Users who check the visible address are led to an attacker-controlled site.",
            "Do not click. Type the organisation's address yourself.",
            "Only anchors whose visible text is a URL or domain can be compared."))
    if tracked:
        out.append(_f(
            f"Links routed through an email click-tracking service ({len(tracked)})", Severity.LOW,
            f"Visible text '{tracked[0]['text_domain']}' links via {tracked[0]['href_domain']}, a known mailing / "
            "link-protection service. Normal for newsletters, but the final destination is hidden.",
            {"tracked": tracked[:10]}, src, "context"))
    ips = [ln for ln in web if is_ip(ln.host)]
    if ips:
        out.append(_f(
            f"Links point to raw IP addresses ({len(ips)})", Severity.MEDIUM,
            f"{ips[0].href[:120]} uses a bare IP address instead of a domain name; legitimate senders almost never "
            "do this.", {"urls": [ln.href[:300] for ln in ips[:10]]}, src, "deceptive_link",
            rec="Do not open these links."))
    odd = [ln for ln in links if ln.scheme in ("javascript", "data", "vbscript", "file")]
    if odd:
        out.append(_f(
            f"Script / data / file links in the email ({len(odd)})", Severity.MEDIUM,
            f"Link scheme '{odd[0].scheme}:' can run code or render an embedded page instead of opening a website.",
            {"hrefs": [ln.href[:200] for ln in odd[:5]]}, src, "deceptive_link"))
    if scan and scan.forms:
        out.append(_f(
            "Email contains an embedded " + ("password form" if scan.password_inputs else "HTML form"),
            Severity.HIGH if scan.password_inputs else Severity.MEDIUM,
            f"The HTML body contains {len(scan.forms)} form(s)"
            + (f" with {scan.password_inputs} password field(s)" if scan.password_inputs else "")
            + "; legitimate organisations do not collect data through forms inside emails.",
            {"form_actions": scan.forms[:5], "password_fields": scan.password_inputs}, "HTML body analysis",
            "credential_harvest", "Data typed into the form is sent straight to the attacker.",
            "Never enter credentials into an email."))
    if web:
        doms = list(dict.fromkeys(ln.reg for ln in web))
        out.append(_f(
            f"{len(web)} web link(s) to {len(doms)} domain(s)", Severity.INFO,
            "Link destinations found in the body: " + ", ".join(doms[:8]) + ("…" if len(doms) > 8 else "") + ".",
            {"link_count": len(web), "domains": doms[:20]}, src, "info"))
    return out


# ---------------------------------------------------------------- attachments ---------------------------------
@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    detected_type: str | None = None
    reasons: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO

    @property
    def risky(self) -> bool:
        return self.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def sniff(data: bytes) -> str | None:
    """File family from magic bytes (what the file really is, regardless of its name)."""
    if data[:2] == b"MZ":
        return "exe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:4] == b"Rar!":
        return "rar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"GIF8":
        return "gif"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta", b"<form", b"<iframe")):
        return "html"
    return None


_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _worse(a: Severity, b: Severity) -> Severity:
    return a if _SEV_RANK[a] >= _SEV_RANK[b] else b


def assess_attachment(filename: str, content_type: str, data: bytes) -> Attachment:
    shown = filename.replace("\u202e", "[U+202E]")
    att = Attachment(filename=shown[:200], content_type=content_type, size=len(data),
                     sha256=hashlib.sha256(data).hexdigest(), detected_type=sniff(data))
    name = filename.lower().strip().rstrip(".")
    parts = [x.strip() for x in name.split(".")]
    ext = parts[-1] if len(parts) > 1 else ""

    def add(reason, sev):
        att.reasons.append(reason)
        att.severity = _worse(att.severity, sev)

    if "\u202e" in filename:
        add("file name contains a right-to-left override character (U+202E) that visually reverses the extension",
            Severity.HIGH)
    if ext in EXEC_EXT:
        add(f".{ext} is an executable / script file type that runs code when opened", Severity.HIGH)
    elif ext in CONTAINER_EXT:
        add(f".{ext} archive / disk image: commonly used to smuggle malware past filters and Mark-of-the-Web",
            Severity.MEDIUM)
    elif ext in HTML_EXT:
        add(f".{ext} file: opens a local web page that can show a fake login form (HTML smuggling)", Severity.MEDIUM)
    elif ext in MACRO_EXT:
        add(f".{ext} is a macro-enabled Office / OneNote file that can run code", Severity.MEDIUM)
    risky_ext = ext in EXEC_EXT | CONTAINER_EXT | HTML_EXT | MACRO_EXT
    if len(parts) >= 3 and parts[-2] in DECOY_EXT and risky_ext:
        add(f"double extension: looks like a .{parts[-2]} but is really a .{ext}", Severity.HIGH)
    if re.search(r"\s{4,}\.\w+$", filename) or re.search(r"\.\w{2,4}[ _]{4,}", filename):
        add("long run of spaces/underscores used to push the real extension out of view", Severity.MEDIUM)
    ct = (content_type or "").lower()
    if ext in EXPECTED_CT and ct and ct not in GENERIC_CT and ct not in EXPECTED_CT[ext]:
        disguise = ct.startswith(SAFE_LOOKING_CT) and risky_ext
        add(f"declared Content-Type {ct} does not match the .{ext} extension", Severity.HIGH if disguise
            else Severity.MEDIUM)
    elif ext in EXEC_EXT | HTML_EXT and ct.startswith(SAFE_LOOKING_CT):
        add(f"declared as harmless {ct} while the file is a .{ext}", Severity.HIGH)
    fam, real = EXT_FAMILY.get(ext), att.detected_type
    if real and fam and real != fam:
        add(f"content is actually {real.upper()} (magic bytes) although the name ends in .{ext}",
            Severity.HIGH if real in ("exe", "elf", "html", "svg") or fam in ("pdf", "jpeg", "png") else Severity.MEDIUM)
    elif real in ("exe", "elf") and not fam:
        add(f"content is a {real.upper()} executable (magic bytes)", Severity.HIGH)
    return att


def scan_attachments(msg: EmailMessage) -> list[Attachment]:
    out = []
    for part in msg.walk():
        if part.is_multipart() or not _is_attachment(part):
            continue
        try:
            fn = part.get_filename() or ""
        except Exception:
            fn = ""
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        if not isinstance(data, bytes):
            data = str(data).encode("utf-8", "replace")
        out.append(assess_attachment(fn or "(unnamed)", part.get_content_type(), data))
        if len(out) >= MAX_ATTACHMENTS:
            break
    return out


def attachment_findings(atts: list[Attachment]) -> list[Finding]:
    out = []
    for a in atts:
        if not a.risky:
            continue
        out.append(_f(
            f"Dangerous attachment: {a.filename}", a.severity,
            "Static inspection (not opened or executed): " + "; ".join(a.reasons) + ".",
            {"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256,
             "detected_type": a.detected_type, "reasons": a.reasons}, "Attachment static analysis (name, declared "
            "type, magic bytes, SHA-256)", "attachment",
            "Opening it can install malware or show a credential-phishing page.",
            "Do not open the attachment. Ask the sender through a separate channel if you expected it.",
            "Attachments are never executed; the SHA-256 can be looked up in a malware sandbox."))
    if atts and not out:
        out.append(_f(f"{len(atts)} attachment(s), no risky type detected", Severity.INFO,
                      "Attachment names, declared types and magic bytes look consistent.",
                      {"attachments": [{"filename": a.filename, "content_type": a.content_type, "sha256": a.sha256}
                                       for a in atts[:10]]},
                      "Attachment static analysis", "info",
                      lim="Content was not scanned for malware (no antivirus engine)."))
    return out


# ---------------------------------------------------------------- Received chain ------------------------------
def parse_received(v: str) -> dict:
    hop = {}
    body, _, date = v.rpartition(";") if ";" in v else (v, "", "")
    for key in ("from", "by", "with"):
        m = re.search(rf"\b{key}\s+([^\s;()]+)", body, re.I)
        if m:
            hop[key] = m.group(1)[:120]
    from_part = re.split(r"\bby\b", body, maxsplit=1, flags=re.I)[0]
    ips = re.findall(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]", from_part) or re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
                                                                                 from_part)
    if ips:
        hop["ip"] = ips[0]
    if date.strip():
        hop["date"] = date.strip()[:60]
    return hop


def received_findings(p: Parsed) -> tuple[list[dict], str | None, list[Finding]]:
    hops = [parse_received(v) for v in p.received]
    origin = next((h["ip"] for h in reversed(hops) if h.get("ip") and _ip_public(h["ip"])), None)
    ev = {"hops": hops[:12], "hop_count": len(hops), "origin_ip": origin}
    fs = [_f(f"Delivered through {len(hops)} Received hop(s)", Severity.INFO,
             (f"Earliest public sending IP in the trace: {origin}. " if origin else "")
             + "Hops are listed newest (your provider) first.", ev, "Received-header trace (RFC 5321 §4.4)", "info",
             lim="Only the Received headers added by your own provider are trustworthy; lower ones can be forged by "
                 "the sender.")]
    try:
        sent = parsedate_to_datetime(p.date) if p.date else None
        if sent and sent.tzinfo and sent - dt.datetime.now(dt.UTC) > dt.timedelta(days=1):
            fs.append(_f("Date header is in the future", Severity.LOW, f"The message claims to be sent on {p.date}.",
                         {"date": p.date}, "Header analysis", "context"))
    except (TypeError, ValueError, IndexError):
        pass
    return hops, origin, fs


# ---------------------------------------------------------------- orchestration -------------------------------
@dataclass
class EmailChecks:
    parsed: Parsed
    auth: dict
    dns: dict
    scan: HtmlScan
    links: list[Link]
    attachments: list[Attachment]
    hops: list[dict]
    origin_ip: str | None
    body_text: str
    body_source: str
    findings: list[Finding]
    checks: list[CheckStatus]


def run_all(raw: str, live_dns: bool = True, lookup: Callable = txt_lookup,
            rank_fn: Callable[[str], int | None] | None = None, trusted_ids: set[str] | None = None) -> EmailChecks:
    checks: list[CheckStatus] = []
    p = parse(raw)
    checks.append(CheckStatus(name="email_parse", status="ok" if p.from_addr else "failed",
                              detail=f"From={p.from_addr or 'missing'}; {len(p.received)} Received; "
                                     f"{len(p.auth_results)} Authentication-Results; {len(p.dkim_signatures)} DKIM-"
                                     "Signature"))
    auth, f_auth = auth_findings(p, trusted_ids)
    checks.append(CheckStatus(name="email_authentication", status="ok" if auth.get("source") else "unavailable",
                              detail=f"spf={auth['spf']} dkim={auth['dkim']} dmarc={auth['dmarc']}; "
                                     f"{auth.get('source') or 'no authentication headers'}"[:300]))
    f_bh = dkim_body_findings(p)
    if p.dkim_signatures:
        checks.append(CheckStatus(name="dkim_body_hash", status="ok" if f_bh else "skipped",
                                  detail=f_bh[0].title if f_bh else "no bh= tag"))
    dns_info, f_dns, c_dns = dns_findings(p.from_domain, live_dns, lookup)
    checks += c_dns
    f_id = identity_findings(p, auth, rank_fn)
    checks.append(CheckStatus(name="sender_identity", status="ok" if p.from_addr else "failed",
                              detail=f"{sum(f.severity != Severity.INFO for f in f_id)} identity issue(s)"))
    body_text, scan, body_source = extract_body(p.msg)
    links = scan.links + ([] if scan.links else plain_links(body_text))
    f_links = link_findings(links, scan)
    checks.append(CheckStatus(name="email_links", status="ok", detail=f"{len(links)} link(s) from {body_source}"))
    atts = scan_attachments(p.msg)
    f_att = attachment_findings(atts)
    checks.append(CheckStatus(name="attachments", status="ok",
                              detail=f"{len(atts)} attachment(s), {sum(a.risky for a in atts)} risky"))
    hops, origin, f_rcv = received_findings(p)
    checks.append(CheckStatus(name="received_chain", status="ok" if hops else "skipped",
                              detail=f"{len(hops)} hop(s), origin {origin or 'unknown'}"))
    findings = f_auth + f_bh + f_dns + f_id + f_links + f_att + f_rcv
    return EmailChecks(parsed=p, auth=auth, dns=dns_info, scan=scan, links=links, attachments=atts, hops=hops,
                       origin_ip=origin, body_text=body_text, body_source=body_source, findings=findings,
                       checks=checks)
