"""Domain intelligence: structure, typosquatting / homographs, registration age (RDAP), DNS."""
from __future__ import annotations

import datetime as dt
import re
import unicodedata

import dns.exception
import dns.resolver
import httpx
import idna

from ..ml.url_features import (BRANDS, FREE_HOSTING, SHORTENERS, SUSPICIOUS_TLDS, _extract, brand_match,
                               damerau, is_ip)
from ..schemas import Finding, Severity

# Official registered domains for brands (avoid flagging the real thing).
OFFICIAL = {
    "paypal": ["paypal.com"], "google": ["google.com", "google.co.in"], "gmail": ["gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "microsoftonline.com"], "apple": ["apple.com"],
    "icloud": ["icloud.com"], "amazon": ["amazon.com", "amazon.in"], "facebook": ["facebook.com"],
    "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"], "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"], "binance": ["binance.com"], "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"], "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], "onlinesbi": ["onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com"], "hdfcbank": ["hdfcbank.com"], "icici": ["icicibank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "kotak": ["kotak.com"], "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"], "irctc": ["irctc.co.in"], "flipkart": ["flipkart.com"], "jio": ["jio.com"],
    "airtel": ["airtel.in"], "indiapost": ["indiapost.gov.in"], "incometax": ["incometax.gov.in"],
    "uidai": ["uidai.gov.in"], "epfo": ["epfindia.gov.in"], "parivahan": ["parivahan.gov.in"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "dropbox": ["dropbox.com"], "adobe": ["adobe.com"],
}
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "next", "return", "returnurl",
                   "return_to", "returnto", "continue", "dest", "destination", "goto", "target", "to", "out", "link",
                   "u", "r", "rurl", "forward", "callback", "service", "success_url"}


def _scripts(s: str) -> set[str]:
    out = set()
    for ch in s:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def _rdap(domain: str) -> dict:
    try:
        r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=6, follow_redirects=True,
                      headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"available": False, "status": r.status_code}
        j = r.json()
    except (httpx.HTTPError, ValueError):
        return {"available": False}
    created = next((e.get("eventDate") for e in j.get("events", []) if e.get("eventAction") == "registration"), None)
    registrar = None
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vc = ent.get("vcardArray", [None, []])[1]
            registrar = next((x[3] for x in vc if x and x[0] == "fn"), None)
    return {"available": True, "created": created, "registrar": registrar, "status": j.get("status", [])}


def _dns(host: str) -> dict:
    res = dns.resolver.Resolver()
    res.lifetime = 4
    out = {}
    for rr in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            out[rr] = [r.to_text() for r in res.resolve(host, rr)][:8]
        except (dns.exception.DNSException, Exception):
            out[rr] = []
    return out


def analyze(host: str, path_and_query: str = "", tranco_rank: int | None = None) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []

    def add(title, sev, desc, evidence, source, impact=None, rec=None):
        findings.append(Finding(id="", module="domain", title=title, severity=sev, description=desc,
                                evidence=evidence, source=source, impact=impact, recommendation=rec))

    ext = _extract(host)
    reg = ext.top_domain_under_public_suffix or host
    label = ext.domain.lower()
    info: dict = {"registered_domain": reg, "subdomain": ext.subdomain, "suffix": ext.suffix,
                  "tranco_rank": tranco_rank}

    if is_ip(host):
        add("Raw IP address instead of a domain", Severity.MEDIUM,
            "The link points to an IP address. Legitimate services almost always use a domain name.",
            {"host": host}, "URL structure analysis")

    # Homograph / IDN
    if "xn--" in host:
        try:
            uni = idna.decode(host)
        except idna.IDNAError:
            uni = host
        scripts = _scripts(uni)
        info["unicode_host"] = uni
        sev = Severity.HIGH if (len(scripts) > 1 or scripts & set(CONFUSABLE_SCRIPTS)) else Severity.MEDIUM
        add("Internationalised (punycode) domain", sev,
            f"Domain displays as '{uni}' and uses scripts {sorted(scripts)}; look-alike characters can mimic real brands.",
            {"punycode": host, "unicode": uni, "scripts": sorted(scripts)}, "IDN/homograph analysis",
            "Users may believe they are on a familiar site.", "Type the official address manually instead.")

    # Typosquatting / brand impersonation
    official_all = {d for v in OFFICIAL.values() for d in v}
    brand, dist = brand_match(label)
    if reg not in official_all:
        if brand and 0 < dist <= 2 and len(label) >= 4:
            add(f"Look-alike of '{brand}' (typosquatting)", Severity.HIGH,
                f"'{reg}' differs from the brand name '{brand}' by {dist} character edit(s) (after folding look-alike "
                f"characters such as 0→o, 1→l, rn→m).",
                {"registered_domain": reg, "brand": brand, "edit_distance": dist,
                 "official_domains": OFFICIAL.get(brand, [])}, "Edit-distance + homoglyph analysis",
                "Classic phishing technique to trick users at a glance.", "Verify the official domain.")
        elif label in BRANDS:
            add(f"Brand name '{label}' on an unofficial domain", Severity.HIGH,
                f"'{reg}' uses the brand name '{label}' but is not one of its official domains "
                f"({', '.join(OFFICIAL.get(label, ['unknown']))}).",
                {"registered_domain": reg, "brand": label, "official_domains": OFFICIAL.get(label, [])},
                "Brand/official-domain comparison")
        else:
            tokens = set(re.split(r"[-._\d]+", f"{label}.{ext.subdomain.lower()}"))
            hits = [b for b in BRANDS if b in tokens or (len(b) >= 4 and (b in label or b in ext.subdomain.lower()))]
            if hits:
                where = "subdomain" if any(b in ext.subdomain.lower() and b not in label for b in hits) else "domain name"
                add(f"Brand name '{hits[0]}' embedded in {where}", Severity.HIGH,
                    f"The {where} contains '{hits[0]}' but the site is registered as '{reg}', not an official "
                    f"{hits[0]} domain.",
                    {"registered_domain": reg, "brands": hits, "official_domains": OFFICIAL.get(hits[0], [])},
                    "Brand/official-domain comparison", "Impersonation of a trusted organisation.",
                    "Do not log in or pay through this link.")
        pq = path_and_query.lower()
        in_path = [b for b in BRANDS if len(b) >= 5 and b in pq]
        if in_path:
            add(f"Brand name '{in_path[0]}' in URL path", Severity.MEDIUM,
                f"The path mentions '{in_path[0]}' while the site is '{reg}'.",
                {"registered_domain": reg, "brands": in_path}, "URL structure analysis")

    # Embedded redirect parameters: ?url= / ?redirect= / ?next= ... pointing at a different site
    from urllib.parse import parse_qsl, unquote, urlsplit as _us
    q = path_and_query.split("?", 1)[1] if "?" in path_and_query else ""
    for key, val in parse_qsl(q, keep_blank_values=False):
        v = unquote(unquote(val)).strip()
        if key.lower() in REDIRECT_PARAMS or re.match(r"(?i)^(https?:)?//", v):
            if not re.match(r"(?i)^(https?:)?//", v):
                continue
            th = (_us(v if "://" in v else "http:" + v).hostname or "").lower()
            treg = (_extract(th).top_domain_under_public_suffix or th) if th else ""
            if treg and treg != reg:
                add("Embedded redirect to another site", Severity.MEDIUM,
                    f"The link carries a '{key}=' parameter that points to {treg}. Open-redirect parameters are "
                    f"used to hide a phishing destination behind a trusted-looking link.",
                    {"parameter": key, "embedded_target": v[:300], "target_domain": treg, "link_domain": reg},
                    "URL structure analysis", "The visible domain may not be where you end up.",
                    "Do not trust the link because of its first domain; check where it really leads.")
                break

    if reg in SHORTENERS:
        add("URL shortener", Severity.LOW, "The real destination is hidden behind a shortening service.",
            {"shortener": reg}, "URL structure analysis", rec="Check the redirect destination shown in this report.")
    if reg in FREE_HOSTING or any(host.endswith("." + f) for f in FREE_HOSTING):
        add("Hosted on a free / user-content platform", Severity.MEDIUM,
            f"The site lives on a shared platform ({reg}) where anyone can publish pages; phishing kits are "
            "frequently hosted this way.", {"platform": reg}, "Hosting-platform analysis")
    if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        add(f"High-abuse top-level domain (.{ext.suffix})", Severity.LOW,
            f".{ext.suffix} domains are cheap and disproportionately used in abuse; this alone proves nothing.",
            {"tld": ext.suffix}, "TLD abuse statistics (heuristic)")
    if host.count("-") >= 3 or len(ext.subdomain.split(".")) >= 4:
        add("Complex hostname structure", Severity.LOW, "Many hyphens or nested subdomains, a common obfuscation trick.",
            {"host": host}, "URL structure analysis")

    if not is_ip(host):
        rd = _rdap(reg)
        info["rdap"] = rd
        if rd.get("available") and rd.get("created"):
            try:
                created = dt.datetime.fromisoformat(rd["created"].replace("Z", "+00:00"))
                age = (dt.datetime.now(dt.timezone.utc) - created).days
                info["domain_created"], info["domain_age_days"], info["registrar"] = created.date().isoformat(), age, rd.get("registrar")
                if age < 30:
                    add("Very newly registered domain", Severity.HIGH, f"Registered {age} days ago ({created.date()}).",
                        {"created": created.date().isoformat(), "age_days": age, "registrar": rd.get("registrar")},
                        "RDAP registration data", "Most phishing domains are used within days of registration.")
                elif age < 180:
                    add("Recently registered domain", Severity.MEDIUM, f"Registered {age} days ago ({created.date()}).",
                        {"created": created.date().isoformat(), "age_days": age}, "RDAP registration data")
            except ValueError:
                pass
        dnsinfo = _dns(host)
        info["dns"] = dnsinfo
        if not dnsinfo.get("A") and not dnsinfo.get("AAAA"):
            add("Domain does not resolve", Severity.INFO, "No A/AAAA records; the site may be offline or taken down.",
                {"dns": dnsinfo}, "DNS lookup")
        if tranco_rank:
            info["popularity"] = f"Tranco top-1M rank {tranco_rank}"
    return info, findings
