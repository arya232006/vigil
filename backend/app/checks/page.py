"""Passive website checks on the fetched response: security headers, cookies, software disclosure,
mixed content, and static HTML phishing indicators. Nothing is executed; no forms are submitted."""
from __future__ import annotations

import gzip
import re
import zlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..ml.url_features import BRANDS, _extract
from ..schemas import Finding, Severity
from .fetcher import FetchResult

PASSIVE = "Passive inspection of the HTTP response (no exploitation, no active scanning)"

HEADER_CHECKS = [
    ("strict-transport-security", Severity.MEDIUM, "HSTS missing",
     "Browsers may be downgraded to plain HTTP by a network attacker (SSL stripping).",
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", True),
    ("content-security-policy", Severity.LOW, "Content-Security-Policy missing",
     "No browser-enforced restriction on script sources, so XSS has a larger impact.",
     "Define a Content-Security-Policy restricting script/style sources.", False),
    ("x-content-type-options", Severity.LOW, "X-Content-Type-Options missing",
     "Browsers may MIME-sniff responses into executable content.", "Add 'X-Content-Type-Options: nosniff'.", False),
    ("referrer-policy", Severity.INFO, "Referrer-Policy missing",
     "Full URLs (possibly with tokens) can leak to third parties via the Referer header.",
     "Add 'Referrer-Policy: strict-origin-when-cross-origin'.", False),
    ("permissions-policy", Severity.INFO, "Permissions-Policy missing",
     "Embedded content is not restricted from powerful browser features.",
     "Add a Permissions-Policy limiting camera, microphone, geolocation, etc.", False),
]

# End-of-life software lines with publicly known vulnerabilities (version from banner headers).
EOL = [
    (re.compile(r"php/([5-7]\.\d+|8\.0)\b", re.I), "PHP", "PHP branches before 8.1 are end-of-life and receive no security fixes"),
    (re.compile(r"apache/2\.(?:[0-2]\.\d+|4\.(?:[0-9]|[1-4]\d|5[0-7]))\b", re.I), "Apache httpd", "Apache httpd versions before 2.4.58 have published CVEs"),
    (re.compile(r"nginx/(?:0\.|1\.(?:[0-9]|1\d|2[0-3])\.)", re.I), "nginx", "nginx versions before 1.24 are out of support"),
    (re.compile(r"microsoft-iis/(?:[5-8]\.\d)", re.I), "IIS", "IIS 8.x and earlier run on unsupported Windows versions"),
    (re.compile(r"openssl/(?:0\.|1\.0\.|1\.1\.)", re.I), "OpenSSL", "OpenSSL 1.1.1 and earlier are end-of-life"),
]


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict] = []
        self.password_inputs = 0
        self.inputs: list[str] = []
        self.scripts_src: list[str] = []
        self.resources: list[str] = []
        self.iframes: list[str] = []
        self.meta_refresh: str | None = None
        self.links: list[str] = []
        self.inline_js = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower()})
        elif tag == "input":
            t = a.get("type", "text").lower()
            name = (a.get("name", "") + " " + a.get("placeholder", "") + " " + a.get("id", "")).lower()
            if t == "password":
                self.password_inputs += 1
            self.inputs.append(f"{t}:{name.strip()}")
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.scripts_src.append(a["src"])
        elif tag in ("img", "link", "source"):
            src = a.get("src") or a.get("href")
            if src:
                self.resources.append(src)
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script and len(self.inline_js) < 50:
            self.inline_js.append(data[:20000])


def decode_body(res: FetchResult) -> str:
    body = res.body
    enc = res.headers.get("content-encoding", "")
    try:
        if "gzip" in enc:
            body = gzip.decompress(body)
        elif "deflate" in enc:
            body = zlib.decompress(body)
    except (OSError, zlib.error, EOFError):
        pass
    m = re.search(r"charset=([\w-]+)", res.content_type or "")
    try:
        return body.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def analyze(res: FetchResult, final_host: str, registered_domain: str) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    info: dict = {}

    def add(title, sev, desc, evidence, impact=None, rec=None, module="headers", limitations=None, source=PASSIVE):
        findings.append(Finding(id="", module=module, title=title, severity=sev, description=desc, evidence=evidence,
                                source=source, impact=impact, recommendation=rec, limitations=limitations))

    h = res.headers
    https = res.final_url.startswith("https://")
    first = res.hops[0].url if res.hops else res.final_url

    # --- Transport ---------------------------------------------------------------------------------
    if not https:
        add("Site served without HTTPS", Severity.MEDIUM,
            "The final page is delivered over unencrypted HTTP.", {"final_url": res.final_url},
            "Anything typed (passwords, card numbers) can be read or modified in transit.",
            "Never enter sensitive data on this page; the owner should enable HTTPS.")
    elif first.startswith("http://") and len(res.hops) == 1:
        add("No HTTP→HTTPS redirect", Severity.LOW, "Plain-HTTP requests are not upgraded to HTTPS.", {"url": first})

    # --- Security headers (only meaningful on a real HTML page) ------------------------------------
    is_html = "html" in (res.content_type or "").lower()
    if res.status and res.status < 400 and is_html:
        missing = []
        for hdr, sev, title, impact, rec, https_only in HEADER_CHECKS:
            if https_only and not https:
                continue
            if hdr not in h:
                if hdr == "content-security-policy" and "frame-ancestors" in h.get("content-security-policy", ""):
                    continue
                missing.append(hdr)
                add(title, sev, f"Response has no '{hdr}' header.", {"header": hdr, "present_headers": sorted(h)[:30]},
                    impact, rec, limitations="Header checks reflect this single response; other pages may differ.")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            add("Clickjacking protection missing", Severity.LOW,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.", {"header": "x-frame-options"},
                "The page can be framed by another site to trick users into clicks.",
                "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors'.")
        info["missing_headers"] = missing

        cookies = [v for k, v in res.headers.items() if k == "set-cookie"]
        for c in cookies[:5]:
            lc = c.lower()
            flags = [f for f, ok in (("Secure", "secure" in lc), ("HttpOnly", "httponly" in lc),
                                     ("SameSite", "samesite" in lc)) if not ok]
            if flags and https:
                add("Cookie missing security flags", Severity.LOW, f"Cookie set without {', '.join(flags)}.",
                    {"cookie": c.split(";")[0].split("=")[0], "missing": flags},
                    "Session cookies may be stolen via XSS or sent cross-site.", "Set Secure; HttpOnly; SameSite.")

    banner = " ".join(h.get(k, "") for k in ("server", "x-powered-by", "x-aspnet-version"))
    if banner.strip():
        info["software_banner"] = banner.strip()
        for rx, prod, why in EOL:
            m = rx.search(banner)
            if m:
                add(f"Outdated {prod} version disclosed", Severity.MEDIUM,
                    f"Banner reports '{m.group(0)}'. {why}.", {"banner": banner.strip()},
                    "Known public exploits may apply.", f"Upgrade {prod} to a supported release and hide version banners.",
                    limitations="Based on the self-reported banner; the server may be patched or the banner falsified.")
        if re.search(r"\d+\.\d+", banner):
            add("Software version disclosed", Severity.INFO, f"Headers reveal '{banner.strip()}'.", {"banner": banner.strip()},
                "Helps attackers pick matching exploits.", "Remove version numbers from Server/X-Powered-By headers.")

    if not is_html:
        info["content_type"] = res.content_type
        return info, findings

    # --- HTML (static, never executed) -----------------------------------------------------------
    html = decode_body(res)
    p = _Parser()
    try:
        p.feed(html[:1_500_000])
    except Exception:  # malformed HTML must not break analysis
        pass
    title = re.sub(r"\s+", " ", p.title).strip()[:200]
    info.update({"title": title, "forms": len(p.forms), "password_fields": p.password_inputs,
                 "iframes": len(p.iframes), "scripts": len(p.scripts_src)})

    def host_of(u: str) -> str:
        try:
            return (urlsplit(urljoin(res.final_url, u)).hostname or "").lower()
        except ValueError:
            return ""

    def reg_of(hst: str) -> str:
        e = _extract(hst)
        return e.top_domain_under_public_suffix or hst

    if https:
        insecure = [u for u in p.scripts_src + p.resources + p.iframes if u.startswith("http://")]
        if insecure:
            add("Mixed content", Severity.MEDIUM, f"HTTPS page loads {len(insecure)} resource(s) over plain HTTP.",
                {"examples": insecure[:5]}, "Network attackers can tamper with these resources.",
                "Load all resources over HTTPS.")

    # Credential harvesting
    sensitive = [i for i in p.inputs if re.search(r"pass|otp|pin|cvv|card|aadhaar|pan\b|ssn|mpin|seed|mnemonic", i)]
    ext_forms = [f for f in p.forms if f["action"] and reg_of(host_of(f["action"])) not in ("", registered_domain)]
    if p.password_inputs or sensitive:
        info["sensitive_inputs"] = sensitive[:10]
        add("Page requests credentials or sensitive data", Severity.MEDIUM,
            f"Found {p.password_inputs} password field(s) and inputs asking for: "
            f"{', '.join(sorted({s.split(':', 1)[1][:30] for s in sensitive})[:6]) or 'password'}.",
            {"password_fields": p.password_inputs, "inputs": sensitive[:10]}, module="url",
            impact="Entering data here gives it to whoever controls this site.",
            rec="Only enter credentials on the organisation's official domain.")
    if ext_forms:
        add("Form submits data to a different domain", Severity.HIGH,
            f"Form(s) post to {sorted({host_of(f['action']) for f in ext_forms})[:3]}, not to {registered_domain}.",
            {"form_actions": [f["action"][:200] for f in ext_forms[:3]]}, module="url",
            impact="Typical of phishing kits that exfiltrate credentials to attacker servers.",
            rec="Do not submit this form.")
    if any(f["action"].lower().startswith("mailto:") for f in p.forms):
        add("Form sends data by email", Severity.HIGH, "A form uses a mailto: action, a common low-effort phishing trick.",
            {"forms": p.forms[:3]}, module="url")

    # Brand impersonation in title / page content
    tl = title.lower()
    page_brands = [b for b in BRANDS if len(b) >= 4 and re.search(rf"\b{re.escape(b)}\b", tl)]
    reg_label = _extract(registered_domain).domain.lower()
    if page_brands and not any(b in reg_label or reg_label in b for b in page_brands):
        sev = Severity.HIGH if (p.password_inputs or sensitive) else Severity.MEDIUM
        add(f"Page claims to be '{page_brands[0]}' but domain is {registered_domain}", sev,
            f"Title '{title[:80]}' references {page_brands[0]}, which does not match the site's domain.",
            {"title": title, "brands": page_brands, "registered_domain": registered_domain}, module="url",
            impact="Identity mismatch between the claimed organisation and the actual website.",
            rec="Navigate to the organisation's official site directly.")
    brand_assets = sorted({reg_of(host_of(u)) for u in p.resources + p.scripts_src
                           if any(b in reg_of(host_of(u)) for b in BRANDS if len(b) >= 5)} - {registered_domain})
    if brand_assets and (p.password_inputs or sensitive):
        add("Loads assets from a brand's official domain", Severity.MEDIUM,
            f"A credential page on {registered_domain} hot-links logos/scripts from {brand_assets[:3]}.",
            {"asset_domains": brand_assets[:5]}, module="url",
            impact="Phishing kits copy real brand assets to look authentic.")

    # Client-side redirects & obfuscation (static pattern match, not executed)
    js = "\n".join(p.inline_js)
    if p.meta_refresh and "url=" in p.meta_refresh.lower():
        target = p.meta_refresh.split("=", 1)[-1].strip(" '\"")
        info["client_redirect"] = target
        add("Automatic meta-refresh redirect", Severity.MEDIUM, f"Page redirects the browser to {target[:120]}.",
            {"meta_refresh": p.meta_refresh[:200]}, module="redirect")
    m = re.search(r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]{8,300})['\"]", js)
    if m:
        info["client_redirect"] = m.group(1)
        add("JavaScript redirect", Severity.LOW, f"Script sends the browser to {m.group(1)[:120]}.",
            {"target": m.group(1)[:300]}, module="redirect",
            limitations="Detected by static pattern matching; dynamic redirects may be missed.")
    obf = [k for k, rx in (("eval(atob", r"eval\s*\(\s*atob"), ("eval(unescape", r"eval\s*\(\s*unescape"),
                           ("document.write(unescape", r"document\.write\s*\(\s*unescape"),
                           ("long base64 blob", r"[A-Za-z0-9+/]{800,}={0,2}"),
                           ("String.fromCharCode chain", r"(?:fromCharCode\([^)]{40,}\))")) if re.search(rx, js)]
    if obf:
        add("Obfuscated JavaScript", Severity.MEDIUM, f"Inline scripts use obfuscation patterns: {', '.join(obf)}.",
            {"patterns": obf}, module="url", impact="Often used to hide phishing/malware logic from scanners.",
            limitations="Some legitimate sites minify or encode scripts.")
    # Passive exposure checks: only what this one fetched page already shows. No paths are probed.
    exposure_lim = "Based only on the fetched page; no other paths were requested (passive inspection)."
    if re.match(r"(?i)\s*index of /", title) or re.search(r"(?i)<h1>\s*index of /", html[:5000]):
        add("Open directory listing", Severity.MEDIUM, "The server lists the files in this folder to anyone.",
            {"title": title}, impact="Can leak backups, source code or private files.",
            rec="Disable directory listing (autoindex) on the server.", limitations=exposure_lim)
    sensitive_rx = re.compile(r"(?i)(/\.env$|/\.git(/|$)|\.sql(\.gz)?$|\.bak$|\.old$|\.swp$|wp-config\.php|/\.htpasswd|"
                              r"/\.ds_store$|id_rsa|/phpinfo\.php|/server-status|\.tar\.gz$|/backup[^/]*\.(zip|tar|gz)$)")
    exposed = sorted({u for u in p.links + p.resources + p.scripts_src if sensitive_rx.search(u.split("?")[0])})[:5]
    if exposed:
        add("Page links to sensitive files", Severity.MEDIUM,
            f"The page references {len(exposed)} file(s) that are normally private (config, VCS, backups, dumps).",
            {"files": exposed}, impact="If reachable, these may expose credentials or source code.",
            rec="Remove the files from the web root and the links from the page.", limitations=exposure_lim)
    debug_sig = [n for n, rx in (("Python traceback", r"Traceback \(most recent call last\)"),
                                 ("Django debug page", r"You're seeing this error because you have <code>DEBUG = True"),
                                 ("Laravel/Whoops error page", r"Whoops! There was an error|Illuminate\\"),
                                 ("PHP error output", r"<b>(Fatal error|Warning|Parse error)</b>:.{0,200} on line <b>\d+"),
                                 ("Java stack trace", r"at [a-z]+(\.[a-z0-9_]+)+\([A-Za-z0-9_]+\.java:\d+\)"),
                                 ("phpinfo() page", r"<title>phpinfo\(\)</title>|PHP Version \d+\.\d+\.\d+</h1>"))
                 if re.search(rx, html[:300_000])]
    if debug_sig:
        add("Debug or error details exposed", Severity.MEDIUM, f"The page shows {', '.join(debug_sig)}.",
            {"signatures": debug_sig}, impact="Reveals internal paths, versions and code that help attackers.",
            rec="Turn off debug mode and show generic error pages in production.", limitations=exposure_lim)

    if re.search(r"oncontextmenu\s*=\s*['\"]?return false|event\.button\s*==\s*2", html, re.I):
        add("Right-click disabled", Severity.LOW, "The page blocks right-click / inspection.", {}, module="url")
    if p.iframes and not title and len(p.links) < 3:
        add("Content hidden in iframe", Severity.LOW, "The page is mostly an iframe wrapper around other content.",
            {"iframes": p.iframes[:3]}, module="url")
    return info, findings
