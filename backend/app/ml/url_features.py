"""Lexical URL features. Shared by training (ml/train_url.py) and inference so they never drift.
Computed from the URL string only: no network access."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled public suffix list

BRANDS = [
    "paypal", "google", "gmail", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
    "facebook", "instagram", "whatsapp", "netflix", "linkedin", "twitter", "telegram", "binance",
    "coinbase", "metamask", "dropbox", "adobe", "dhl", "fedex", "ups", "usps", "chase", "wellsfargo",
    "bankofamerica", "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank", "kotak",
    "paytm", "phonepe", "gpay", "bhim", "npci", "irctc", "flipkart", "myntra", "jio", "airtel",
    "indiapost", "incometax", "uidai", "aadhaar", "epfo", "parivahan", "yono", "steam", "roblox",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "tiny.cc", "lnk.to", "s.id", "t.ly", "bit.do", "shorte.st", "v.gd",
}
SUSPICIOUS_TLDS = {
    "top", "xyz", "shop", "icu", "click", "buzz", "rest", "cfd", "sbs", "cyou", "monster", "quest",
    "zip", "mov", "gq", "ml", "cf", "tk", "ga", "work", "live", "online", "site", "store", "fun",
    "support", "help", "info", "loan", "win", "bid", "vip", "lol", "pw", "cc", "ru", "cn",
}
KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
    "confirm", "bank", "wallet", "kyc", "password", "passwd", "billing", "invoice", "payment", "refund",
    "unlock", "suspend", "limited", "reward", "bonus", "free", "gift", "claim", "prize", "support",
    "webscr", "auth", "token", "recover", "reset", "otp", "pan", "aadhaar",
]
RISKY_EXT = (".exe", ".apk", ".scr", ".zip", ".rar", ".js", ".msi", ".bat", ".jar", ".iso", ".dmg")

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
                            "$": "s", "|": "l"})


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def damerau(a: str, b: str) -> int:
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def normalize_label(label: str) -> str:
    return label.lower().translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def brand_match(registered_label: str) -> tuple[str | None, int]:
    """Closest brand to the registered domain label and its edit distance (after homoglyph folding)."""
    if not registered_label:
        return None, 99
    norm = normalize_label(registered_label)
    best, dist = None, 99
    for b in BRANDS:
        if abs(len(norm) - len(b)) > 3:      # distance would exceed what we care about; skip (speed)
            continue
        dd = min(damerau(norm, b), damerau(registered_label.lower(), b))
        if dd < dist:
            best, dist = b, dd
    return best, dist


def parse(url: str):
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    sp = urlsplit(u)
    host = (sp.hostname or "").lower().rstrip(".")
    ext = _extract(host)
    return u, sp, host, ext


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


FEATURE_NAMES: list[str] = [
    "url_len", "host_len", "path_len", "query_len", "n_dots_host", "n_subdomain_parts", "n_hyphens_host",
    "n_digits_host", "digit_ratio_url", "n_special", "has_at", "has_ip_host", "has_port", "is_https",
    "host_entropy", "path_entropy", "n_path_segments", "has_double_slash_path", "has_punycode",
    "non_ascii", "kw_count", "brand_in_sub_or_path", "brand_distance", "brand_exact_registered",
    "is_shortener", "suspicious_tld", "tld_len", "longest_token", "max_digit_run", "risky_ext",
    "n_query_params", "has_url_in_query", "vowel_ratio_host",
]


def features(url: str) -> dict[str, float]:
    u, sp, host, ext = parse(url)
    path, query = sp.path or "", sp.query or ""
    lower = u.lower()
    reg_label = ext.domain.lower()
    sub = ext.subdomain.lower()
    brand, dist = brand_match(reg_label)
    brand_exact = 1.0 if reg_label in BRANDS else 0.0
    sub_path = f"{sub} {path.lower()} {query.lower()}"
    brand_elsewhere = any(b in sub_path for b in BRANDS if len(b) >= 4) and not brand_exact
    tokens = re.split(r"[^a-z0-9]+", lower)
    digit_runs = re.findall(r"\d+", host)
    letters = [c for c in host if c.isalpha()]
    try:
        port = sp.port
    except ValueError:
        port = None
    return {
        "url_len": len(u),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "n_dots_host": host.count("."),
        "n_subdomain_parts": len([p for p in sub.split(".") if p]),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in u) / max(len(u), 1),
        "n_special": sum(u.count(c) for c in "@~%=&_!*,;$"),
        "has_at": float("@" in sp.netloc),
        "has_ip_host": float(is_ip(host)),
        "has_port": float(port is not None),
        "is_https": float(sp.scheme == "https"),
        "host_entropy": _entropy(host),
        "path_entropy": _entropy(path),
        "n_path_segments": len([p for p in path.split("/") if p]),
        "has_double_slash_path": float("//" in path),
        "has_punycode": float("xn--" in host),
        "non_ascii": float(any(ord(c) > 127 for c in u)),
        "kw_count": sum(lower.count(k) for k in KEYWORDS),
        "brand_in_sub_or_path": float(brand_elsewhere),
        "brand_distance": float(min(dist, 6)),
        "brand_exact_registered": brand_exact,
        "is_shortener": float(ext.registered_domain in SHORTENERS or host in SHORTENERS),
        "suspicious_tld": float(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        "tld_len": len(ext.suffix),
        "longest_token": max((len(t) for t in tokens), default=0),
        "max_digit_run": max((len(r) for r in digit_runs), default=0),
        "risky_ext": float(path.lower().endswith(RISKY_EXT)),
        "n_query_params": len([q for q in query.split("&") if q]),
        "has_url_in_query": float("http" in query.lower() or "www." in query.lower()),
        "vowel_ratio_host": sum(c in "aeiou" for c in letters) / max(len(letters), 1),
    }


def vector(url: str) -> list[float]:
    f = features(url)
    return [f[n] for n in FEATURE_NAMES]


# ---- Host-level model (what the trained classifier uses) -------------------------------------
# Public phishing datasets have scheme/path biases (legit = bare https homepages), so the learned model
# only sees the hostname. Path/query signals are handled by explainable rules in the risk engine.

FREE_HOSTING = {
    "firebaseapp.com", "web.app", "github.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "weebly.com", "wixsite.com", "000webhostapp.com", "blogspot.com", "glitch.me", "herokuapp.com",
    "repl.co", "replit.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net",
    "appspot.com", "web.core.windows.net", "r2.dev", "ipfs.io", "dweb.link", "square.site", "godaddysites.com",
    "webflow.io", "framer.app", "carrd.co", "sites.google.com", "forms.gle", "surge.sh", "onrender.com",
    "fly.dev", "translate.goog", "duckdns.org", "no-ip.org", "hopto.org", "serveo.net", "my.canva.site",
}

HOST_FEATURE_NAMES: list[str] = [
    "host_len", "reg_label_len", "n_dots", "n_subdomain_parts", "n_hyphens", "n_digits", "digit_ratio",
    "host_entropy", "label_entropy", "has_punycode", "non_ascii", "kw_count", "brand_in_subdomain",
    "brand_distance", "brand_exact_registered", "brand_substring", "is_shortener", "suspicious_tld",
    "tld_len", "longest_token", "max_digit_run", "has_ip_host", "vowel_ratio", "free_hosting",
    "consonant_run",
]


def clean_host(host_or_url: str) -> str:
    _, _, host, _ = parse(host_or_url)
    return host[4:] if host.startswith("www.") else host


def host_features(host_or_url: str) -> dict[str, float]:
    host = clean_host(host_or_url)
    ext = _extract(host)
    reg = ext.registered_domain or host
    label = ext.domain.lower()
    sub = ext.subdomain.lower()
    brand, dist = brand_match(label)
    exact = label in BRANDS
    letters = [c for c in host if c.isalpha()]
    cons_runs = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", host)
    return {
        "host_len": len(host),
        "reg_label_len": len(label),
        "n_dots": host.count("."),
        "n_subdomain_parts": len([p for p in sub.split(".") if p]),
        "n_hyphens": host.count("-"),
        "n_digits": sum(c.isdigit() for c in host),
        "digit_ratio": sum(c.isdigit() for c in host) / max(len(host), 1),
        "host_entropy": _entropy(host),
        "label_entropy": _entropy(label),
        "has_punycode": float("xn--" in host),
        "non_ascii": float(any(ord(c) > 127 for c in host)),
        "kw_count": sum(host.count(k) for k in KEYWORDS),
        "brand_in_subdomain": float(any(b in sub for b in BRANDS if len(b) >= 4) and not exact),
        "brand_distance": float(min(dist, 6)),
        "brand_exact_registered": float(exact),
        "brand_substring": float(any(b in label for b in BRANDS if len(b) >= 4) and not exact),
        "is_shortener": float(reg in SHORTENERS),
        "suspicious_tld": float(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        "tld_len": len(ext.suffix),
        "longest_token": max((len(t) for t in re.split(r"[^a-z0-9]+", host)), default=0),
        "max_digit_run": max((len(r) for r in re.findall(r"\d+", host)), default=0),
        "has_ip_host": float(is_ip(host)),
        "vowel_ratio": sum(c in "aeiou" for c in letters) / max(len(letters), 1),
        "free_hosting": float(reg in FREE_HOSTING or any(host.endswith("." + f) for f in FREE_HOSTING)),
        "consonant_run": max((len(r) for r in cons_runs), default=0),
    }


def host_vector(host_or_url: str) -> list[float]:
    f = host_features(host_or_url)
    return [f[n] for n in HOST_FEATURE_NAMES]
