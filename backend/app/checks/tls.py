"""TLS certificate & web-trust analysis.

A valid certificate is never treated as proof that a site is safe: it only proves the connection is encrypted
to whoever controls the domain.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import socket
import ssl
import threading
from pathlib import Path

import certifi
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from ..schemas import Finding, Severity, TLSInfo
from .fetcher import BlockedTarget, safe_request

DISTRUSTED = json.loads((Path(__file__).resolve().parent.parent / "data" / "distrusted_cas.json").read_text())["entries"]
NOW = lambda: dt.datetime.now(dt.timezone.utc)  # noqa: E731

# ---- Trivially-weak EC key detection ---------------------------------------------------------------
# In the Oct 2026 eMudhra incident one intermediate's private key was the integer 4. If a private scalar is
# tiny, the public key equals k*G for small k, which we can test from the public key alone.
WEAK_K_MAX = 1 << 14
_weak: dict[tuple[str, int], int] = {}
_weak_ready = threading.Event()


def _build_weak_table() -> None:
    for curve in (ec.SECP256R1(), ec.SECP384R1()):
        for k in range(1, WEAK_K_MAX + 1):
            _weak[(curve.name, ec.derive_private_key(k, curve).public_key().public_numbers().x)] = k
    _weak_ready.set()


threading.Thread(target=_build_weak_table, daemon=True).start()


def weak_key_check(cert: x509.Certificate) -> str | None:
    pk = cert.public_key()
    if isinstance(pk, ec.EllipticCurvePublicKey):
        _weak_ready.wait(timeout=20)
        k = _weak.get((pk.curve.name, pk.public_numbers().x))
        if k:
            return f"EC private key is the trivially small integer {k} (public key = {k}·G)"
    if isinstance(pk, rsa.RSAPublicKey):
        n = pk.public_numbers().n
        if pk.key_size < 1024:
            return f"RSA modulus only {pk.key_size} bits"
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(200):                         # Fermat: factors fast if p and q are too close
            b2 = a * a - n
            b = math.isqrt(b2)
            if b * b == b2:
                return "RSA modulus factorable with Fermat's method (primes too close together)"
            a += 1
    return None


# ---- Helpers ----------------------------------------------------------------------------------------
def _name(n: x509.Name) -> str:
    return n.rfc4514_string()


def _attr(n: x509.Name, oid) -> str | None:
    v = n.get_attributes_for_oid(oid)
    return v[0].value if v else None


def _key_desc(cert: x509.Certificate) -> tuple[str, int | None]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC {pk.curve.name}", pk.curve.key_size
    return type(pk).__name__.replace("PublicKey", ""), None


def _san(cert: x509.Certificate) -> list[str]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def _sct_count(cert: x509.Certificate) -> int:
    try:
        return len(cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value)
    except x509.ExtensionNotFound:
        return 0


def _connect(host: str, ip: str, port: int, verify: bool, legacy: bool = False):
    """Handshake with one retry on transient network errors (resets/timeouts are common under rate limiting)."""
    for attempt in range(2):
        try:
            return _connect_once(host, ip, port, verify, legacy)
        except (ConnectionResetError, TimeoutError, socket.timeout) :
            if attempt == 1 or legacy:
                raise
            import time as _t
            _t.sleep(0.8)


def _connect_once(host: str, ip: str, port: int, verify: bool, legacy: bool = False):
    if verify:
        ctx = ssl.create_default_context(cafile=certifi.where())
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if legacy:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with socket.create_connection((ip, port), timeout=6) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            chain = t.get_verified_chain() if verify else t.get_unverified_chain()
            return t.version(), t.cipher(), [x509.load_der_x509_certificate(c) for c in chain]


def _revocation(leaf: x509.Certificate, issuer: x509.Certificate | None) -> tuple[str, str]:
    """Return (status, source). status: good | revoked | unknown."""
    try:
        aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp_urls = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        ocsp_urls = []
    if ocsp_urls and issuer is not None:
        try:
            req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
            code, body = safe_request("POST", ocsp_urls[0], req.public_bytes(serialization.Encoding.DER),
                                      {"Content-Type": "application/ocsp-request"}, max_bytes=200_000)
            r = ocsp.load_der_ocsp_response(body)
            if r.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                st = r.certificate_status
                return ("revoked" if st == ocsp.OCSPCertStatus.REVOKED else
                        "good" if st == ocsp.OCSPCertStatus.GOOD else "unknown"), f"OCSP {ocsp_urls[0]}"
        except (BlockedTarget, httpx.HTTPError, ValueError, OSError):
            pass
    try:
        dps = leaf.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        urls = [n.value for dp in dps for n in (dp.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        urls = []
    for u in urls[:1]:
        try:
            code, body = safe_request("GET", u, max_bytes=8_000_000, timeout=8)
            crl = x509.load_der_x509_crl(body) if not body.startswith(b"-----") else x509.load_pem_x509_crl(body)
            return ("revoked" if crl.get_revoked_certificate_by_serial_number(leaf.serial_number) else "good"), f"CRL {u}"
        except (BlockedTarget, httpx.HTTPError, ValueError, OSError):
            continue
    return "unknown", "no reachable OCSP/CRL"


def ct_lookup(domain: str, leaf_serial_hex: str | None) -> dict:
    """Query crt.sh (public Certificate Transparency aggregator). Best effort, short timeout."""
    try:
        r = httpx.get("https://crt.sh/", params={"q": domain, "output": "json", "exclude": "expired"}, timeout=3.5)
        rows = r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        rows = None
    if rows is None:
        return {"available": False}
    recent_cut = (NOW() - dt.timedelta(days=30)).date().isoformat()
    serials = {str(x.get("serial_number", "")).lower().lstrip("0") for x in rows}
    issuers = sorted({x.get("issuer_name", "") for x in rows})[:10]
    return {
        "available": True,
        "entries": len(rows),
        "issued_last_30d": sum(1 for x in rows if str(x.get("not_before", "")) >= recent_cut),
        "issuers": issuers,
        "leaf_logged": (leaf_serial_hex or "").lower().lstrip("0") in serials if leaf_serial_hex else None,
    }


def _distrust_hits(chain: list[x509.Certificate]) -> list[dict]:
    hits = []
    for c in chain:
        names = f"{_name(c.subject)} | {_name(c.issuer)}"
        for e in DISTRUSTED:
            if any(s.lower() in names.lower() for s in e["match"]["name_contains"]):
                if e.get("issued_after") and c.not_valid_before_utc.date().isoformat() < e["issued_after"]:
                    continue
                hits.append({"entry": e, "cert": _attr(c.subject, NameOID.COMMON_NAME) or _name(c.subject)})
    uniq = {h["entry"]["id"]: h for h in hits}
    return list(uniq.values())


# ---- Main entry -------------------------------------------------------------------------------------
def analyze(host: str, ip: str, registered_domain: str | None, port: int = 443,
            do_ct: bool = True) -> tuple[TLSInfo, list[Finding], str]:
    """Returns (TLSInfo, findings, check_status_detail)."""
    info = TLSInfo(https=True)
    findings: list[Finding] = []

    def add(title, sev, desc, evidence, impact=None, rec=None, source="TLS handshake + X.509 parsing"):
        findings.append(Finding(id="", module="tls", title=title, severity=sev, description=desc,
                                evidence=evidence, source=source, impact=impact, recommendation=rec))

    verify_error = None
    try:
        version, cipher, vchain = _connect(host, ip, port, verify=True)
        info.valid = True
    except ssl.SSLCertVerificationError as e:
        info.valid, verify_error, vchain = False, e.verify_message, []
    except (OSError, ssl.SSLError) as e:
        info.https = False
        info.verdict = "unavailable"
        return info, findings, f"TLS connection failed: {e}"

    try:
        version, cipher, chain = _connect(host, ip, port, verify=False)
    except (OSError, ssl.SSLError) as e:
        return info, findings, f"TLS handshake failed: {e}"

    leaf = chain[0]
    issuer = chain[1] if len(chain) > 1 else None
    from concurrent.futures import ThreadPoolExecutor
    _ex = ThreadPoolExecutor(2)
    ct_future = _ex.submit(ct_lookup, registered_domain or host, format(leaf.serial_number, "x")) \
        if do_ct and info.valid else None
    legacy_future = _ex.submit(_connect, host, ip, port, False, True)
    key_type, key_bits = _key_desc(leaf)
    sans = _san(leaf)
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    info.subject_cn = _attr(leaf.subject, NameOID.COMMON_NAME)
    info.san = sans[:50]
    info.issuer = _attr(leaf.issuer, NameOID.COMMON_NAME) or _name(leaf.issuer)
    info.issuer_org = _attr(leaf.issuer, NameOID.ORGANIZATION_NAME)
    info.not_before, info.not_after = nb.isoformat(), na.isoformat()
    info.days_remaining = (na - NOW()).days
    info.hostname_match = hostname_matches(host, sans or ([info.subject_cn] if info.subject_cn else []))
    info.key_type, info.key_bits = key_type, key_bits
    info.signature_algorithm = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else "none"
    info.protocol = version
    full_chain = vchain or chain
    info.chain = [{
        "subject": _attr(c.subject, NameOID.COMMON_NAME) or _name(c.subject),
        "issuer": _attr(c.issuer, NameOID.COMMON_NAME) or _name(c.issuer),
        "org": _attr(c.subject, NameOID.ORGANIZATION_NAME),
        "not_after": c.not_valid_after_utc.date().isoformat(),
        "key": " ".join(str(x) for x in _key_desc(c) if x),
        "sha256": c.fingerprint(hashes.SHA256()).hex(),
    } for c in full_chain]
    ev = {"host": host, "issuer": info.issuer, "subject_cn": info.subject_cn, "not_after": info.not_after,
          "protocol": version}

    compromised = suspicious = False

    if verify_error:
        suspicious = True
        add("Certificate failed validation", Severity.HIGH,
            f"Browsers would reject this certificate: {verify_error}.", {**ev, "verify_error": verify_error},
            "Users see a security warning; attackers may be intercepting or impersonating the site.",
            "Do not enter any information on this site.")
    if info.days_remaining is not None and info.days_remaining < 0:
        suspicious = True
        add("Certificate expired", Severity.HIGH, f"The certificate expired {-info.days_remaining} days ago.",
            {**ev, "days_remaining": info.days_remaining}, "Connection authenticity can no longer be relied on.",
            "Site owner must renew the certificate.")
    if nb > NOW():
        suspicious = True
        add("Certificate not yet valid", Severity.MEDIUM, "The certificate's validity period has not started.", ev)
    if info.hostname_match is False:
        suspicious = True
        add("Hostname does not match certificate", Severity.HIGH,
            f"The certificate is issued for {sans[:5] or info.subject_cn}, not for {host}.",
            {**ev, "san": sans[:10]}, "Typical of misconfiguration or impersonation.", "Do not trust this site.")
    if leaf.issuer == leaf.subject:
        suspicious = True
        add("Self-signed certificate", Severity.HIGH, "The certificate is signed by itself, not by a trusted CA.", ev,
            "Anyone can create such a certificate; it proves nothing about identity.")
    if info.signature_algorithm in ("sha1", "md5"):
        suspicious = True
        add("Weak signature algorithm", Severity.HIGH, f"Certificate signed with {info.signature_algorithm.upper()}.",
            ev, "Collision attacks make forged certificates feasible.")
    if (key_type == "RSA" and key_bits and key_bits < 2048) or (key_type.startswith("EC") and key_bits and key_bits < 256):
        suspicious = True
        add("Inadequate key size", Severity.HIGH, f"{key_type} key of {key_bits} bits is below current minimums.",
            {**ev, "key": f"{key_type} {key_bits}"})
    lifetime = (na - nb).days
    if lifetime > 398 and nb > dt.datetime(2020, 9, 1, tzinfo=dt.timezone.utc) and info.valid:
        add("Unusually long certificate lifetime", Severity.LOW,
            f"Lifetime is {lifetime} days; publicly trusted certificates are limited to 398 days.",
            {**ev, "lifetime_days": lifetime})
    age_days = (NOW() - nb).days
    if 0 <= age_days <= 7:
        add("Recently issued certificate", Severity.INFO,
            f"Certificate issued {age_days} day(s) ago. Common for new phishing sites, but also for normal renewals.",
            {**ev, "issued_days_ago": age_days})

    # Weak keys anywhere in the presented chain (eMudhra-style)
    for c in chain:
        w = weak_key_check(c)
        if w:
            compromised = True
            add("Trivially weak CA/certificate key detected", Severity.CRITICAL,
                f"{_attr(c.subject, NameOID.COMMON_NAME)}: {w}. Anyone can derive this private key and forge certificates.",
                {**ev, "certificate": _attr(c.subject, NameOID.COMMON_NAME), "detail": w,
                 "sha256": c.fingerprint(hashes.SHA256()).hex()},
                "The trust chain is cryptographically broken.", "Treat the connection as untrusted.",
                source="Public-key weak-scalar test (detects this specific weakness class only)")

    for h in _distrust_hits(full_chain):
        e = h["entry"]
        sev = Severity(e["severity"])
        if sev in (Severity.CRITICAL, Severity.HIGH):
            compromised = True
        else:
            suspicious = True
        add(f"Chain includes a distrusted CA ({e['id']})", sev, f"{h['cert']}: {e['reason']}",
            {**ev, "distrust_since": e["since"], "matched_certificate": h["cert"]},
            "Browsers no longer trust certificates from this CA; it may be compromised.",
            "Site owner should migrate to a trusted CA.", source=f"Distrusted-CA dataset: {e['source']}")

    rev, rev_src = _revocation(leaf, issuer)
    if rev == "revoked":
        compromised = True
        add("Certificate has been revoked", Severity.CRITICAL,
            "The issuing CA has revoked this certificate (often after key compromise or mis-issuance).",
            {**ev, "revocation_source": rev_src}, "The certificate must not be trusted.", source=rev_src)

    scts = _sct_count(leaf)
    try:
        ct = ct_future.result(timeout=3.5) if ct_future else {"available": False}
    except Exception:
        ct = {"available": False}
    info.ct_log_entries = ct.get("entries")
    if info.valid and scts == 0:
        suspicious = True
        add("No Certificate Transparency proof", Severity.MEDIUM,
            "The certificate carries no embedded SCTs; publicly trusted certificates are normally logged in CT.",
            {**ev, "embedded_scts": 0})
    if ct.get("available") and ct.get("leaf_logged") is False and scts == 0:
        add("Certificate not found in CT logs", Severity.MEDIUM,
            "crt.sh has no record of this certificate's serial number for the domain.",
            {**ev, "ct_entries": ct.get("entries")}, source="crt.sh Certificate Transparency search")

    try:
        legacy_future.result(timeout=8)
        add("Deprecated TLS 1.0/1.1 accepted", Severity.MEDIUM, "Server still negotiates TLS 1.0 or 1.1.", ev,
            "Weak protocol versions enable downgrade and known cryptographic attacks.",
            "Disable TLS 1.0/1.1; allow TLS 1.2+ only.")
    except Exception:
        pass
    _ex.shutdown(wait=False)

    info.verdict = "potentially_compromised" if compromised else "suspicious" if suspicious else "valid"
    detail = f"{version}, issuer {info.issuer}, revocation {rev} ({rev_src}), SCTs {scts}"
    if ct.get("available"):
        detail += f", CT entries {ct['entries']} ({ct['issued_last_30d']} in last 30d)"
    return info, findings, detail
