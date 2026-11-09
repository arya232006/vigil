"""SSRF-safe, IP-pinned HTTP fetcher.

- Only http/https on standard web ports.
- Resolves the hostname, rejects any non-public IP (private, loopback, link-local incl. 169.254.169.254
  cloud metadata, CGNAT, multicast, reserved), then connects to that exact IP (defeats DNS rebinding)
  while sending the original Host header and TLS SNI.
- Follows redirects manually, re-validating every hop. Never executes JavaScript, never saves files,
  caps body size and total time.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_HOPS = 8
MAX_BYTES = 1_500_000
TIMEOUT = httpx.Timeout(8.0, connect=5.0)
MAX_TOTAL_SECONDS = 20.0              # whole fetch; the read timeout above only limits the gap between packets
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/130.0 Safari/537.36 Vigil/1.0")


class BlockedTarget(Exception):
    pass


class UnresolvableHost(BlockedTarget):
    """DNS failed: the site is offline / taken down / never existed (not an SSRF block)."""


@dataclass
class Hop:
    url: str
    status: int | None = None
    ip: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class FetchResult:
    hops: list[Hop]
    final_url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    content_type: str
    truncated: bool
    error: str | None = None
    elapsed_ms: int = 0


def normalize_url(raw: str) -> str:
    s = raw.strip().strip("<>\"'")
    s = s.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")   # defanged IOCs
    if "://" not in s:
        s = "http://" + s
    try:
        sp = urlsplit(s)
    except ValueError as e:
        raise BlockedTarget("invalid URL") from e
    if sp.scheme.lower() not in ("http", "https"):
        raise BlockedTarget(f"scheme '{sp.scheme}' not allowed")
    host = (sp.hostname or "").rstrip(".")
    if not host:
        raise BlockedTarget("no hostname")
    try:
        port = sp.port
    except ValueError as e:
        raise BlockedTarget(f"invalid port: {e}") from e
    if ":" in host:                                   # IPv6 literal
        host_idna = f"[{host.lower()}]"
    else:
        try:
            host_idna = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            host_idna = host.lower()
    netloc = host_idna if port is None else f"{host_idna}:{port}"
    return urlunsplit((sp.scheme.lower(), netloc, sp.path or "/", sp.query, ""))


def is_public_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not (a.is_multicast or a.is_reserved or a.is_loopback or a.is_link_local)


def resolve_public(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnresolvableHost(f"DNS resolution failed: {e}") from e
    ips = sorted({i[4][0] for i in infos})
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise BlockedTarget("resolves to a private or internal address (SSRF protection)")
    return ips


def _pinned_request(client: httpx.Client, url: str, ip: str) -> httpx.Response:
    sp = urlsplit(url)
    host = sp.hostname or ""
    port = sp.port
    ip_host = f"[{ip}]" if ":" in ip else ip
    netloc = ip_host if port is None else f"{ip_host}:{port}"
    pinned = urlunsplit((sp.scheme, netloc, sp.path or "/", sp.query, ""))
    host_header = host if port is None else f"{host}:{port}"
    req = client.build_request(
        "GET", pinned,
        headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8",
                 "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-IN,en;q=0.9"},
        extensions={"sni_hostname": host},
    )
    return client.send(req, stream=True)


def safe_request(method: str, raw_url: str, content: bytes | None = None, headers: dict | None = None,
                 max_bytes: int = 5_000_000, timeout: float = 6.0) -> tuple[int, bytes]:
    """Single SSRF-checked, IP-pinned request (no redirects). Used for OCSP/CRL URLs taken from certificates,
    which are attacker-controlled input."""
    url = normalize_url(raw_url)
    sp = urlsplit(url)
    port = sp.port or (443 if sp.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise BlockedTarget(f"port {port} not allowed")
    ip = resolve_public(sp.hostname or "", port)[0]
    ip_host = f"[{ip}]" if ":" in ip else ip
    pinned = urlunsplit((sp.scheme, ip_host if sp.port is None else f"{ip_host}:{sp.port}", sp.path or "/", sp.query, ""))
    h = {"Host": sp.netloc, "User-Agent": USER_AGENT, **(headers or {})}
    with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
        req = c.build_request(method, pinned, headers=h, content=content, extensions={"sni_hostname": sp.hostname})
        resp = c.send(req, stream=True)
        deadline = time.monotonic() + MAX_TOTAL_SECONDS
        try:
            body = bytearray()
            for chunk in resp.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise BlockedTarget("response too large")
                if time.monotonic() > deadline:
                    raise BlockedTarget("response too slow")
            return resp.status_code, bytes(body)
        finally:
            resp.close()


def safe_fetch(raw_url: str) -> FetchResult:
    t0 = time.monotonic()
    url = normalize_url(raw_url)
    hops: list[Hop] = []
    # verify=False: content fetch only. Certificate trust is analysed separately in tls.py.
    with httpx.Client(verify=False, follow_redirects=False, timeout=TIMEOUT) as client:
        for _ in range(MAX_HOPS + 1):
            if time.monotonic() - t0 > MAX_TOTAL_SECONDS:
                return FetchResult(hops, url, None, {}, b"", "", False, "fetch time limit reached",
                                   int((time.monotonic() - t0) * 1000))
            sp = urlsplit(url)
            port = sp.port or (443 if sp.scheme == "https" else 80)
            if port not in ALLOWED_PORTS:
                raise BlockedTarget(f"port {port} not allowed")
            ip = resolve_public(sp.hostname or "", port)[0]
            hop = Hop(url=url, ip=ip)
            hops.append(hop)
            try:
                resp = _pinned_request(client, url, ip)
            except httpx.HTTPError as e:
                return FetchResult(hops, url, None, {}, b"", "", False, f"{type(e).__name__}: {e}",
                                   int((time.monotonic() - t0) * 1000))
            hop.status = resp.status_code
            hop.headers = {k.lower(): v for k, v in resp.headers.items()}
            if resp.is_redirect and "location" in resp.headers:
                resp.close()
                url = normalize_url(urljoin(url, resp.headers["location"]))
                continue
            body = bytearray()
            truncated = False
            try:
                for chunk in resp.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BYTES or time.monotonic() - t0 > MAX_TOTAL_SECONDS:
                        truncated = True
                        break
            except httpx.HTTPError as e:
                return FetchResult(hops, url, resp.status_code, hop.headers, bytes(body), "", truncated,
                                   f"{type(e).__name__}: {e}", int((time.monotonic() - t0) * 1000))
            finally:
                resp.close()
            return FetchResult(hops, url, resp.status_code, hop.headers, bytes(body[:MAX_BYTES]),
                               hop.headers.get("content-type", ""), truncated, None,
                               int((time.monotonic() - t0) * 1000))
    return FetchResult(hops, url, None, {}, b"", "", False, f"too many redirects (>{MAX_HOPS})",
                       int((time.monotonic() - t0) * 1000))
