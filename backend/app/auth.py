"""Who is calling: verifies Clerk session tokens sent as `Authorization: Bearer <token>`.

No header means a guest. A header that fails verification is always a 401, never a guest: treating it as a guest would
save a signed-in user's report with no owner, where anyone holding its link could read it.

Configured by CLERK_PUBLISHABLE_KEY. Only Clerk's public signing keys are used, so the backend needs no secret.
"""
from __future__ import annotations

import base64
import binascii
import functools
import os
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient


def _issuer() -> str | None:
    """A publishable key is pk_<env>_<base64 of the instance's Frontend API host + '$'>."""
    parts = os.getenv("CLERK_PUBLISHABLE_KEY", "").strip().split("_", 2)
    if len(parts) != 3:
        return None
    try:
        host = base64.b64decode(parts[2] + "=" * (-len(parts[2]) % 4)).decode().rstrip("$")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return f"https://{host}" if host else None


@functools.lru_cache(maxsize=4)
def _jwks_client(issuer: str) -> PyJWKClient:
    # Keys are cached. An explicit User-Agent because Python's default one can be refused by CDNs.
    return PyJWKClient(f"{issuer}/.well-known/jwks.json", cache_keys=True, lifespan=3600, timeout=5,
                       headers={"User-Agent": "vigil-api"})


def _signing_key(token: str, issuer: str):
    return _jwks_client(issuer).get_signing_key_from_jwt(token).key


DEFAULT_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3100,http://127.0.0.1:3100"


def cors_origins() -> list[str]:
    return [o.strip() for o in os.getenv("CORS_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()]


def _allowed_origins() -> list[str]:
    return [o for o in cors_origins() if o != "*"]


def current_user(request: Request) -> str | None:
    """The caller's Clerk user id, or None for a guest."""
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Invalid authorization header")
    issuer = _issuer()
    if issuer is None:
        raise HTTPException(503, "Sign-in is not configured on this server")
    try:
        claims = jwt.decode(token.strip(), _signing_key(token.strip(), issuer), algorithms=["RS256"], issuer=issuer,
                            leeway=5, options={"require": ["exp", "iat", "iss", "sub"]})
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(503, "Sign-in could not be verified right now. Try again.") from None
    except jwt.PyJWTError:
        raise HTTPException(401, "Your session is invalid or has expired") from None
    origins, azp = _allowed_origins(), claims.get("azp")
    if origins and azp not in origins and (azp is not None or "CORS_ORIGINS" in os.environ):
        raise HTTPException(401, "Your session is not valid for this site")
    return claims["sub"]


def require_user(user: Annotated[str | None, Depends(current_user)]) -> str:
    if user is None:
        raise HTTPException(401, "Sign in to see this")
    return user


Viewer = Annotated[str | None, Depends(current_user)]
SignedInUser = Annotated[str, Depends(require_user)]
