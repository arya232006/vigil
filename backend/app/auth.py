"""Who is calling: email + password or Google accounts with server-side sessions.

Passwords are stored as Argon2id hashes. A session is a random token held by the browser in an HttpOnly cookie; the
database keeps only its SHA-256, so a leaked table can't be replayed, and deleting the row ends the session at once.

No cookie means a guest. A cookie that fails verification is always a 401, never a guest: treating it as a guest would
save a signed-in user's report with no owner, where anyone holding its link could read it.

Cookies are sent automatically, so any state-changing request that carries one must come from an allowed Origin.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import os
import re
import secrets
import time
from typing import Annotated
from urllib.parse import quote, unquote, urlencode

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from . import store

COOKIE = "vigil_session"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
MIN_PASSWORD = 10
MAX_PASSWORD = 128                  # bounds the work an attacker can make Argon2 do per request
SESSION_SECONDS = int(float(os.getenv("SESSION_TTL_DAYS", "14")) * 86_400)
EMAIL = re.compile(r"[^@\s]+@[^@\s.]+(\.[^@\s.]+)+")
DEFAULT_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3100,http://127.0.0.1:3100"

_hasher = PasswordHasher()


class Credentials(BaseModel):
    email: str
    password: str


def allowed_origins() -> list[str]:
    """Never "*": the API accepts credentials, so a wildcard would let any site act as the signed-in user."""
    return [o.strip() for o in os.getenv("CORS_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip() not in ("", "*")]


def require_allowed_origin(request: Request) -> None:
    if request.headers.get("origin") not in allowed_origins():
        raise HTTPException(403, "This request did not come from an allowed site")


def _same_site() -> str:
    value = os.getenv("SESSION_COOKIE_SAMESITE", "lax").strip().lower()
    return value if value in ("lax", "strict", "none") else "lax"


def _secure() -> bool:
    origins = allowed_origins()
    return _same_site() == "none" or (bool(origins) and all(o.startswith("https://") for o in origins))


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, path="/", httponly=True, secure=_secure(),
                        samesite=_same_site())


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE, path="/", httponly=True, secure=_secure(), samesite=_same_site())


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _start_session(user_id: str, response: Response) -> None:
    now = int(time.time())
    store.purge_sessions(now)
    token = secrets.token_urlsafe(32)
    store.create_session(_digest(token), user_id, now, now + SESSION_SECONDS)
    _set_cookie(response, token)


def _normalise_email(email: str) -> str:
    return email.strip().lower()


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(16))


def sign_up(credentials: Credentials, response: Response) -> dict:
    email = _normalise_email(credentials.email)
    if len(email) > 254 or not EMAIL.fullmatch(email):
        raise HTTPException(400, "Enter a valid email address")
    if not MIN_PASSWORD <= len(credentials.password) <= MAX_PASSWORD:
        raise HTTPException(400, f"Use a password of {MIN_PASSWORD} to {MAX_PASSWORD} characters")
    user_id = store.create_user(email, _hasher.hash(credentials.password), int(time.time()))
    if user_id is None:
        raise HTTPException(409, "An account with this email already exists")
    _start_session(user_id, response)
    return {"user": {"id": user_id, "email": email}}


def sign_in(credentials: Credentials, response: Response) -> dict:
    """Unknown emails do the same hashing work as wrong passwords, so timing doesn't reveal which emails have accounts."""
    email = _normalise_email(credentials.email)
    user = store.find_user(email)
    if user and not user[1]:                # a Google-only account has no password to match
        user = None
    stored = user[1] if user else _dummy_hash()
    try:
        _hasher.verify(stored, credentials.password[:MAX_PASSWORD + 1])
    except (VerificationError, InvalidHashError):
        user = None
    if user is None or len(credentials.password) > MAX_PASSWORD:
        raise HTTPException(401, "Incorrect email or password")
    if _hasher.check_needs_rehash(stored):
        store.set_password_hash(user[0], _hasher.hash(credentials.password))
    _start_session(user[0], response)
    return {"user": {"id": user[0], "email": email}}


def sign_out(request: Request, response: Response) -> dict:
    token = request.cookies.get(COOKIE)
    if token:
        store.delete_session(_digest(token))
    _clear_cookie(response)
    return {"ok": True}


def account(request: Request, response: Response) -> dict | None:
    """The signed-in account, or None. Used to learn the session state, so a stale cookie is cleared here, not refused."""
    token = request.cookies.get(COOKIE)
    if token is None:
        return None
    found = store.session_user(_digest(token), int(time.time()))
    if found is None:
        _clear_cookie(response)
        return None
    return {"id": found[0], "email": found[1]}


GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
OAUTH_COOKIE = "vigil_oauth"
OAUTH_PATH = "/api/auth/google"
OAUTH_SECONDS = 600
DEFAULT_NEXT = "/investigate"


def google_enabled() -> bool:
    return bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))


def _redirect_uri() -> str:
    return os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/google/callback")


def _frontend() -> str:
    origins = allowed_origins()
    return os.getenv("FRONTEND_URL", origins[0] if origins else "").rstrip("/")


def _safe_next(value: str) -> str:
    """Only paths on our own site, so a crafted link can't send someone elsewhere after they sign in."""
    return value if len(value) <= 512 and re.fullmatch(r"/(?![/\\])[^\s\\]*", value) else DEFAULT_NEXT


def google_start(next_path: str) -> RedirectResponse:
    if not google_enabled():
        raise HTTPException(404, "Google sign-in is not set up")
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urlencode({"client_id": os.environ["GOOGLE_CLIENT_ID"], "redirect_uri": _redirect_uri(), "response_type": "code",
                       "scope": "openid email", "state": state, "code_challenge": challenge,
                       "code_challenge_method": "S256", "prompt": "select_account"})
    response = RedirectResponse(f"{GOOGLE_AUTH}?{query}", 303)
    # Always Lax: this cookie must come back on the top-level redirect from Google, and that is all it needs.
    response.set_cookie(OAUTH_COOKIE, f"{state}.{verifier}.{quote(_safe_next(next_path), safe='')}", max_age=OAUTH_SECONDS,
                        path=OAUTH_PATH, httponly=True, secure=_secure(), samesite="lax")
    return response


def _google_identity(code: str, verifier: str) -> dict:
    with httpx.Client(timeout=10) as client:
        token = client.post(GOOGLE_TOKEN, data={
            "code": code, "client_id": os.environ["GOOGLE_CLIENT_ID"], "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": _redirect_uri(), "grant_type": "authorization_code", "code_verifier": verifier})
        token.raise_for_status()
        info = client.get(GOOGLE_USERINFO, headers={"Authorization": f"Bearer {token.json()['access_token']}"})
        info.raise_for_status()
        return info.json()


def google_finish(request: Request) -> RedirectResponse:
    """Any failure ends on the sign-in page, because the browser arrives here by redirect and can't show an API error."""
    if not google_enabled():
        raise HTTPException(404, "Google sign-in is not set up")
    failed = RedirectResponse(f"{_frontend()}/sign-in?error=google", 303)
    failed.delete_cookie(OAUTH_COOKIE, path=OAUTH_PATH)
    parts = request.cookies.get(OAUTH_COOKIE, "").split(".", 2)
    state, code = request.query_params.get("state", ""), request.query_params.get("code")
    if len(parts) != 3 or not code or not secrets.compare_digest(parts[0].encode(), state.encode()):
        return failed
    try:
        identity = _google_identity(code, parts[1])
    except (httpx.HTTPError, KeyError, ValueError):
        return failed
    if identity.get("email_verified") is not True or not identity.get("sub") or not identity.get("email"):
        return failed
    user_id = store.google_user(identity["sub"], _normalise_email(identity["email"]), int(time.time()))
    if user_id is None:
        return failed
    response = RedirectResponse(f"{_frontend()}{_safe_next(unquote(parts[2]))}", 303)
    response.delete_cookie(OAUTH_COOKIE, path=OAUTH_PATH)
    _start_session(user_id, response)
    return response


def current_user(request: Request) -> str | None:
    """The caller's user id, or None for a guest."""
    token = request.cookies.get(COOKIE)
    if token is None:
        return None
    if request.method not in SAFE_METHODS:
        require_allowed_origin(request)
    found = store.session_user(_digest(token), int(time.time()))
    if found is None:
        cleared = Response()
        _clear_cookie(cleared)
        raise HTTPException(401, "Your session is invalid or has expired", headers={"Set-Cookie": cleared.headers["set-cookie"]})
    return found[0]


def require_user(user: Annotated[str | None, Depends(current_user)]) -> str:
    if user is None:
        raise HTTPException(401, "Sign in to see this")
    return user


Viewer = Annotated[str | None, Depends(current_user)]
SignedInUser = Annotated[str, Depends(require_user)]
