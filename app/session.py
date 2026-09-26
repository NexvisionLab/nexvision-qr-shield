"""Stateless browser sessions for the web UI.

A signed cookie stands in for the API key so the page never keeps the key in
script-readable storage. The signing key is derived from ``QR_SHIELD_API_KEY``,
so rotating the API key ends every existing session.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

SESSION_COOKIE = "qrs_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


def _signing_key(api_key: str) -> bytes:
    return hmac.new(api_key.encode("utf-8"), b"qr-shield-ui-session-v1", hashlib.sha256).digest()


def _signature(api_key: str, body: str) -> str:
    return hmac.new(_signing_key(api_key), body.encode("ascii"), hashlib.sha256).hexdigest()


def keys_match(supplied: str, api_key: str) -> bool:
    # Compare bytes: compare_digest rejects non-ASCII str input with TypeError.
    return bool(supplied) and hmac.compare_digest(supplied.encode("utf-8", "surrogateescape"), api_key.encode("utf-8"))


def issue_session(api_key: str, now: float) -> str:
    body = f"{int(now) + SESSION_TTL_SECONDS}.{secrets.token_urlsafe(16)}"
    return f"{body}.{_signature(api_key, body)}"


def session_valid(token: str, api_key: str, now: float) -> bool:
    expiry, _, rest = token.partition(".")
    nonce, _, signature = rest.partition(".")
    if not (expiry.isdigit() and nonce and signature and token.isascii()):
        return False
    expected = _signature(api_key, f"{expiry}.{nonce}")
    return hmac.compare_digest(signature, expected) and int(expiry) > now
