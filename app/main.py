from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import time
import uuid
from collections import Counter, deque
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .analyzer import analyze_payload
from .artifact import MAX_ARTIFACT_BYTES, decode_artifact
from .decoder import DecodeError, decode_qr
from .session import (
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    issue_session,
    keys_match,
    session_valid,
)

BASE = Path(__file__).resolve().parent
PRODUCTION = os.getenv("QR_SHIELD_ENV", "development").casefold() == "production"
app = FastAPI(title="NexVision QR Shield", version=__version__, docs_url=None if PRODUCTION else "/api/docs", redoc_url=None)
allowed_hosts = [item.strip() for item in os.getenv("QR_SHIELD_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if item.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
DECODE_LIMIT = asyncio.Semaphore(2)
REQUESTS: dict[str, deque[float]] = {}
OVERFLOW_REQUESTS: deque[float] = deque()
MAX_RATE_KEYS = 10_000
RATE_LIMIT = 60
RATE_WINDOW_SECONDS = 60
logger = logging.getLogger("qr_shield.audit")


def _apply_security_headers(response, request_id: str):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), geolocation=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob: data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Request-ID"] = request_id
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _consume_rate_limit(key: str, now: float) -> bool:
    cutoff = now - RATE_WINDOW_SECONDS
    window = REQUESTS.get(key)
    if window is None:
        if len(REQUESTS) >= MAX_RATE_KEYS:
            for existing_key, existing in list(REQUESTS.items()):
                while existing and existing[0] < cutoff:
                    existing.popleft()
                if not existing:
                    REQUESTS.pop(existing_key, None)
        if len(REQUESTS) < MAX_RATE_KEYS:
            window = REQUESTS.setdefault(key, deque())
        else:
            window = OVERFLOW_REQUESTS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return False
    window.append(now)
    return True


def _strict_form_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise HTTPException(422, "network_checks must be exactly 'true' or 'false'.")


def _secret_is_strong(value: str) -> bool:
    if len(value) < 32 or value != value.strip() or any(char.isspace() for char in value):
        return False
    counts = Counter(value)
    entropy_bits = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) * len(value)
    return len(counts) >= 12 and entropy_bits >= 128


def _production_controls() -> tuple[dict[str, bool], bool]:
    api_key = os.getenv("QR_SHIELD_API_KEY", "")
    hmac_key = os.getenv("QR_SHIELD_REPORT_HMAC_KEY", "")
    controls = {
        "production_mode": PRODUCTION,
        "api_authentication": _secret_is_strong(api_key),
        "report_hmac": _secret_is_strong(hmac_key),
        "separate_secrets": bool(api_key and hmac_key and api_key != hmac_key),
        "trusted_hosts_restricted": bool(allowed_hosts) and "*" not in allowed_hosts,
        "network_preflight_enabled": os.getenv("QR_SHIELD_ALLOW_NETWORK_PREFLIGHT") == "1",
        "offline_ocr_enabled": os.getenv("QR_SHIELD_OCR") == "1",
    }
    ready = not PRODUCTION or all(
        controls[name]
        for name in ("api_authentication", "report_hmac", "separate_secrets", "trusted_hosts_restricted")
    )
    return controls, ready


class TextAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    payload: StrictStr
    network_checks: StrictBool = False

    @field_validator("payload")
    @classmethod
    def payload_size(cls, value: str) -> str:
        if not value.strip() or len(value) > 8192:
            raise ValueError("Payload must contain 1 to 8,192 characters.")
        return value


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key: StrictStr

    @field_validator("key")
    @classmethod
    def key_size(cls, value: str) -> str:
        if not value or len(value) > 1024:
            raise ValueError("Access key must contain 1 to 1,024 characters.")
        return value


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("x-request-id", "")
    if not request_id or len(request_id) > 128 or not all(char.isalnum() or char in "-_." for char in request_id):
        request_id = str(uuid.uuid4())
    key = request.client.host if request.client else "unknown"
    if not _consume_rate_limit(key, time.monotonic()):
        response = JSONResponse({"detail": "Rate limit exceeded. Try again shortly."}, status_code=429)
        response.headers["Retry-After"] = str(RATE_WINDOW_SECONDS)
        return _apply_security_headers(response, request_id)
    if request.url.path.startswith("/api/") and PRODUCTION:
        _controls, ready = _production_controls()
        if not ready:
            return _apply_security_headers(JSONResponse({"detail": "Production security configuration is incomplete."}, status_code=503), request_id)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("sec-fetch-site", "").casefold() == "cross-site":
        return _apply_security_headers(JSONResponse({"detail": "Cross-site request rejected."}, status_code=403), request_id)
    api_key = os.getenv("QR_SHIELD_API_KEY", "")
    if request.url.path.startswith("/api/") and request.url.path != "/api/session" and api_key:
        supplied = request.headers.get("x-api-key", "")
        authorization = request.headers.get("authorization", "")
        if authorization.casefold().startswith("bearer "):
            supplied = authorization[7:]
        if not (keys_match(supplied, api_key) or session_valid(request.cookies.get(SESSION_COOKIE, ""), api_key, time.time())):
            return _apply_security_headers(JSONResponse({"detail": "Authentication required."}, status_code=401), request_id)
    response = await call_next(request)
    return _apply_security_headers(response, request_id)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"version": __version__})


def _session_state(request: Request) -> dict[str, bool]:
    api_key = os.getenv("QR_SHIELD_API_KEY", "")
    if not api_key:
        return {"auth_required": False, "authenticated": True}
    return {"auth_required": True, "authenticated": session_valid(request.cookies.get(SESSION_COOKIE, ""), api_key, time.time())}


@app.get("/api/session")
async def session_status(request: Request):
    return _session_state(request)


@app.post("/api/session")
async def sign_in(body: SessionRequest, request: Request):
    api_key = os.getenv("QR_SHIELD_API_KEY", "")
    if not api_key:
        return _session_state(request)
    if not keys_match(body.key, api_key):
        logger.info(json.dumps({"event": "ui_sign_in_rejected"}))
        raise HTTPException(401, "Access key not accepted.")
    response = JSONResponse({"auth_required": True, "authenticated": True})
    response.set_cookie(
        SESSION_COOKIE, issue_session(api_key, time.time()), max_age=SESSION_TTL_SECONDS, path="/api",
        httponly=True, samesite="strict", secure=PRODUCTION or request.url.scheme == "https",
    )
    logger.info(json.dumps({"event": "ui_sign_in"}))
    return response


@app.delete("/api/session")
async def sign_out():
    response = JSONResponse({"auth_required": bool(os.getenv("QR_SHIELD_API_KEY")), "authenticated": False})
    response.delete_cookie(SESSION_COOKIE, path="/api", httponly=True, samesite="strict", secure=PRODUCTION)
    return response


@app.get("/health")
async def health():
    controls, ready = _production_controls()
    content = {"status": "ok" if ready else "configuration-required", "version": __version__, "production_ready": ready, "controls": controls}
    return JSONResponse(content, status_code=200 if ready else 503)


@app.post("/api/analyze/image")
async def analyze_image(
    file: Annotated[UploadFile, File()],
    network_checks: Annotated[str, Form()] = "false",
):
    network_enabled = _strict_form_bool(network_checks)
    content_type = (file.content_type or "").lower()
    if content_type and not content_type.startswith("image/"):
        raise HTTPException(415, "Only image uploads are accepted.")
    data = await file.read(12 * 1024 * 1024 + 1)
    try:
        async with DECODE_LIMIT:
            payloads, digest, image_analysis = await asyncio.wait_for(asyncio.to_thread(decode_qr, data), 15.0)
    except TimeoutError as exc:
        raise HTTPException(408, "QR decoding exceeded the 15-second safety limit.") from exc
    except DecodeError as exc:
        raise HTTPException(422, str(exc)) from exc
    results = [await analyze_payload(payload, digest, network_enabled, image_analysis) for payload in payloads]
    logger.info(json.dumps({"event": "image_analysis", "count": len(results), "verdicts": [item.verdict for item in results], "image_sha256": digest}))
    return {"count": len(results), "results": [result.to_dict() for result in results]}


@app.post("/api/analyze/file")
async def analyze_file(
    file: Annotated[UploadFile, File()],
    network_checks: Annotated[str, Form()] = "false",
):
    network_enabled = _strict_form_bool(network_checks)
    data = await file.read(MAX_ARTIFACT_BYTES + 1)
    try:
        async with DECODE_LIMIT:
            decoded = await asyncio.wait_for(
                asyncio.to_thread(decode_artifact, data, file.filename or "", file.content_type or ""), 35.0
            )
    except TimeoutError as exc:
        raise HTTPException(408, "Artifact decoding exceeded the safety time limit.") from exc
    except DecodeError as exc:
        raise HTTPException(422, str(exc)) from exc
    results = [await analyze_payload(item["payload"], item["sha256"], network_enabled, item["image_analysis"], item["context_text"]) for item in decoded]
    artifact_hash = hashlib.sha256(data).hexdigest()
    logger.info(json.dumps({"event": "artifact_analysis", "count": len(results), "verdicts": [item.verdict for item in results], "artifact_sha256": artifact_hash}))
    return {"count": len(results), "artifact_sha256": artifact_hash, "results": [result.to_dict() for result in results]}


@app.post("/api/analyze/text")
async def analyze_text(body: TextAnalysisRequest):
    result = await analyze_payload(body.payload, network_checks=body.network_checks)
    logger.info(json.dumps({"event": "text_analysis", "verdict": result.verdict, "payload_sha256": result.payload_sha256}))
    return JSONResponse(result.to_dict())
