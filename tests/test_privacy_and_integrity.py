from __future__ import annotations

import asyncio
import io
import json
import string
from collections import deque
from email.message import EmailMessage

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.analyzer import analyze_payload
from app.artifact import decode_artifact
from app.decoder import decode_qr
from app.main import (
    MAX_RATE_KEYS,
    OVERFLOW_REQUESTS,
    REQUESTS,
    _consume_rate_limit,
    app,
)
from app.offline_intel import _load_blocklist, blocklist_match
from app.payment import TLVError, creditor_reference_valid, parse_tlv

client = TestClient(app)


def _strong_test_secret(offset: int) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(alphabet[(index * 17 + offset) % len(alphabet)] for index in range(48))


def _png(payload: str) -> bytes:
    import zxingcpp

    barcode = zxingcpp.create_barcode(payload, zxingcpp.BarcodeFormat.QRCode)
    array = np.asarray(zxingcpp.write_barcode_to_image(barcode, 500))
    output = io.BytesIO()
    Image.fromarray(array).save(output, format="PNG")
    return output.getvalue()


@pytest.mark.parametrize(
    "payload,canary",
    [
        ("FIDO:/FIDO-SESSION-CANARY", "FIDO-SESSION-CANARY"),
        ("tg://login?token=ACCOUNT-LINK-CANARY", "ACCOUNT-LINK-CANARY"),
        ("data:text/plain,DANGEROUS-CANARY", "DANGEROUS-CANARY"),
        (
            "intent://scan/#Intent;S.browser_fallback_url=https%3A%2F%2Fevil.test%2F%3Ftoken%3DINTENT-CANARY;end",
            "INTENT-CANARY",
        ),
        (
            "mailto:help@example.test?body=See%20https%3A%2F%2Fevil.test%2F%3Ftoken%3DMAIL-CANARY",
            "MAIL-CANARY",
        ),
        ("https://example.test/#access_token=FRAGMENT-CANARY", "FRAGMENT-CANARY"),
        ("https://[invalid/?token=MALFORMED-CANARY", "MALFORMED-CANARY"),
    ],
)
def test_sensitive_action_canaries_never_enter_results(payload, canary):
    result = asyncio.run(analyze_payload(payload))
    assert canary not in json.dumps(result.to_dict())
    assert result.payload_redacted


@pytest.mark.parametrize("kind", ["email", "sms"])
def test_personal_redaction_continues_into_nested_urls(monkeypatch, kind):
    monkeypatch.setenv("QR_SHIELD_REDACTION_LEVEL", "personal")
    scheme = "mailto:person@example.test?body=" if kind == "email" else "sms:+15551234567?body="
    payload = scheme + "See%20https%3A%2F%2Fevil.test%2F%3Ftoken%3DPERSONAL-CANARY"
    result = asyncio.run(analyze_payload(payload)).to_dict()
    assert "PERSONAL-CANARY" not in json.dumps(result)
    assert result["payload_redacted"]


@pytest.mark.parametrize("endpoint", ["/api/analyze/image", "/api/analyze/file"])
def test_multipart_network_flag_requires_exact_boolean_text(endpoint):
    response = client.post(
        endpoint,
        files={"file": ("qr.png", b"not-used", "image/png")},
        data={"network_checks": "yes"},
    )
    assert response.status_code == 422


def test_rate_state_is_bounded_and_uses_single_overflow_bucket():
    REQUESTS.clear()
    OVERFLOW_REQUESTS.clear()
    for index in range(MAX_RATE_KEYS):
        REQUESTS[f"client-{index}"] = deque([100.0])
    assert _consume_rate_limit("new-client", 100.0)
    assert len(REQUESTS) == MAX_RATE_KEYS
    assert len(OVERFLOW_REQUESTS) == 1
    REQUESTS.clear()
    OVERFLOW_REQUESTS.clear()


def test_auth_failure_keeps_security_headers(monkeypatch):
    monkeypatch.setenv("QR_SHIELD_API_KEY", "A" * 32)
    response = client.post("/api/analyze/text", json={"payload": "hello", "network_checks": False})
    assert response.status_code == 401
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-request-id"]


def test_production_health_fails_closed_for_weak_or_reused_secrets(monkeypatch):
    monkeypatch.setattr("app.main.PRODUCTION", True)
    monkeypatch.setenv("QR_SHIELD_API_KEY", "short")
    monkeypatch.setenv("QR_SHIELD_REPORT_HMAC_KEY", "short")
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["production_ready"] is False
    blocked = client.post("/api/analyze/text", headers={"X-API-Key": "short"}, json={"payload": "hello", "network_checks": False})
    assert blocked.status_code == 503


def test_production_health_accepts_distinct_high_entropy_secrets(monkeypatch):
    monkeypatch.setattr("app.main.PRODUCTION", True)
    monkeypatch.setenv("QR_SHIELD_API_KEY", _strong_test_secret(3))
    monkeypatch.setenv("QR_SHIELD_REPORT_HMAC_KEY", _strong_test_secret(9))
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["production_ready"] is True


def test_production_health_rejects_long_low_entropy_placeholders(monkeypatch):
    monkeypatch.setattr("app.main.PRODUCTION", True)
    monkeypatch.setenv("QR_SHIELD_API_KEY", "A" * 64)
    monkeypatch.setenv("QR_SHIELD_REPORT_HMAC_KEY", "B" * 64)
    response = client.get("/health")
    assert response.status_code == 503


def test_weak_hmac_key_does_not_claim_signed_evidence(monkeypatch):
    monkeypatch.setenv("QR_SHIELD_REPORT_HMAC_KEY", "weak")
    result = asyncio.run(analyze_payload("hello"))
    assert result.evidence_integrity["signed"] is False


def test_tlv_rejects_a_length_that_splits_utf8_codepoint():
    with pytest.raises(TLVError, match="UTF-8"):
        parse_tlv("0001é")


def test_iso_11649_creditor_reference_uses_correct_length_rules():
    assert creditor_reference_valid("RF18539007547034")
    assert not creditor_reference_valid("RF00539007547034")


def test_exact_url_blocklist_preserves_path_case(tmp_path, monkeypatch):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("url:https://Example.test/CaseSensitive\n", encoding="utf-8")
    monkeypatch.setenv("QR_SHIELD_BLOCKLIST", str(blocklist))
    _load_blocklist.cache_clear()
    assert blocklist_match("example.test", "https://example.test/CaseSensitive")[0]
    assert not blocklist_match("example.test", "https://example.test/casesensitive")[0]
    _load_blocklist.cache_clear()


@pytest.mark.parametrize("format_name,payload", [("MicroQRCode", "HELLO"), ("RMQRCode", "https://x.co/a")])
def test_zxing_only_formats_report_decoded_count(format_name, payload):
    import zxingcpp

    barcode = zxingcpp.create_barcode(payload, getattr(zxingcpp.BarcodeFormat, format_name))
    image = np.asarray(zxingcpp.write_barcode_to_image(barcode, 200))
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    payloads, _digest, evidence = decode_qr(encoded.tobytes())
    assert payloads == [payload]
    assert evidence["decoders"]["opencv"]["decoded_count"] == 0
    assert evidence["qr_count"] == 1
    assert evidence["detected_geometry_count"] == 0


def test_email_subject_contributes_to_surrounding_context():
    message = EmailMessage()
    message["Subject"] = "Urgent: verify your account and enter OTP"
    message.set_content("See attached notice.")
    message.add_attachment(_png("https://example.org/login"), maintype="image", subtype="png", filename="notice.png")
    decoded = decode_artifact(message.as_bytes(), "notice.eml", "message/rfc822")
    assert "Urgent: verify your account" in decoded[0]["context_text"]
