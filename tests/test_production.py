import asyncio
import io
import json
import shutil
from email.message import EmailMessage

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.analyzer import analyze_payload, classify_payload
from app.artifact import decode_artifact
from app.decoder import DecodeError, decode_qr
from app.main import app
from app.payment import analyze_emv_qr

PIX_SAMPLE = "00020101021226910014br.gov.bcb.pix2569qrcodes.fiduciascm.digital/v1/qr/ded35b9c-fdf8-4789-ba97-24f26cc9327252040000530398654041.005802BR5910Woovi_Demo6009Sao_Paulo6229052544e554f94d8a4d4cb72a1848f630470AA"


def _png(payload: str) -> bytes:
    import zxingcpp
    barcode = zxingcpp.create_barcode(payload, zxingcpp.BarcodeFormat.QRCode)
    array = np.asarray(zxingcpp.write_barcode_to_image(barcode, 500))
    output = io.BytesIO()
    Image.fromarray(array).save(output, format="PNG")
    return output.getvalue()


def test_authenticator_migration_bundle_is_fully_redacted():
    # Top-level protobuf field 1 containing a deliberately recognizable seed.
    encoded = "ChJTRUNSRVRfU0VFRF9DQU5BUlk="
    payload = f"otpauth-migration://offline?data={encoded}"
    result = asyncio.run(analyze_payload(payload))
    serialized = json.dumps(result.to_dict())
    assert encoded not in serialized
    assert "SECRET_SEED_CANARY" not in serialized
    assert result.payload_redacted
    assert "migration_data" in result.sensitive_fields
    assert result.decoded_details["authentication_export"]["entry_count"] == 1


def test_emv_classifier_accepts_dynamic_pix_urls_and_symbols():
    assert classify_payload(PIX_SAMPLE) == "emv-payment"
    details = analyze_emv_qr(PIX_SAMPLE)
    assert details["payment_network"] == "Pix / BR Code"
    assert "qrcodes.fiduciascm.digital" not in json.dumps(details)


def test_url_parser_ambiguity_abstains_and_never_selects_host():
    result = asyncio.run(analyze_payload(r"https://trusted.example\@evil.example/login", network_checks=True))
    assert result.verdict == "Unable to determine"
    assert result.normalized_url is None
    assert "URL_PARSER_AMBIGUITY" in {item.code for item in result.findings}


def test_fido_and_android_intent_are_structured():
    fido = asyncio.run(analyze_payload("FIDO:/123456789012345678901234567890"))
    assert fido.payload_type == "authentication-session"
    assert fido.score >= 42
    intent = asyncio.run(analyze_payload("intent://scan/#Intent;scheme=zxing;package=com.example.app;S.browser_fallback_url=https%3A%2F%2Fevil.example%2Flogin;end"))
    assert intent.decoded_details["android_intent"]["package"] == "com.example.app"
    assert intent.decoded_details["android_intent"]["fallback_host"] == "evil.example"


def test_integrity_seal_is_present():
    result = asyncio.run(analyze_payload("hello"))
    assert len(result.evidence_integrity["canonical_result_sha256"]) == 64


def test_email_attachment_qr_and_surrounding_context():
    message = EmailMessage()
    message["Subject"] = "Account alert"
    message.set_content("Urgent action. Verify your account and enter OTP immediately.")
    message.add_attachment(_png("https://example.org/login"), maintype="image", subtype="png", filename="notice.png")
    decoded = decode_artifact(message.as_bytes(), "notice.eml", "message/rfc822")
    assert decoded[0]["payload"] == "https://example.org/login"
    assert "Urgent action" in decoded[0]["context_text"]
    result = asyncio.run(analyze_payload(**{key: decoded[0][key] for key in ("payload", "sha256", "image_analysis", "context_text")}))
    assert any(item.code.startswith("CONTEXT_") for item in result.findings)


@pytest.mark.skipif(shutil.which("pdftoppm") is None, reason="Poppler unavailable")
def test_pdf_qr_ingestion():
    image = Image.open(io.BytesIO(_png("https://example.org/pdf-evidence"))).convert("RGB")
    source = io.BytesIO(); image.save(source, format="PDF")
    decoded = decode_artifact(source.getvalue(), "evidence.pdf", "application/pdf")
    assert decoded[0]["payload"] == "https://example.org/pdf-evidence"
    assert decoded[0]["image_analysis"]["source"]["container"] == "PDF"


def test_zxing_is_restricted_to_qr_family():
    zxingcpp = pytest.importorskip("zxingcpp")
    for barcode_format in (zxingcpp.BarcodeFormat.DataMatrix, zxingcpp.BarcodeFormat.Code128, zxingcpp.BarcodeFormat.Aztec):
        barcode = zxingcpp.create_barcode("https://example.org/not-a-qr", barcode_format)
        array = np.asarray(zxingcpp.write_barcode_to_image(barcode, 300))
        output = io.BytesIO(); Image.fromarray(array).save(output, format="PNG")
        with pytest.raises(DecodeError):
            decode_qr(output.getvalue())


def test_new_language_policy_detects_coordinated_russian_lure():
    result = asyncio.run(analyze_payload("Срочно: ваш аккаунт будет заблокирован. Подтвердите учетную запись и введите код."))
    assert "MULTILINGUAL_SOCIAL_ENGINEERING" in {item.code for item in result.findings}


def test_network_preflight_requires_server_enablement(monkeypatch):
    monkeypatch.delenv("QR_SHIELD_ALLOW_NETWORK_PREFLIGHT", raising=False)
    result = asyncio.run(analyze_payload("https://example.org/", network_checks=True))
    assert "PREFLIGHT_DISABLED" in {item.code for item in result.findings}
    assert not result.resolved_ips


def test_optional_api_key_authentication(monkeypatch):
    monkeypatch.setenv("QR_SHIELD_API_KEY", "test-secret-key")
    with TestClient(app) as client:
        denied = client.post("/api/analyze/text", json={"payload": "hello", "network_checks": False})
        allowed = client.post("/api/analyze/text", headers={"X-API-Key": "test-secret-key"}, json={"payload": "hello", "network_checks": False})
    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_file_api_accepts_image_evidence(monkeypatch):
    monkeypatch.delenv("QR_SHIELD_API_KEY", raising=False)
    with TestClient(app) as client:
        response = client.post("/api/analyze/file", files={"file": ("qr.png", _png("https://example.org/api"), "image/png")}, data={"network_checks": "false"})
    assert response.status_code == 200
    assert response.json()["results"][0]["normalized_url"] == "https://example.org/api"
