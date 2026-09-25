import io
import os

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.analyzer import (
    _destination_graph,
    _is_public_ip,
    analyze_payload,
    normalize_http_url,
)
from app.decoder import DecodeError, decode_qr
from app.main import app
from app.offline_intel import local_blocklist
from app.url_intelligence import _obfuscated_ip

client = TestClient(app)


@pytest.mark.asyncio
async def test_mfa_secret_never_enters_result():
    result = await analyze_payload("otpauth://totp/Example?secret=TOPSECRET&issuer=Bank")
    exported = result.to_dict()
    assert "TOPSECRET" not in str(exported)
    assert exported["payload_redacted"] is True
    assert exported["payload_sha256"]


@pytest.mark.asyncio
async def test_wifi_password_never_enters_result():
    result = await analyze_payload(r"WIFI:T:WPA;S:Office;P:VerySecret123;;")
    assert "VerySecret123" not in str(result.to_dict())
    assert "wifi_password" in result.sensitive_fields


@pytest.mark.asyncio
async def test_url_secret_query_is_redacted_everywhere():
    result = await analyze_payload("https://example.com/login?token=abcdef&next=%2Fhome")
    assert "abcdef" not in str(result.to_dict())
    assert result.payload_redacted


@pytest.mark.asyncio
async def test_dpp_bootstrap_key_is_redacted():
    result = await analyze_payload("DPP:K:super-secret-bootstrap;M:010203040506;;")
    assert "super-secret-bootstrap" not in str(result.to_dict())
    assert result.payload_type == "wifi"


@pytest.mark.parametrize("value", ["false", 0, 1, None, [], {}])
def test_network_flag_is_strict_boolean(value):
    response = client.post("/api/analyze/text", json={"payload": "https://example.com", "network_checks": value})
    assert response.status_code == 422


def test_extra_request_fields_are_rejected():
    response = client.post("/api/analyze/text", json={"payload": "hello", "network_checks": False, "admin": True})
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("127.0.1", "127.0.0.1"),
    ],
)
def test_whatwg_style_obfuscated_ipv4(host, expected):
    assert _obfuscated_ip(host) == expected


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "fe80::1"])
def test_non_public_address_classes_are_blocked(address):
    assert not _is_public_ip(address)


def test_uts46_idna_normalization():
    _url, display, host = normalize_http_url("https://faß.de/")
    assert host.startswith("xn--")
    assert display == "faß.de"


def test_recursive_destination_graph_is_bounded_and_redacted():
    root = "https://one.example/?next=https%3A%2F%2Ftwo.example%2F%3Furl%3Dhttps%253A%252F%252Fthree.example%252F%253Ftoken%253Dsecret"
    graph = _destination_graph(root, max_depth=3, max_nodes=4)
    assert 2 <= len(graph) <= 4
    assert "secret" not in str(graph)


def test_animated_image_is_rejected():
    first = Image.new("RGB", (100, 100), "white")
    second = Image.new("RGB", (100, 100), "black")
    buf = io.BytesIO()
    first.save(buf, format="WEBP", save_all=True, append_images=[second], duration=100, loop=0)
    with pytest.raises(DecodeError, match="Animated|multi-frame"):
        decode_qr(buf.getvalue())


def test_local_blocklist_reports_pack_id_not_filesystem_path():
    _domains, _urls, source = local_blocklist()
    assert source.startswith("local-pack:")
    assert os.sep not in source


@pytest.mark.asyncio
async def test_grouped_scoring_is_reported():
    result = await analyze_payload("https://singpass-login-secure.example/verify?redirect=https://evil.example")
    assert "risk_groups" in result.engine
    assert result.engine["score_type"].startswith("explainable")
    assert result.engine["external_api_required"] is False


def test_security_headers_do_not_allow_inline_application_styles():
    response = client.get("/")
    assert "style-src 'self'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
