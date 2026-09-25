import pytest

from app.analyzer import analyze_payload, classify_payload, normalize_http_url


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("https://example.com", "url"),
        ("WIFI:T:WPA;S:Guest;P:secret;;", "wifi"),
        ("otpauth://totp/Example?secret=ABC", "authentication-secret"),
        ("mailto:help@example.com", "email"),
        ("javascript:alert(1)", "dangerous-scheme"),
        ("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "cryptocurrency-payment"),
        ("0002010102116304FFFF", "emv-payment"),
        ("hello", "text"),
    ],
)
def test_classification(payload, expected):
    assert classify_payload(payload) == expected


def test_normalization_removes_fragment_and_idna_encodes():
    url, display, ascii_host = normalize_http_url("https://bücher.example/a#secret")
    assert url == "https://xn--bcher-kva.example/a"
    assert display == "bücher.example"
    assert ascii_host == "xn--bcher-kva.example"


@pytest.mark.asyncio
async def test_credentials_are_critical_without_network():
    result = await analyze_payload("https://trusted.example@evil.example/login", network_checks=False)
    assert any(item.code == "URL_CREDENTIALS" for item in result.findings)
    assert result.verdict == "Dangerous"


@pytest.mark.asyncio
async def test_mfa_secret_is_protected():
    result = await analyze_payload("otpauth://totp/Test?secret=ABCDEF", network_checks=False)
    assert result.payload_type == "authentication-secret"
    assert result.score >= 60


@pytest.mark.asyncio
async def test_dangerous_scheme_is_blocked_offline():
    result = await analyze_payload("javascript:alert(document.cookie)")
    assert result.verdict == "Dangerous"
    assert any(item.code == "DANGEROUS_SCHEME" for item in result.findings)


@pytest.mark.asyncio
async def test_brand_impersonation_is_detected():
    result = await analyze_payload("https://singpass-login-secure.example/verify", network_checks=False)
    assert any(item.code == "BRAND_IMPERSONATION" for item in result.findings)


@pytest.mark.asyncio
async def test_nested_redirect_is_detected():
    result = await analyze_payload("https://example.com/go?redirect=https%3A%2F%2Fevil.test%2Flogin")
    assert any(item.code == "NESTED_URL" for item in result.findings)


@pytest.mark.asyncio
async def test_open_wifi_is_detected():
    result = await analyze_payload("WIFI:T:nopass;S:Free Airport WiFi;;")
    assert any(item.code == "OPEN_WIFI" for item in result.findings)


@pytest.mark.asyncio
async def test_invalid_emv_crc_is_detected():
    result = await analyze_payload("0002010102116304FFFF")
    assert any(item.code == "EMV_CRC_INVALID" for item in result.findings)


@pytest.mark.asyncio
async def test_plain_text_does_not_become_url():
    result = await analyze_payload("Meeting room 4", network_checks=False)
    assert result.verdict == "Low observable risk"
    assert result.normalized_url is None


@pytest.mark.asyncio
async def test_disabled_network_checks_do_not_resolve(monkeypatch):
    async def forbidden(_host):
        raise AssertionError("DNS must not run when network checks are disabled")

    monkeypatch.setattr("app.analyzer.resolve_public_ips", forbidden)
    result = await analyze_payload("https://example.com", network_checks=False)
    assert result.reputation[0]["status"] == "loaded"
    assert result.engine["mode"] == "fully offline"


def test_ipv6_normalization_keeps_brackets():
    url, _, host = normalize_http_url("https://[2001:4860:4860::8888]/")
    assert url == "https://[2001:4860:4860::8888]/"
    assert host == "2001:4860:4860::8888"
