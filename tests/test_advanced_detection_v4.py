from __future__ import annotations

import base64

import cv2
import pytest

from app.advanced_url import analyze_advanced_url
from app.analyzer import analyze_payload, classify_payload, normalize_http_url
from app.decoder import decode_qr
from app.evasion import analyze_evasion
from app.payment import analyze_epc_qr, iban_valid


def _codes(findings):
    return {item.code for item in findings}


def _advanced(url: str):
    normalized, _display, host = normalize_http_url(url)
    return analyze_advanced_url(url, normalized, host)


def test_base64_hidden_url_is_detected():
    token = base64.b64encode(b"https://evil.example/login").decode()
    findings, details = analyze_evasion(token)
    assert "HIDDEN_ENCODED_URL" in _codes(findings)
    assert details["hidden_url_count"] == 1


def test_base64_hidden_dangerous_scheme_is_detected():
    token = base64.b64encode(b"javascript:alert(1)").decode()
    findings, _details = analyze_evasion(token)
    assert "HIDDEN_DANGEROUS_SCHEME" in _codes(findings)


def test_html_entity_hidden_url_is_detected():
    findings, _details = analyze_evasion("https&#58;//evil.example/verify")
    assert "HIDDEN_ENCODED_URL" in _codes(findings)


def test_json_escaped_hidden_url_is_detected():
    findings, _details = analyze_evasion(r"\u0068\u0074\u0074\u0070\u0073://evil.example/login")
    assert "HIDDEN_ENCODED_URL" in _codes(findings)


def test_multistage_base64_is_detected():
    inner = base64.b64encode(b"https://evil.example/login").decode()
    outer = base64.b64encode(inner.encode()).decode()
    findings, details = analyze_evasion(outer)
    assert "MULTISTAGE_ENCODING" in _codes(findings)
    assert max(item["depth"] for item in details["layers"]) >= 2


def test_split_security_terms_are_recovered():
    findings, details = analyze_evasion("v.e.r.i.f.y a.c.c.o.u.n.t and p.a.s.s.w.o.r.d")
    assert "OBFUSCATED_SECURITY_TERMS" in _codes(findings)
    assert {"verify", "account", "password"} <= set(details["recovered_obfuscated_terms"])


def test_normal_percent_encoding_is_not_called_hidden_destination():
    findings, details = analyze_evasion("https://example.com/search?q=hello%20world")
    assert "HIDDEN_ENCODED_URL" not in _codes(findings)
    assert details["hidden_url_count"] == 0


def test_brand_claim_outside_official_domain():
    findings, details = _advanced("https://evil.example/singpass/verify/account")
    assert "CLAIMED_BRAND_MISMATCH" in _codes(findings)
    assert "singpass" in details["claimed_brands_outside_host"]


def test_official_brand_domain_is_not_mismatch():
    findings, _details = _advanced("https://singpass.gov.sg/verify/account")
    assert "CLAIMED_BRAND_MISMATCH" not in _codes(findings)


def test_brand_name_inside_unrelated_word_is_not_claim():
    findings, _details = _advanced("https://example.com/pineapple/verify/account")
    assert "CLAIMED_BRAND_MISMATCH" not in _codes(findings)


def test_shared_hosting_auth_lure():
    findings, details = _advanced("https://secure-login-example.vercel.app/account/verify/password")
    assert "HOSTED_AUTH_LURE" in _codes(findings)
    assert details["shared_infrastructure"] == "vercel.app"


def test_benign_shared_hosting_without_auth_is_not_scored():
    findings, _details = _advanced("https://portfolio-user.github.io/projects")
    assert "HOSTED_AUTH_LURE" not in _codes(findings)


def test_hosting_provider_root_is_not_treated_as_tenant_lure():
    findings, _details = _advanced("https://vercel.app/login/verify/account")
    assert "HOSTED_AUTH_LURE" not in _codes(findings)


def test_fragment_auth_lure():
    findings, details = _advanced("https://example.com/#/login/verify/account")
    assert "FRAGMENT_LURE" in _codes(findings)
    assert details["fragment_present"] is True


def test_double_extension_download():
    findings, _details = _advanced("https://example.com/invoice.pdf.exe")
    assert "DOUBLE_EXTENSION_DOWNLOAD" in _codes(findings)


def test_repeated_encoded_delimiters():
    findings, details = _advanced("https://example.com/go?x=%252F%2540%255C")
    assert "ENCODED_URL_DELIMITERS" in _codes(findings)
    assert details["encoded_separator_count"] >= 3


def test_valid_iban_and_epc_payment():
    payload = "BCD\n001\n1\nSCT\nCOBADEFFXXX\nExample Beneficiary\nDE89370400440532013000\nEUR12.34\nOTHR\nRF18539007547034\n\nInvoice"
    assert iban_valid("DE89370400440532013000")
    details = analyze_epc_qr(payload)
    assert details["structure_valid"]
    assert details["iban_last4"] == "3000"
    assert "Example Beneficiary" not in str(details)


def test_invalid_epc_payment():
    payload = "BCD\n001\n1\nSCT\n\nExample\nDE00370400440532013000\nEUR9999999999.00"
    details = analyze_epc_qr(payload)
    assert not details["structure_valid"]
    assert any("IBAN" in issue for issue in details["validation_issues"])


@pytest.mark.asyncio
async def test_epc_payload_is_classified_and_redacted():
    payload = "BCD\n001\n1\nSCT\nCOBADEFFXXX\nPrivate Person\nDE89370400440532013000\nEUR12.34\nOTHR\nRF18539007547034"
    result = await analyze_payload(payload)
    assert result.payload_type == "epc-payment"
    assert "DE89370400440532013000" not in str(result.to_dict())
    assert "Private Person" not in str(result.to_dict())
    assert "EPC_PAYMENT" in _codes(result.findings)


def test_walletconnect_classification():
    assert classify_payload("wc:topic@2?relay-protocol=irn&symKey=abcdef") == "wallet-session"


@pytest.mark.asyncio
async def test_walletconnect_secret_is_redacted():
    result = await analyze_payload("wc:topic@2?relay-protocol=irn&symKey=SUPERSECRET")
    assert "SUPERSECRET" not in str(result.to_dict())
    assert "WALLETCONNECT_SESSION" in _codes(result.findings)


@pytest.mark.asyncio
async def test_message_header_injection():
    result = await analyze_payload("mailto:help@example.com?subject=Hello%0d%0aBcc:attacker@example.net")
    assert "MESSAGE_HEADER_INJECTION" in _codes(result.findings)


@pytest.mark.asyncio
async def test_enterprise_wifi_without_validation_constraints():
    result = await analyze_payload("WIFI:T:WPA2-EAP;S:Corporate;I:user;;")
    assert "ENTERPRISE_WIFI_VALIDATION_MISSING" in _codes(result.findings)


@pytest.mark.asyncio
async def test_compound_attack_chain_fusion():
    hidden = base64.b64encode(b"https://collector.example/login").decode()
    result = await analyze_payload(f"https://evil.example/singpass/urgent-action/verify-your-account?data={hidden}")
    assert "COMPOUND_ATTACK_CHAIN" in _codes(result.findings)
    assert result.decoded_details["attack_chain"]["stage_count"] >= 3


@pytest.mark.asyncio
async def test_advanced_analysis_remains_offline(monkeypatch):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("network must remain disabled")

    monkeypatch.setattr("app.analyzer.resolve_public_ips", forbidden)
    result = await analyze_payload("https://evil.example/singpass/verify/account", network_checks=False)
    assert result.engine["mode"] == "fully offline"
    assert result.engine["external_api_required"] is False


def test_qr_structural_profile_is_reported():
    image = cv2.QRCodeEncoder_create().encode("https://example.com")
    ok, encoded = cv2.imencode(".png", image)
    assert ok
    _payloads, _digest, evidence = decode_qr(encoded.tobytes())
    profile = evidence["qr_structure"][0]
    assert 0 < profile["dark_module_ratio"] < 1
    assert 0 <= profile["center_uniformity"] <= 1
    assert 0 <= profile["timing_alternation_ratio"] <= 1


@pytest.mark.asyncio
async def test_decoded_evasion_evidence_does_not_leak_nested_secret():
    hidden = base64.b64encode(b"https://evil.example/?token=DO-NOT-LEAK").decode()
    result = await analyze_payload(hidden)
    assert "DO-NOT-LEAK" not in str(result.to_dict())
    assert "HIDDEN_ENCODED_URL" in _codes(result.findings)


def test_recursive_decoder_respects_state_budget():
    parts = [base64.b64encode(f"https://site{i}.example/login".encode()).decode() for i in range(30)]
    _findings, details = analyze_evasion(" ".join(parts), max_states=6)
    assert details["decoded_layer_count"] <= 5
