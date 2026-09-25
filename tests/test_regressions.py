import asyncio
import json

import pytest

from app import analyzer
from app.analyzer import (
    _is_public_ip,
    analyze_payload,
    inspect_redirects,
    normalize_http_url,
)
from app.offline_intel import _load_blocklist, blocklist_match
from app.payment import (
    analyze_crypto_uri,
    analyze_emv_qr,
    analyze_epc_qr,
    analyze_upi_uri,
    crc16_ccitt_false,
)
from app.url_intelligence import _obfuscated_ip


def _run(payload: str):
    return asyncio.run(analyze_payload(payload))


def _codes(result) -> set[str]:
    return {item.code for item in result.findings if item.score}


@pytest.mark.parametrize("url", [
    "https://www.dbs.com.sg/",
    "https://www.cpf.gov.sg/",
    "https://www.google.com.sg/",
    "https://outlook.live.com/",
    "https://onedrive.live.com/",
    "https://fonts.googleapis.com/css",
    "https://s3.amazonaws.com/bucket",
])
def test_official_domains_are_not_flagged_as_impersonation(url):
    result = _run(url)
    assert not _codes(result) & {"BRAND_IN_SUBDOMAIN", "BRAND_IMPERSONATION"}
    assert result.verdict == "Low observable risk"


@pytest.mark.parametrize("url", [
    "https://paypal.evil.example/",
    "https://www.dbs.com.sg.evil.xyz/",
])
def test_brand_in_untrusted_subdomain_is_still_flagged(url):
    assert "BRAND_IN_SUBDOMAIN" in _codes(_run(url))


@pytest.mark.parametrize("payload, secret", [
    ("https://x.example/?next=http%3A%2F%2Fh.example%2F%3Fa%3D%27%26token%3DNESTEDSECRET", "NESTEDSECRET"),
    ("https://x.example/?uri=otpauth%3A%2F%2Ftotp%2Fx%3Fsecret%3DJBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
    ("WIFI:S:Cafe;T:WPA;P:unterminated-pass", "unterminated-pass"),
    ("DPP:C:81/1;K:MDkwEwYHKoZIzj0CAQ", "MDkwEwYHKoZIzj0CAQ"),
])
def test_secrets_do_not_reach_serialized_results(payload, secret):
    assert secret not in json.dumps(_run(payload).to_dict())


def test_lone_surrogate_payload_is_analyzed_not_crashed():
    result = _run("hello \ud800 world")
    assert result.evidence_integrity["canonical_result_sha256"]


@pytest.mark.parametrize("host", ["0x7f.0.0.1", "017700000001", "0x7f000001", "2130706433", "127.1"])
def test_obfuscated_loopback_forms_are_decoded(host):
    assert _obfuscated_ip(host) == "127.0.0.1"


@pytest.mark.parametrize("host", ["example.com", "12345", "1.2.3.4"])
def test_ordinary_hosts_are_not_obfuscated_ips(host):
    assert _obfuscated_ip(host) is None


@pytest.mark.parametrize("address", ["64:ff9b::7f00:1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe"])
def test_embedded_private_ipv4_is_not_public(address):
    assert not _is_public_ip(address)


def test_url_blocklist_matches_normalized_forms(tmp_path, monkeypatch):
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text("url:https://evil.example\nurl:https://bücher.example/x#fragment\n", encoding="utf-8")
    monkeypatch.setenv("QR_SHIELD_BLOCKLIST", str(blocklist))
    _load_blocklist.cache_clear()
    try:
        for url in ("https://evil.example", "https://evil.example:443/", "https://bücher.example/x"):
            normalized, _display, host = normalize_http_url(url)
            assert blocklist_match(host, normalized)[0], url
    finally:
        _load_blocklist.cache_clear()


def _fake_network(monkeypatch, responses):
    async def resolve(host):
        return ["93.184.216.34"], []

    requested = []

    async def headers(url, ip, method="HEAD"):
        requested.append(url)
        response = responses[len(requested) - 1]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(analyzer, "resolve_public_ips", resolve)
    monkeypatch.setattr(analyzer, "_pinned_headers", headers)
    return requested


def test_redirect_to_nonstandard_port_is_not_followed(monkeypatch):
    requested = _fake_network(monkeypatch, [(302, {"location": "http://victim.example:6379/"}, "93.184.216.34")])
    _chain, findings = asyncio.run(inspect_redirects("https://start.example/"))
    assert requested == ["https://start.example/"]
    assert "PREFLIGHT_PORT_BLOCKED" in {item.code for item in findings}


def test_malformed_location_header_is_reported(monkeypatch):
    _fake_network(monkeypatch, [(302, {"location": "http://[::1"}, "93.184.216.34")])
    _chain, findings = asyncio.run(inspect_redirects("https://start.example/"))
    assert "MALFORMED_REDIRECT" in {item.code for item in findings}


def test_redirect_follows_the_normalized_host(monkeypatch):
    requested = _fake_network(monkeypatch, [
        (302, {"location": "https://BÜCHER.example/next"}, "93.184.216.34"),
        (200, {}, "93.184.216.34"),
    ])
    asyncio.run(inspect_redirects("https://start.example/"))
    assert requested[1].startswith("https://xn--bcher-kva.example/")


def test_malformed_status_line_raises_handled_error():
    async def scenario():
        async def reply(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(reply, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with pytest.raises(ValueError, match="status line"):
                await analyzer._pinned_headers(f"http://local.test:{port}/", "127.0.0.1")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


EPC_BASE = ["BCD", "002", "1", "SCT", "COBADEFFXXX", "Example Beneficiary", "DE89370400440532013000", "EUR12.34", "", "", "Invoice"]


def _epc(**changes):
    lines = list(EPC_BASE)
    for index, value in changes.items():
        lines[int(index[1:])] = value
    return "\n".join(lines)


def test_emv_crc_equal_to_its_own_tag_is_valid():
    payload = "0002010102115204599953037025802SG5909S0001109D6009SINGAPORE63046304"
    assert crc16_ccitt_false(payload[:-4]) == "6304"
    assert analyze_emv_qr(payload)["crc_valid"]


@pytest.mark.parametrize("changes", [
    {"f7": "EUR999999999.99"},
    {"f2": "3"},
    {"f8": "GDSV"},
])
def test_valid_epc_variants_are_accepted(changes):
    assert analyze_epc_qr(_epc(**changes))["validation_issues"] == []


@pytest.mark.parametrize("changes, issue", [
    ({"f7": "EUR\u0661\u0660"}, "amount"),
    ({"f6": "DE\u0668\u0669370400440532013000"}, "IBAN"),
    ({"f1": "001", "f4": ""}, "BIC is required"),
    ({"f5": "x" * 71}, "70 characters"),
])
def test_invalid_epc_variants_are_rejected(changes, issue):
    assert any(issue in item for item in analyze_epc_qr(_epc(**changes))["validation_issues"])


def test_non_ascii_digits_are_not_valid_amounts():
    assert analyze_upi_uri("upi://pay?pa=shop@bank&am=\u0661\u0660")["validation_issues"]
    assert analyze_crypto_uri("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=\u0661")["validation_issues"]


def test_bitcoin_address_case_rules():
    assert analyze_crypto_uri("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT")["structure_valid"]
    assert not analyze_crypto_uri("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyI")["structure_valid"]
    assert analyze_crypto_uri("bitcoin:BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")["structure_valid"]
    assert not analyze_crypto_uri("bitcoin:bc1qw508d6qejxtdg4y5r3zarvaRY0c5xw7kv8f3t4")["structure_valid"]


@pytest.mark.parametrize("uri", [
    "ethereum:pay-0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359?value=2.014e18",
    "ethereum:0x89205a3a3b2a69de6dbf7f01ed13b2108b2c43e7/transfer?address=0x8e23ee67d1332ad560396262c48ffbb01f93d052&uint256=1",
    "ethereum:0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359@1?value=1",
])
def test_eip681_payment_links_are_accepted(uri):
    assert analyze_crypto_uri(uri)["validation_issues"] == []
