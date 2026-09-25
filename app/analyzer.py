from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import unicodedata
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

import idna

from .advanced_url import analyze_advanced_url
from .evasion import analyze_evasion
from .models import AnalysisResult, Finding
from .multilingual_intel import analyze_multilingual_text
from .offline_intel import intelligence_metadata, local_blocklist
from .payment import (
    analyze_crypto_uri,
    analyze_emv_qr,
    analyze_epc_qr,
    analyze_upi_uri,
    looks_like_emv_qr,
)
from .privacy import payload_digest, redact_mapping, redact_payload
from .url_intelligence import analyze_url_offline

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "lnkd.in", "qrco.de", "tiny.cc", "short.io", "s.id", "t.ly", "dub.sh", "linktr.ee"}
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "xyz", "work", "cam", "rest", "gq", "tk", "support", "live", "shop", "buzz", "monster", "beauty", "cyou", "quest"}
SUSPICIOUS_WORDS = re.compile(r"(?i)(login|logon|signin|verify|verification|secure|account|wallet|invoice|payment|update|unlock|suspend|urgent|gift|reward|bank|crypto|password|mfa|otp|refund|fine|delivery|parcel|customs|tax|paynow|singpass|confirm|expire|limited)")
DOWNLOAD_EXTENSIONS = re.compile(r"(?i)\.(exe|msi|msp|scr|bat|cmd|com|ps1|vbs|js|jse|jar|apk|dmg|pkg|iso|img|zip|rar|7z|hta|lnk|xll|docm|xlsm|one)(?:$|[?#])")
TRACKING_KEYS = {"utm_source", "utm_medium", "utm_campaign", "gclid", "fbclid", "mc_eid"}
URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")
DANGEROUS_SCHEMES = {"javascript", "data", "file", "smb", "intent", "shell", "ms-appx", "vbscript"}


def _finding(code: str, title: str, detail: str, severity: str, score: int = 0, **evidence) -> Finding:
    return Finding(code, title, detail, severity, score, evidence)


def classify_payload(payload: str) -> str:
    value, lower = payload.strip(), payload.strip().lower()
    if lower.startswith(("http://", "https://")): return "url"
    if lower.startswith(("wifi:", "dpp:")): return "wifi"
    if lower.startswith(("mailto:", "matmsg:")): return "email"
    if lower.startswith("tel:"): return "telephone"
    if lower.startswith(("sms:", "smsto:", "mms:", "mmsto:")): return "sms"
    if lower.startswith(("begin:vcard", "mecard:")): return "contact"
    if lower.startswith("begin:vevent"): return "calendar-event"
    if lower.startswith("geo:"): return "location"
    if lower.startswith(("otpauth:", "otpauth-migration:")): return "authentication-secret"
    if lower.startswith("fido:"): return "authentication-session"
    if lower.startswith(("tg://login", "whatsapp://link", "discord://login")): return "account-link-session"
    if lower.startswith("wc:"): return "wallet-session"
    if lower.startswith(("bitcoin:", "ethereum:", "litecoin:", "monero:")): return "cryptocurrency-payment"
    if lower.startswith(("upi://", "upi:")): return "upi-payment"
    if looks_like_emv_qr(value): return "emv-payment"
    if value.startswith(("BCD\n", "BCD\r\n")): return "epc-payment"
    scheme = lower.split(":", 1)[0] if ":" in lower else ""
    if scheme in DANGEROUS_SCHEMES: return "dangerous-scheme"
    if re.match(r"^[a-z][a-z0-9+.-]*:", lower): return "custom-scheme"
    if re.match(r"^(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:/|$)", lower): return "url-like"
    return "text"


def _url_interpretation_ambiguity(raw: str) -> dict | None:
    """Reject authority bytes known to diverge between RFC and browser parsers."""
    candidate = raw if raw.casefold().startswith(("http://", "https://")) else "https://" + raw
    authority = candidate.split("//", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    reasons = []
    if "\\" in authority:
        reasons.append("backslash in authority")
    if re.search(r"(?i)%(?:2f|5c|40|3a)", authority):
        reasons.append("encoded structural delimiter in authority")
    if any(unicodedata.category(char) in {"Cf", "Cc", "Zl", "Zp"} for char in authority):
        reasons.append("invisible or control character in authority")
    return {"reasons": reasons, "authority_sha256": hashlib.sha256(authority.encode("utf-8", "surrogatepass")).hexdigest()} if reasons else None


def _parse_otpauth(payload: str) -> dict:
    parsed = urlsplit(payload)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    algorithm = query.get("algorithm", "SHA1").upper()
    try: digits = int(query.get("digits", "6"))
    except ValueError: digits = -1
    try: period = int(query.get("period", "30"))
    except ValueError: period = -1
    label = unquote(parsed.path.lstrip("/"))
    label_issuer = label.split(":", 1)[0] if ":" in label else None
    issuer = query.get("issuer")
    return {
        "type": parsed.netloc.casefold() or "unknown",
        "algorithm": algorithm,
        "digits": digits,
        "period": period,
        "issuer_consistent": not (label_issuer and issuer) or label_issuer.casefold() == issuer.casefold(),
        "secret_present": bool(query.get("secret")),
        "valid_profile": algorithm in {"SHA1", "SHA256", "SHA512"} and digits in {6, 8} and 15 <= period <= 120,
    }


def _migration_entry_count(payload: str) -> int | None:
    """Count top-level repeated protobuf field 1 entries without decoding seeds."""
    try:
        value = dict(parse_qsl(urlsplit(payload).query, keep_blank_values=True)).get("data", "")
        raw = base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) > 65536:
        return None
    cursor = count = 0
    try:
        while cursor < len(raw):
            key = 0; shift = 0
            while True:
                byte = raw[cursor]; cursor += 1; key |= (byte & 0x7f) << shift
                if not byte & 0x80: break
                shift += 7
                if shift > 63: return None
            wire = key & 7; field = key >> 3
            if wire == 2:
                length = 0; shift = 0
                while True:
                    byte = raw[cursor]; cursor += 1; length |= (byte & 0x7f) << shift
                    if not byte & 0x80: break
                    shift += 7
                if field == 1: count += 1
                cursor += length
            elif wire == 0:
                while raw[cursor] & 0x80: cursor += 1
                cursor += 1
            elif wire == 1: cursor += 8
            elif wire == 5: cursor += 4
            else: return None
            if cursor > len(raw): return None
    except (IndexError, ValueError):
        return None
    return count


def _intent_details(payload: str) -> dict:
    fragment = payload.split("#Intent;", 1)[1].rsplit(";end", 1)[0] if "#Intent;" in payload else ""
    fields = {}
    for part in fragment.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = unquote(value)
    fallback = fields.get("S.browser_fallback_url")
    result = {
        "package": fields.get("package"), "component_present": "component" in fields,
        "action": fields.get("action"), "embedded_scheme": fields.get("scheme"),
        "fallback_present": bool(fallback), "extra_count": sum(key[:2] in {"S.", "B.", "i.", "l."} for key in fields),
    }
    if fallback:
        safe, _ = redact_payload(fallback, "url")
        result["fallback_url"] = safe
        result["fallback_host"] = urlsplit(fallback).hostname
    return result


def _seal_result(result: AnalysisResult) -> None:
    material = result.to_dict()
    material["evidence_integrity"] = {}
    canonical = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    result.evidence_integrity = {"algorithm": "SHA-256", "canonical_result_sha256": digest, "signed": False}
    key = os.getenv("QR_SHIELD_REPORT_HMAC_KEY", "").encode()
    if len(key) >= 32:
        result.evidence_integrity.update({"signed": True, "signature_algorithm": "HMAC-SHA256", "signature": hmac.new(key, canonical, hashlib.sha256).hexdigest()})


def _is_public_ip(value: str) -> bool:
    try: return ipaddress.ip_address(value).is_global
    except ValueError: return False


async def resolve_public_ips(host: str) -> tuple[list[str], list[str]]:
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)),
            3.0,
        )
    except (TimeoutError, socket.gaierror):
        return [], []
    all_ips = sorted({item[4][0] for item in records})
    return [ip for ip in all_ips if _is_public_ip(ip)], [ip for ip in all_ips if not _is_public_ip(ip)]


def _scripts(text: str) -> set[str]:
    scripts: set[str] = set()
    known = ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "DEVANAGARI", "BENGALI", "TAMIL", "THAI")
    for char in text:
        if char.isalpha():
            name = unicodedata.name(char, "")
            scripts.update(script for script in known if script in name)
    return scripts


def normalize_http_url(raw: str) -> tuple[str, str, str]:
    candidate = raw.strip()
    if any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in candidate):
        raise ValueError("Control characters are not allowed")
    if not candidate.lower().startswith(("http://", "https://")): candidate = "https://" + candidate
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname: raise ValueError("Invalid HTTP(S) URL")
    display_host = parsed.hostname.rstrip(".")
    try:
        ascii_host = ipaddress.ip_address(display_host).compressed
    except ValueError:
        ascii_host = idna.encode(display_host, uts46=True, std3_rules=True).decode("ascii").lower()
    if len(ascii_host) > 253 or (":" not in ascii_host and any(len(label) > 63 or not label for label in ascii_host.split("."))):
        raise ValueError("Invalid hostname length")
    port = parsed.port
    formatted_host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    return urlunsplit((parsed.scheme.lower(), formatted_host + (f":{port}" if port else ""), parsed.path or "/", parsed.query, "")), display_host, ascii_host


def _static_url_findings(url: str, display_host: str, ascii_host: str) -> list[Finding]:
    p, findings, host = urlsplit(url), [], ascii_host.strip(".")
    labels, decoded_url = host.split("."), unquote(url)
    if p.scheme == "http": findings.append(_finding("HTTP_PLAINTEXT", "Connection is not encrypted", "The destination uses HTTP, so traffic may be intercepted or altered.", "high", 22))
    try:
        ipaddress.ip_address(host.strip("[]")); findings.append(_finding("IP_HOST", "Direct IP address", "The destination uses an IP address instead of a recognizable domain.", "high", 25))
    except ValueError: pass
    if host.startswith("xn--") or ".xn--" in host: findings.append(_finding("PUNYCODE", "Internationalized (Punycode) domain", f"ASCII hostname: {host}. Check for visual impersonation.", "medium", 18))
    try: unicode_host = idna.decode(ascii_host, uts46=True, std3_rules=True)
    except (UnicodeError, idna.IDNAError): unicode_host = display_host
    scripts = _scripts(unicode_host)
    if len(scripts) > 1: findings.append(_finding("MIXED_SCRIPT", "Mixed writing systems in hostname", f"Hostname uses: {', '.join(sorted(scripts))}.", "high", 30))
    if len(labels) >= 5: findings.append(_finding("MANY_SUBDOMAINS", "Unusually deep subdomain", f"Hostname contains {len(labels)} labels.", "medium", 10))
    if labels and labels[-1] in SUSPICIOUS_TLDS: findings.append(_finding("RISKY_TLD", "Frequently abused top-level domain", f"The .{labels[-1]} ending adds risk but is not proof of harm.", "medium", 12))
    if host in SHORTENERS or any(host.endswith("." + item) for item in SHORTENERS): findings.append(_finding("SHORTENER", "Shortened destination", "The visible link conceals its final destination.", "medium", 16))
    if len(url) > 180: findings.append(_finding("LONG_URL", "Very long URL", f"URL length is {len(url)} characters.", "low", 7))
    if url.count("%") >= 5: findings.append(_finding("HEAVY_ENCODING", "Heavily encoded URL", "Multiple encoded characters make the destination harder to inspect.", "medium", 12))
    if p.port and p.port not in {80, 443}: findings.append(_finding("NONSTANDARD_PORT", "Non-standard web port", f"Destination requests port {p.port}.", "medium", 15))
    if DOWNLOAD_EXTENSIONS.search(p.path): findings.append(_finding("EXECUTABLE_PATH", "Potential executable or risky download", "The path ends in a file type frequently abused for malware delivery.", "critical", 40))
    words = sorted({match.lower() for match in SUSPICIOUS_WORDS.findall(decoded_url)})
    if len(words) >= 2: findings.append(_finding("SOCIAL_ENGINEERING_WORDS", "Account, urgency or payment language", f"Terms found: {', '.join(words[:10])}.", "medium", min(20, 6 + len(words) * 2)))
    tracking = sorted(set(dict(parse_qsl(p.query, keep_blank_values=True))) & TRACKING_KEYS)
    if tracking: findings.append(_finding("TRACKING_PARAMETERS", "Tracking parameters present", f"Parameters: {', '.join(tracking)}.", "info", 0))
    return findings


def _tls_probe_sync(host: str, ip: str, port: int) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=4.0) as raw, context.wrap_socket(raw, server_hostname=host) as secure:
        cert, cipher = secure.getpeercert(), secure.cipher()
        return {"verified": True, "protocol": secure.version(), "cipher": cipher[0] if cipher else None, "expires": cert.get("notAfter"), "issuer": {item[0][0]: item[0][1] for item in cert.get("issuer", []) if item}}


async def inspect_tls(host: str, ip: str, port: int = 443) -> tuple[dict, list[Finding]]:
    try:
        info = await asyncio.get_running_loop().run_in_executor(None, _tls_probe_sync, host, ip, port)
        return info, []
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"verified": False, "error": type(exc).__name__}, [_finding("TLS_FAILURE", "TLS certificate could not be verified", "The destination did not complete a trusted TLS handshake.", "high", 24)]


async def _pinned_headers(url: str, ip: str, method: str = "HEAD") -> tuple[int, dict[str, str], str]:
    """Fetch response headers from an already-approved IP without another DNS lookup."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ssl_context, server_hostname=host if ssl_context else None), 4.0
    )
    try:
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = f"[{host}]" if ":" in host else host
        if parsed.port and parsed.port not in {80, 443}:
            host_header += f":{parsed.port}"
        request = (
            f"{method} {target} HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: NexVision-QR-Shield/5.0.1\r\nAccept: */*\r\n"
            "Connection: close\r\nRange: bytes=0-0\r\n\r\n"
        )
        writer.write(request.encode("ascii", errors="strict")); await writer.drain()
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 7.0)
        if len(raw) > 65536:
            raise ValueError("Response headers exceed limit")
        lines = raw.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1); headers[key.strip().lower()] = value.strip()
        peer = writer.get_extra_info("peername")
        connected_ip = peer[0] if peer else ip
        if connected_ip != ip or not _is_public_ip(connected_ip):
            raise ValueError("Connected peer did not match approved public IP")
        return status, headers, connected_ip
    finally:
        writer.close(); await writer.wait_closed()


async def inspect_redirects(start_url: str, max_hops: int = 5) -> tuple[list[dict], list[Finding]]:
    chain, findings, current = [], [], start_url
    origin_host = urlsplit(start_url).hostname
    for _hop in range(max_hops + 1):
            parsed = urlsplit(current)
            public, blocked = await resolve_public_ips(parsed.hostname or "")
            if blocked or not public:
                findings.append(_finding("SSRF_BLOCKED", "Network request blocked", "The destination resolves to a private, reserved or unavailable address; no connection was made.", "high", 25, blocked_ips=blocked)); break
            try:
                status, response_headers, peer_ip = await _pinned_headers(current, public[0])
                location = response_headers.get("location")
                content_type, disposition = response_headers.get("content-type"), response_headers.get("content-disposition")
            except (TimeoutError, OSError, ssl.SSLError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError) as exc:
                chain.append({"url": redact_payload(current, "url")[0], "status": None, "error": type(exc).__name__}); findings.append(_finding("UNREACHABLE", "Destination could not be inspected", "The server did not complete a limited metadata request.", "low", 4)); break
            chain.append({"url": redact_payload(current, "url")[0], "status": status, "connected_ip": peer_ip, "content_type": content_type, "content_disposition": disposition})
            if disposition and "attachment" in disposition.lower(): findings.append(_finding("ATTACHMENT_RESPONSE", "Destination returns a download", "The server marks its response as an attachment.", "high", 26))
            if status not in {301, 302, 303, 307, 308} or not location: break
            next_url, next_p = urljoin(current, location), urlsplit(urljoin(current, location))
            if next_p.scheme not in {"http", "https"}: findings.append(_finding("REDIRECT_SCHEME", "Redirect switches to a non-web scheme", f"Redirect target scheme: {next_p.scheme or 'none'}.", "critical", 40)); break
            chain[-1]["location"] = redact_payload(next_url, "url")[0]
            if next_p.hostname != origin_host: findings.append(_finding("CROSS_DOMAIN_REDIRECT", "Redirect leaves the original domain", f"Redirects to {next_p.hostname}.", "medium", 14))
            try:
                normalized, display, ascii_host = normalize_http_url(next_url)
                extra, _ = analyze_url_offline(next_url, normalized, display, ascii_host); findings.extend(extra)
            except (ValueError, UnicodeError):
                findings.append(_finding("MALFORMED_REDIRECT", "Malformed redirect destination", "The Location header is not safely parseable.", "high", 30)); break
            current = next_url
    else: findings.append(_finding("REDIRECT_LIMIT", "Long redirect chain", f"More than {max_hops} redirects were encountered.", "medium", 12))
    return chain, findings


def _split_wifi_fields(payload: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in re.split(r"(?<!\\);", payload[5:]):
        if ":" in part:
            key, value = part.split(":", 1); fields[key.upper()] = re.sub(r"\\([;,:\\])", r"\1", value)
    return fields


def _embedded_url_findings(payload: str) -> tuple[list[Finding], list[str]]:
    urls = [match.rstrip(".,;)") for match in URL_RE.findall(payload)]
    return ([_finding("EMBEDDED_URL", "Embedded web destination", f"Found {len(urls)} web address(es) inside this action payload.", "medium", 12)] if urls else []), urls[:10]


def _action_profile(kind: str, payload: str) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    profile: dict = {"format": kind}
    lines = payload.replace("\r\n", "\n").split("\n")
    if kind == "contact":
        names = [line.split(":", 1)[0].split(";", 1)[0].upper() for line in lines if ":" in line]
        profile.update({"field_count": len(names), "telephone_count": names.count("TEL"), "email_count": names.count("EMAIL"), "url_count": names.count("URL"), "photo_present": "PHOTO" in names, "key_present": "KEY" in names})
        if "PHOTO" in names or "KEY" in names:
            findings.append(_finding("CONTACT_EMBEDDED_DATA", "Contact card contains embedded photo or key data", "Large or executable contact fields should be reviewed before import.", "medium", 12))
    elif kind == "calendar-event":
        upper = [line.upper() for line in lines]
        profile.update({"organizer_present": any(line.startswith("ORGANIZER") for line in upper), "attendee_count": sum(line.startswith("ATTENDEE") for line in upper), "alarm_present": any("BEGIN:VALARM" in line for line in upper), "attachment_present": any(line.startswith("ATTACH") for line in upper)})
        if profile["attachment_present"] or profile["alarm_present"]:
            findings.append(_finding("CALENDAR_ACTIVE_CONTENT", "Calendar event includes attachment or alarm behavior", "Review external attachments, reminders and organizer identity before importing the event.", "high", 22))
    elif kind in {"email", "sms"}:
        parsed = urlsplit(payload)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        body = query.get("body", "")
        profile.update({"recipient_count": max(1, len(parsed.path.split(","))) if parsed.path else 0, "subject_present": bool(query.get("subject")), "body_length": len(body)})
        if len(body) > 2000:
            findings.append(_finding("MESSAGE_BODY_LARGE", "Unusually large pre-filled message", "Long pre-filled content can conceal instructions or data exfiltration.", "medium", 14))
    elif kind == "telephone":
        number = payload.split(":", 1)[-1].split("?", 1)[0]
        profile.update({"international_prefix": number.startswith("+"), "digit_count": sum(char.isdigit() for char in number)})
    elif kind == "location":
        profile.update({"coordinates_present": bool(re.match(r"(?i)^geo:-?\d+(?:\.\d+)?,-?\d+(?:\.\d+)?", payload))})
    return profile, findings


def _destination_graph(root_url: str, max_depth: int = 3, max_nodes: int = 12) -> list[dict]:
    """Discover nested HTTP(S) destinations with strict depth/node/size budgets."""
    nodes: list[dict] = []
    queue: list[tuple[str, int, str | None]] = [(root_url, 0, None)]
    seen: set[str] = set()
    while queue and len(nodes) < max_nodes:
        current, depth, parent = queue.pop(0)
        if current in seen or len(current) > 8192:
            continue
        seen.add(current)
        try:
            normalized, _display, host = normalize_http_url(current)
        except (ValueError, UnicodeError):
            continue
        safe_url, _ = redact_payload(normalized, "url")
        node_id = f"n{len(nodes)}"
        nodes.append({"id": node_id, "parent": parent, "depth": depth, "url": safe_url, "hostname": host})
        if depth >= max_depth:
            continue
        parsed = urlsplit(normalized)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            decoded = value
            for _ in range(3):
                changed = unquote(decoded)
                if changed == decoded:
                    break
                decoded = changed
            for match in URL_RE.findall(decoded[:8192]):
                queue.append((match.rstrip("'\"),];"), depth + 1, node_id))
    return nodes


def _apply_image_findings(result: AnalysisResult) -> None:
    image = result.image_analysis
    if not image: return
    if image.get("multiple_qr_codes"): result.findings.append(_finding("MULTIPLE_QR", "Multiple QR codes detected", "The image contains more than one decoded destination; verify which one is intended.", "medium", 14))
    flags = set(image.get("quality_flags", []))
    if "qr_quiet_zone_may_be_clipped" in flags: result.findings.append(_finding("CLIPPED_QUIET_ZONE", "QR boundary may be tightly cropped", "A missing quiet border can reduce decoding reliability.", "low", 4))
    if "strong_perspective_distortion" in flags: result.findings.append(_finding("PERSPECTIVE_DISTORTION", "Strong perspective distortion", "Verify the decoded payload independently.", "low", 4))
    if "decoder_disagreement" in flags: result.findings.append(_finding("DECODER_DISAGREEMENT", "QR decoders disagree", "Independent local decoders produced different payloads. Treat the result as ambiguous and verify manually.", "critical", 55))
    if "possible_central_overlay" in flags: result.findings.append(_finding("CENTRAL_QR_OVERLAY", "Possible logo or central overlay", "A highly uniform central region may indicate a logo, sticker or occlusion. This is structural context, not evidence of malicious intent.", "info", 0))
    if flags & {"low_sharpness", "low_contrast", "very_small_source"}: result.findings.append(_finding("IMAGE_QUALITY", "Limited source-image quality", f"Indicators: {', '.join(sorted(flags))}.", "low", 3))


def _apply_attack_chain(result: AnalysisResult) -> None:
    codes = {item.code for item in result.findings if item.score > 0}
    stages: dict[str, list[str]] = {
        "concealment": sorted(code for code in codes if any(token in code for token in ("HIDDEN", "ENCOD", "SHORTENER", "NESTED", "FRAGMENT", "OBFUSCAT", "RECURSIVE"))),
        "impersonation": sorted(code for code in codes if any(token in code for token in ("BRAND", "PUNYCODE", "CONFUS", "MIXED_SCRIPT"))),
        "pressure": sorted(code for code in codes if any(token in code for token in ("SOCIAL_ENGINEERING", "SCAM_PATTERN", "AUTHENTICATION_LURE"))),
        "sensitive_action": sorted(code for code in codes if any(token in code for token in ("SECRET", "PAYMENT", "CREDENTIAL", "WALLETCONNECT", "EXECUTABLE", "DOWNLOAD", "DANGEROUS_SCHEME"))),
    }
    active = {name: values for name, values in stages.items() if values}
    if len(active) >= 3:
        result.findings.append(_finding(
            "COMPOUND_ATTACK_CHAIN", "Multiple attack stages align",
            f"Independent evidence spans {', '.join(active)}. This combination is stronger than any single indicator.",
            "high", 30, stages=active,
        ))
        result.decoded_details["attack_chain"] = {"stage_count": len(active), "stages": active}


def _apply_verdict(result: AnalysisResult) -> None:
    groups = {"identity": [], "deception": [], "concealment": [], "social_engineering": [], "action": [], "network": [], "payment": [], "image": [], "intelligence": []}
    for item in result.findings:
        code = item.code
        group = "network" if code.startswith(("TLS_", "DNS_", "SSRF_", "PRIVATE_", "UNREACHABLE", "REDIRECT_", "CROSS_")) else \
            "image" if code.startswith(("IMAGE_", "MULTIPLE_QR", "CLIPPED_", "PERSPECTIVE_", "DECODER_")) else \
            "payment" if any(token in code for token in ("PAYMENT", "EMV_", "UPI_", "CRYPTO_")) else \
            "action" if any(token in code for token in ("SCHEME", "WIFI", "SECRET_QR", "ACTION_", "USSD", "WALLETCONNECT")) else \
            "intelligence" if "BLOCKLIST" in code else \
            "social_engineering" if any(token in code for token in ("SOCIAL_ENGINEERING", "SCAM_PATTERN", "SCAM_AWARENESS", "AUTHENTICATION_LURE", "ATTACK_CHAIN")) else \
            "concealment" if any(token in code for token in ("HIDDEN", "MULTISTAGE", "FRAGMENT", "ENCODED_URL", "DOUBLE_EXTENSION")) else \
            "deception" if any(token in code for token in ("BRAND", "SCRIPT", "PUNYCODE", "CONFUS", "INVISIBLE", "OBFUSCAT", "ENCOD", "NESTED", "BASE64")) else "identity"
        groups[group].append(max(0, item.score))
    contributions = {name: min(50, max(values, default=0) + round(sum(sorted(values, reverse=True)[1:]) * .25)) for name, values in groups.items()}
    raw = sum(contributions.values())
    positive = [max(0, item.score) for item in result.findings]
    saturated = round(100 * (1 - math.exp(-raw / 90))) if raw else 0
    result.score = min(100, max([saturated, *positive], default=0))
    if any(item.code == "DECODER_DISAGREEMENT" for item in result.findings): result.verdict = "Unable to determine"
    elif any(item.severity == "critical" for item in result.findings) or result.score >= 75: result.verdict = "Dangerous"
    elif result.score >= 55: result.verdict = "High risk"
    elif result.score >= 30: result.verdict = "Suspicious"
    elif result.score >= 10: result.verdict = "Caution"
    else: result.verdict = "Low observable risk"
    result.engine.update({"grouped_rule_points": raw, "risk_groups": contributions, "finding_count": len(result.findings), "abstention_supported": True})
    _seal_result(result)


async def analyze_payload(payload: str, sha256: str | None = None, network_checks: bool = False, image_analysis: dict | None = None, context_text: str | None = None) -> AnalysisResult:
    payload, kind = payload.strip(), classify_payload(payload)
    safe_payload, sensitive_fields = redact_payload(payload, kind)
    safe_image = dict(image_analysis or {})
    embedded_context = safe_image.pop("_context_text", None)
    context_text = (context_text or embedded_context or "")[:32768]
    result = AnalysisResult(payload=safe_payload, payload_type=kind, analyzed_at=datetime.now(UTC).isoformat(), payload_sha256=payload_digest(payload), payload_redacted=bool(sensitive_fields), sensitive_fields=sensitive_fields, sha256=sha256, image_analysis=safe_image)
    result.engine["mode"] = "offline + direct destination preflight" if network_checks else "fully offline"
    result.engine["intelligence_pack"] = intelligence_metadata()
    result.engine["advanced_detectors"] = ["recursive decoding", "cross-field brand claims", "shared-infrastructure auth lures", "attack-chain fusion", "EPC payment validation", "QR structural profile"]
    result.limitations = ["The risk index is an explainable rule score, not a probability or guarantee of safety.", "Offline analysis cannot know whether a previously benign domain has just been compromised.", "The checker never renders pages, executes JavaScript, submits forms or intentionally downloads content.", "Image analysis cannot establish whether a physical QR sticker was replaced without a trusted reference photograph."]
    _apply_image_findings(result)
    controls = [f"U+{ord(c):04X}" for c in payload if unicodedata.category(c) in {"Cc", "Cf"} and c not in "\r\n\t"]
    if controls: result.findings.append(_finding("CONTROL_CHARACTERS", "Hidden control characters", f"Payload contains {', '.join(controls[:8])}.", "high", 28))
    evasion_findings, evasion_details = analyze_evasion(payload)
    result.findings.extend(evasion_findings)
    result.decoded_details["evasion_analysis"] = evasion_details
    multilingual_findings, multilingual_details = analyze_multilingual_text(payload)
    result.findings.extend(multilingual_findings)
    result.decoded_details["multilingual_intelligence"] = multilingual_details
    if context_text:
        context_findings, context_details = analyze_multilingual_text(context_text)
        result.decoded_details["surrounding_context"] = {
            "text_sha256": hashlib.sha256(context_text.encode("utf-8", "surrogatepass")).hexdigest(),
            "character_count": len(context_text),
            "language_signals": context_details.get("language_signals", []),
            "possible_country_signals": context_details.get("possible_country_signals", []),
            "scam_categories": context_details.get("scam_categories", []),
        }
        for item in context_findings:
            item.code = "CONTEXT_" + item.code
            item.title = "Surrounding document: " + item.title
            result.findings.append(item)

    if kind == "authentication-secret":
        result.findings.append(_finding("SECRET_QR", "Authentication secret detected", "This may contain an MFA enrollment seed. Treat it as a password.", "critical", 65))
        if payload.casefold().startswith("otpauth-migration:"):
            result.decoded_details["authentication_export"] = {"format": "Authenticator migration bundle", "entry_count": _migration_entry_count(payload), "secrets_redacted": True}
            result.findings.append(_finding("AUTHENTICATOR_EXPORT", "Authenticator account export", "This QR may transfer one or more MFA seeds. The complete encoded export was removed from results.", "critical", 72))
        else:
            profile = _parse_otpauth(payload)
            result.decoded_details["authentication_profile"] = profile
            if not profile["valid_profile"] or not profile["issuer_consistent"]:
                result.findings.append(_finding("OTP_PROFILE_INVALID", "Unusual authenticator configuration", "Algorithm, digits, period or issuer information is inconsistent with the supported profile.", "high", 28))
    elif kind == "authentication-session":
        result.decoded_details["authentication_session"] = {"protocol": "FIDO cross-device / hybrid authentication", "payload_length": len(payload)}
        result.findings.append(_finding("FIDO_SESSION", "Cross-device authentication session", "Scanning may approve or continue a sign-in on another device. Only proceed when you initiated the session on a trusted device.", "high", 42))
    elif kind == "account-link-session":
        scheme = payload.split(":", 1)[0].casefold()
        result.decoded_details["account_link"] = {"scheme": scheme, "token_redacted": bool(sensitive_fields)}
        result.findings.append(_finding("ACCOUNT_LINK_SESSION", "Messaging or application account-link session", "Scanning may link another device or authorize access to an account. Verify the session on the trusted device.", "critical", 58))
    elif kind == "dangerous-scheme":
        scheme = payload.split(":", 1)[0].lower(); result.decoded_details["scheme"] = scheme
        if scheme == "intent":
            result.decoded_details["android_intent"] = _intent_details(payload)
            if result.decoded_details["android_intent"].get("fallback_present"):
                result.findings.append(_finding("INTENT_FALLBACK", "Android intent contains a browser fallback", "If the target application cannot handle the intent, a separate web destination may open.", "critical", 48))
        result.findings.append(_finding("DANGEROUS_SCHEME", "Potentially dangerous action scheme", f"The QR invokes '{scheme}:' rather than a normal website.", "critical", 70))
    elif kind == "wallet-session":
        result.decoded_details.update({"protocol": "WalletConnect", "session_topic_present": bool(re.match(r"(?i)^wc:[^@?]+@\d+", payload)), "symmetric_key_redacted": any(field.casefold() == "symkey" for field in sensitive_fields)})
        result.findings.append(_finding("WALLETCONNECT_SESSION", "Cryptocurrency wallet connection session", "This QR can connect a wallet to an application that may request signatures or transactions. Verify the application independently before approving anything.", "high", 38))
    elif kind == "wifi":
        if payload.lower().startswith("dpp:"):
            result.decoded_details.update({"provisioning": "Wi-Fi Easy Connect (DPP)", "bootstrap_key_present": bool(re.search(r"(?i)(?:^|;)K:", payload))})
            result.findings.append(_finding("DPP_WIFI", "Wi-Fi device provisioning", "DPP can provision a device onto a network. Verify the configurator and device identity.", "high", 22))
            _apply_verdict(result); return result
        fields = _split_wifi_fields(payload); auth = fields.get("T", "nopass").lower()
        result.decoded_details.update({"ssid": fields.get("S"), "authentication": fields.get("T", "nopass"), "hidden": fields.get("H", "false").lower() == "true", "password_present": bool(fields.get("P"))})
        result.findings.append(_finding("WIFI_CONFIG", "Wi-Fi configuration", "Scanning may join a network controlled by another party.", "medium", 14))
        if auth in {"", "nopass", "none"}: result.findings.append(_finding("OPEN_WIFI", "Open Wi-Fi network", "The QR specifies no wireless authentication.", "high", 25))
        elif auth == "wep": result.findings.append(_finding("WEP_WIFI", "Obsolete WEP security", "WEP does not provide adequate wireless protection.", "high", 24))
        elif auth in {"wpa3", "sae"}: result.findings.append(_finding("WPA3_WIFI", "WPA3 network configuration", "The QR requests a modern WPA3/SAE network; the SSID still needs independent verification.", "info", 0))
        elif "eap" in auth: result.findings.append(_finding("ENTERPRISE_WIFI", "Enterprise Wi-Fi configuration", "Verify the identity, anonymous identity, CA certificate and server-name constraints before joining.", "high", 20))
        if "eap" in auth and not any(fields.get(key) for key in ("CA", "PH2")):
            result.findings.append(_finding("ENTERPRISE_WIFI_VALIDATION_MISSING", "Enterprise Wi-Fi server validation is incomplete", "The configuration does not provide CA/server or phase-2 constraints, increasing evil-twin exposure.", "high", 26))
        if result.decoded_details["hidden"]: result.findings.append(_finding("HIDDEN_WIFI", "Hidden network requested", "Hidden SSIDs are not inherently safer and are harder to verify.", "medium", 8))
    elif kind in {"emv-payment", "epc-payment", "upi-payment", "cryptocurrency-payment"}:
        if kind == "emv-payment":
            details = analyze_emv_qr(payload); result.decoded_details.update(redact_mapping(details))
            result.findings.append(_finding("PAYMENT_REQUEST", "Merchant-presented payment request", "A structurally valid payment code can still name the wrong merchant or account. Confirm the payee in the trusted payment application.", "medium", 12))
            if not details.get("valid_tlv"): result.findings.append(_finding("EMV_MALFORMED", "Malformed payment QR structure", details.get("parse_error", "TLV parsing failed."), "critical", 50))
            elif not details.get("crc_valid"): result.findings.append(_finding("EMV_CRC_INVALID", "Payment QR integrity check failed", "The EMV CRC is missing or does not match.", "critical", 60))
            else: result.findings.append(_finding("EMV_CRC_VALID", "Payment QR CRC is valid", "The structure is internally consistent; this does not verify the merchant.", "info", 0))
            if details.get("validation_issues"):
                result.findings.append(_finding("EMV_STRUCTURE_ISSUES", "Payment structure has validation issues", "; ".join(details["validation_issues"][:6]), "high", 30))
            if details.get("amount"): result.findings.append(_finding("FIXED_PAYMENT", "Payment amount is pre-filled", f"Amount: {details['amount']} (currency {details.get('currency_numeric') or 'unknown'}).", "medium", 8))
        elif kind == "epc-payment":
            details = analyze_epc_qr(payload); result.decoded_details.update(details)
            if details["structure_valid"]:
                result.findings.append(_finding("EPC_PAYMENT", "SEPA bank-transfer payment request", "The EPC structure and IBAN checksum are valid; this does not establish that the beneficiary is trustworthy.", "medium", 18))
            else:
                result.findings.append(_finding("EPC_PAYMENT_INVALID", "Invalid or malformed SEPA payment QR", "; ".join(details["validation_issues"][:6]), "high", 34))
        elif kind == "cryptocurrency-payment":
            details = analyze_crypto_uri(payload); result.decoded_details.update(details)
            result.findings.append(_finding("CRYPTO_PAYMENT", "Cryptocurrency payment request", "Transfers are generally irreversible; verify the address and amount independently.", "high", 28))
            if details["validation_issues"]: result.findings.append(_finding("CRYPTO_PAYMENT_INVALID", "Malformed cryptocurrency payment request", "; ".join(details["validation_issues"]), "high", 32))
        else:
            details = analyze_upi_uri(payload); result.decoded_details.update(details)
            result.findings.append(_finding("UPI_PAYMENT", "UPI payment request", "Verify the payee inside the trusted payment app before authorizing.", "medium", 18))
            if details["validation_issues"]: result.findings.append(_finding("UPI_PAYMENT_INVALID", "Malformed UPI payment request", "; ".join(details["validation_issues"]), "high", 32))
    elif kind in {"telephone", "sms", "email", "contact", "calendar-event", "location", "custom-scheme"}:
        result.findings.append(_finding("ACTION_PAYLOAD", f"{kind.replace('-', ' ').title()} action", "Review every field before allowing another application to act.", "medium", 10))
        profile, profile_findings = _action_profile(kind, payload)
        result.decoded_details["action_profile"] = profile
        result.findings.extend(profile_findings)
        embedded, urls = _embedded_url_findings(payload); result.findings.extend(embedded); result.decoded_details["embedded_urls"] = [redact_payload(url, "url")[0] for url in urls]
        if kind == "telephone" and re.search(r"[*#]", payload): result.findings.append(_finding("USSD_OR_SERVICE_CODE", "Telephone service code", "The number contains * or # and may invoke a carrier/device function.", "high", 25))
        if kind in {"email", "sms"} and re.search(r"(?i)(?:%0d|%0a|\r|\n)", payload):
            result.findings.append(_finding("MESSAGE_HEADER_INJECTION", "Encoded line break in message action", "CR/LF characters can inject extra message headers or hide additional instructions.", "critical", 42))
        if kind == "custom-scheme":
            scheme = payload.split(":", 1)[0].casefold()
            result.decoded_details["scheme"] = scheme
            level = "critical" if scheme in {"intent", "market", "itms-services", "ms-settings"} else "high"
            result.findings.append(_finding("CUSTOM_SCHEME", "Application deep link", f"The '{scheme}:' URI can launch an application or trigger an app-specific action.", level, 35 if level == "critical" else 20))
        if SUSPICIOUS_WORDS.search(payload): result.findings.append(_finding("SOCIAL_ENGINEERING_TEXT", "Urgency, account or payment wording", "The payload contains language often used in social engineering.", "medium", 12))
    elif kind not in {"url", "url-like"}:
        result.findings.append(_finding("PLAIN_TEXT", "Plain text payload", "No automatic web destination or device action was detected.", "info", 0))
    else:
        ambiguity = _url_interpretation_ambiguity(payload)
        if ambiguity:
            result.decoded_details["url_parser_disagreement"] = ambiguity
            result.findings.append(_finding("URL_PARSER_AMBIGUITY", "Browser and server may interpret different hosts", "The URL authority contains characters with known cross-parser ambiguity. Active inspection was not attempted.", "critical", 70, **ambiguity))
            _apply_verdict(result); result.verdict = "Unable to determine"; _seal_result(result); return result
        try: normalized, display_host, ascii_host = normalize_http_url(payload)
        except (ValueError, UnicodeError):
            result.findings.append(_finding("INVALID_URL", "Malformed web address", "The payload resembles a URL but cannot be safely normalized.", "high", 32)); _apply_verdict(result); return result
        safe_normalized, _ = redact_payload(normalized, "url")
        result.normalized_url, result.display_host, result.ascii_host = safe_normalized, display_host, ascii_host
        result.findings.extend(_static_url_findings(normalized, display_host, ascii_host))
        offline, details = analyze_url_offline(payload, normalized, display_host, ascii_host); result.findings.extend(offline)
        advanced, advanced_details = analyze_advanced_url(payload, normalized, ascii_host); result.findings.extend(advanced)
        details["advanced_url_profile"] = advanced_details
        graph = _destination_graph(normalized)
        if len(graph) > 1:
            details["destination_graph"] = graph
            deep = max(node["depth"] for node in graph)
            result.findings.append(_finding("RECURSIVE_DESTINATIONS", "Nested destination chain", f"Discovered {len(graph) - 1} embedded destination(s) across {deep} level(s).", "high" if deep > 1 else "medium", 24 if deep > 1 else 12))
        result.decoded_details.update(redact_mapping(details))
        raw_url = payload if payload.lower().startswith(("http://", "https://")) else "https://" + payload
        raw_parts = urlsplit(raw_url)
        if raw_parts.username or raw_parts.password: result.findings.append(_finding("URL_CREDENTIALS", "URL hides a hostname behind credentials", "Text before @ can disguise the actual destination host.", "critical", 45))
        domains, urls, source = local_blocklist(); result.reputation = [{"provider": "Local offline blocklist", "status": "loaded", "domain_count": len(domains), "url_count": len(urls), "source": source}]
        if network_checks and os.getenv("QR_SHIELD_ALLOW_NETWORK_PREFLIGHT") != "1":
            result.findings.append(_finding("PREFLIGHT_DISABLED", "Direct preflight is disabled by server policy", "An administrator must explicitly enable destination contact after deploying an isolated egress worker.", "info", 0))
        elif network_checks:
            public, blocked = await resolve_public_ips(ascii_host); result.resolved_ips = public
            if blocked: result.findings.append(_finding("PRIVATE_ADDRESS", "Private or reserved destination", "Active inspection was blocked because DNS returned non-public address space.", "high", 30, blocked_ips=blocked))
            elif not public: result.findings.append(_finding("DNS_FAILURE", "Domain did not resolve", "No public IP address was found.", "medium", 15))
            else:
                result.findings.append(_finding("DNS_PUBLIC", "Public DNS resolution", f"Resolved to {len(public)} public address(es).", "info", 0))
                requested_port = urlsplit(normalized).port or (443 if urlsplit(normalized).scheme == "https" else 80)
                if requested_port not in {80, 443}:
                    result.findings.append(_finding("PREFLIGHT_PORT_BLOCKED", "Direct preflight port blocked", "Active inspection is restricted to TCP ports 80 and 443.", "medium", 10))
                else:
                    tasks = [inspect_redirects(normalized)]
                    if urlsplit(normalized).scheme == "https": tasks.append(inspect_tls(ascii_host, public[0], requested_port))
                    completed = await asyncio.gather(*tasks); chain, redirect_findings = completed[0]; result.redirect_chain = chain; result.findings.extend(redirect_findings)
                    if len(completed) > 1:
                        tls, tls_findings = completed[1]; result.decoded_details["tls"] = tls; result.findings.extend(tls_findings)
    _apply_attack_chain(result)
    _apply_verdict(result)
    return result
