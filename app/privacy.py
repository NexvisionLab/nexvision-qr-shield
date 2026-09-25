from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

SECRET_KEYS = {
    "secret", "token", "access_token", "refresh_token", "apikey", "api_key",
    "password", "passwd", "pwd", "pin", "otp", "key", "private_key", "symkey",
}
URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")


def _decode_repeated(value: str) -> str:
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _redact_embedded_urls(value: str, depth: int) -> tuple[str, list[str]]:
    fields: list[str] = []

    def replace(match: re.Match[str]) -> str:
        safe, nested_fields = redact_payload(match.group(0), "url", depth + 1)
        fields.extend(f"nested.{name}" for name in nested_fields)
        return safe

    return URL_RE.sub(replace, value), fields


def _redact_fragment(fragment: str, depth: int) -> tuple[str, list[str]]:
    fields: list[str] = []
    secret_names = "|".join(sorted((re.escape(item) for item in SECRET_KEYS), key=len, reverse=True))
    pattern = re.compile(rf"(?i)((?:^|[?&;/])(?:{secret_names})=)([^&;]*)")

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).lstrip("?&;/").split("=", 1)[0]
        fields.append(key)
        return match.group(1) + "[REDACTED]"

    redacted = pattern.sub(replace, fragment)
    if depth < 3:
        redacted, nested = _redact_embedded_urls(redacted, depth)
        fields.extend(nested)
    return redacted, fields


def _mask(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "•" * max(4, len(value))
    return value[:keep] + "•" * min(12, len(value) - keep * 2) + value[-keep:]


def redact_payload(payload: str, kind: str, _depth: int = 0) -> tuple[str, list[str]]:
    """Return a safe display/export representation. Raw secrets never enter results."""
    fields: list[str] = []
    personal = os.getenv("QR_SHIELD_REDACTION_LEVEL", "secrets").casefold() in {"personal", "strict"}
    if kind == "authentication-secret":
        try:
            p = urlsplit(payload)
            query = []
            for key, value in parse_qsl(p.query, keep_blank_values=True):
                # Google Authenticator migration exports place one or more OTP
                # seeds inside a protobuf carried by the otherwise generic
                # ``data`` parameter. It must never enter a result or report.
                if p.scheme.casefold() == "otpauth-migration" and key.casefold() == "data":
                    fields.append("migration_data")
                    value = "[REDACTED AUTHENTICATOR EXPORT]"
                elif key.casefold() in SECRET_KEYS:
                    fields.append(key)
                    value = "[REDACTED]"
                elif _depth < 3:
                    decoded = _decode_repeated(value)
                    if decoded.casefold().startswith(("http://", "https://")):
                        nested, nested_fields = redact_payload(decoded, "url", _depth + 1)
                        if nested_fields:
                            value = nested; fields.extend(f"nested.{name}" for name in nested_fields)
                query.append((key, value))
            fragment, fragment_fields = _redact_fragment(p.fragment, _depth)
            fields.extend(fragment_fields)
            return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), fragment)), sorted(set(fields or ["secret"]))
        except ValueError:
            return "[REDACTED AUTHENTICATION SECRET]", ["secret"]
    if kind in {"authentication-session", "account-link-session"}:
        scheme = payload.split(":", 1)[0].casefold() if ":" in payload else "session"
        return f"{scheme}:[REDACTED SESSION DATA]", ["session_data"]
    if kind == "dangerous-scheme":
        scheme = payload.split(":", 1)[0].casefold() if ":" in payload else "action"
        return f"{scheme}:[REDACTED ACTION DATA]", ["action_data"]
    if kind == "wifi":
        if payload.casefold().startswith("dpp:"):
            changed = re.sub(r"(?i)(?<!\\)(K:)(.*?)(?<!\\);", r"\1[REDACTED];", payload)
            return changed, ["dpp_bootstrap_key"] if changed != payload else []
        def replace(match: re.Match[str]) -> str:
            fields.append("wifi_password")
            return f"{match.group(1)}[REDACTED]"
        return re.sub(r"(?i)(?<!\\)(P:)(.*?)(?<!\\);", replace, payload), sorted(set(fields))
    if kind == "epc-payment":
        lines = payload.replace("\r\n", "\n").split("\n")
        if len(lines) > 6 and lines[6]:
            lines[6] = _mask(re.sub(r"\s+", "", lines[6]), 2)
            fields.append("iban")
        if len(lines) > 5 and lines[5]:
            lines[5] = "[REDACTED BENEFICIARY]"
            fields.append("beneficiary")
        return "\n".join(lines), fields
    if personal and kind in {"contact", "calendar-event"}:
        sensitive_names = {"FN", "N", "NICKNAME", "EMAIL", "TEL", "ADR", "BDAY", "ANNIVERSARY", "ATTENDEE", "ORGANIZER", "LOCATION", "DESCRIPTION"}
        output = []
        for line in payload.replace("\r\n", "\n").split("\n"):
            name = line.split(":", 1)[0].split(";", 1)[0].upper()
            if name in sensitive_names and ":" in line:
                output.append(line.split(":", 1)[0] + ":[REDACTED PERSONAL DATA]")
                fields.append(name.casefold())
            else:
                output.append(line)
        return "\n".join(output), sorted(set(fields))
    if personal and kind in {"telephone", "sms", "email", "location"}:
        if kind == "location":
            payload = re.sub(r"(?i)^geo:[^?]+", "geo:[REDACTED COORDINATES]", payload)
            fields.append("coordinates")
        if kind == "telephone":
            return re.sub(r"(?i)^tel:[^?;]+", "tel:[REDACTED NUMBER]", payload), ["telephone"]
        if kind == "sms":
            payload = re.sub(r"(?i)^((?:sms|smsto|mms|mmsto):)[^?;:]+", r"\1[REDACTED NUMBER]", payload)
            fields.append("recipient")
        if kind == "email":
            payload = re.sub(r"(?i)^((?:mailto|matmsg):)[^?;]+", r"\1[REDACTED RECIPIENT]", payload)
            fields.append("recipient")
    if kind in {"url", "url-like", "custom-scheme", "email", "sms", "location", "upi-payment", "cryptocurrency-payment", "wallet-session"}:
        try:
            candidate = payload if ":" in payload.split("/", 1)[0] else "https://" + payload
            p = urlsplit(candidate)
            query = []
            for key, value in parse_qsl(p.query, keep_blank_values=True):
                if key.casefold() in SECRET_KEYS:
                    fields.append(key)
                    value = "[REDACTED]"
                elif _depth < 3:
                    decoded = _decode_repeated(value)
                    nested, nested_fields = _redact_embedded_urls(decoded, _depth)
                    if nested_fields:
                        value = nested
                        fields.extend(nested_fields)
                query.append((key, value))
            netloc = p.netloc
            if p.password:
                fields.append("url_password")
                user = p.username or ""
                host = p.hostname or ""
                port = f":{p.port}" if p.port else ""
                netloc = f"{user}:[REDACTED]@{host}{port}"
            fragment, fragment_fields = _redact_fragment(p.fragment, _depth)
            fields.extend(fragment_fields)
            result = urlunsplit((p.scheme, netloc, p.path, urlencode(query), fragment))
            if not payload.lower().startswith(("http://", "https://")) and result.startswith("https://"):
                result = result[8:]
            return result, sorted(set(fields))
        except (ValueError, UnicodeError):
            scheme = payload.split(":", 1)[0].casefold() if ":" in payload else kind
            return f"{scheme}:[REDACTED UNPARSEABLE DATA]", ["unparseable_payload"]
    return payload, []


def payload_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="surrogatepass")).hexdigest()


def redact_mapping(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key.casefold() in SECRET_KEYS:
                result[key] = "[REDACTED]"
            elif isinstance(item, str) and key.casefold() in {"url", "location", "normalized_url"}:
                result[key] = redact_payload(item, "url")[0]
            else:
                result[key] = redact_mapping(item)
        return result
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    return value
