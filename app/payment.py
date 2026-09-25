from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qsl, urlsplit


@dataclass
class TLVError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


def crc16_ccitt_false(text: str) -> str:
    crc = 0xFFFF
    for byte in text.encode("utf-8"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def parse_tlv(payload: str) -> list[dict[str, str]]:
    fields: list[dict[str, str]] = []
    raw = payload.encode("utf-8")
    cursor = 0
    while cursor < len(raw):
        if cursor + 4 > len(raw):
            raise TLVError(f"Truncated TLV header at offset {cursor}")
        try:
            tag = raw[cursor:cursor + 2].decode("ascii")
            length_text = raw[cursor + 2:cursor + 4].decode("ascii")
        except UnicodeDecodeError as exc:
            raise TLVError(f"Non-ASCII tag or length at offset {cursor}") from exc
        if not tag.isdigit() or not length_text.isdigit():
            raise TLVError(f"Non-numeric tag or length at offset {cursor}")
        length = int(length_text)
        start = cursor + 4
        end = start + length
        if end > len(raw):
            raise TLVError(f"Tag {tag} declares {length} bytes beyond payload end")
        try:
            value = raw[start:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise TLVError(f"Tag {tag} contains invalid or truncated UTF-8") from exc
        fields.append({"tag": tag, "length": str(length), "value": value})
        cursor = end
    return fields


def looks_like_emv_qr(payload: str) -> bool:
    """Recognize EMV MPM by structure, without excluding UTF-8 or URL data."""
    if not payload.startswith("000201") or len(payload.encode("utf-8")) > 8192:
        return False
    try:
        fields = parse_tlv(payload)
    except TLVError:
        # A malformed EMV-looking payload still needs the payment validator,
        # rather than falling through to URL/plain-text analysis.
        return bool(re.match(r"^0002(?:01|\d{2})", payload))
    return bool(fields and fields[0]["tag"] == "00" and fields[0]["value"] == "01")


def _safe_template(field: dict[str, str]) -> tuple[dict, list[str], dict[str, str]]:
    """Parse an EMV template while retaining no payee proxy or account value."""
    nested = parse_tlv(field["value"])
    by_tag = {item["tag"]: item["value"] for item in nested}
    gui = by_tag.get("00", "")
    safe_fields = []
    for item in nested:
        value = item["value"]
        if item["tag"] == "00":
            safe_fields.append({"tag": "00", "length": item["length"], "value": value})
        else:
            safe_fields.append({
                "tag": item["tag"],
                "length": item["length"],
                "value_redacted": True,
                "value_sha256": hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest(),
            })
    return {"tag": field["tag"], "gui": gui or None, "fields": safe_fields}, [], by_tag


def _payment_profile(country: str | None, currency: str | None, templates: list[dict]) -> tuple[str, list[str]]:
    guis = {str(item.get("gui") or "").upper() for item in templates}
    joined = " ".join(guis)
    issues: list[str] = []
    network = "other/undetermined"
    expected: tuple[str, str] | None = None
    if "BR.GOV.BCB.PIX" in guis:
        network, expected = "Pix / BR Code", ("BR", "986")
    elif guis & {"A000000677010111", "A000000677010114"}:
        network, expected = "PromptPay / Thai QR", ("TH", "764")
    elif "SG.PAYNOW" in joined:
        network, expected = "PayNow / SGQR", ("SG", "702")
    elif "DUITNOW" in joined or "PAYNET" in joined:
        network, expected = "DuitNow QR", ("MY", "458")
    elif country == "ID" and currency == "360":
        network, expected = "Possible QRIS", ("ID", "360")
    if expected:
        if country and country != expected[0]:
            issues.append(f"payment profile expects country {expected[0]}, not {country}")
        if currency and currency != expected[1]:
            issues.append(f"payment profile expects currency {expected[1]}, not {currency}")
    return network, issues


def analyze_emv_qr(payload: str) -> dict:
    details: dict = {"standard": "EMV merchant-presented QR", "valid_tlv": False, "crc_valid": False}
    try:
        fields = parse_tlv(payload)
    except TLVError as exc:
        details["parse_error"] = str(exc)
        return details
    details["valid_tlv"] = True
    tags = [field["tag"] for field in fields]
    issues: list[str] = []
    duplicates = sorted({tag for tag in tags if tags.count(tag) > 1})
    if duplicates:
        issues.append("duplicate tags: " + ", ".join(duplicates))
    required = {"00", "52", "53", "58", "59", "60", "63"}
    missing = sorted(required - set(tags))
    if missing:
        issues.append("missing mandatory tags: " + ", ".join(missing))
    if tags and tags[0] != "00":
        issues.append("payload format indicator is not first")
    if "63" in tags and tags[-1] != "63":
        issues.append("CRC tag is not last")
    by_tag = {field["tag"]: field["value"] for field in fields}
    details.update({
        "payload_format": by_tag.get("00"),
        "initiation_method": {"11": "static", "12": "dynamic"}.get(by_tag.get("01"), "unspecified"),
        "currency_numeric": by_tag.get("53"),
        "amount": by_tag.get("54"),
        "country": by_tag.get("58"),
        "merchant_name": by_tag.get("59"),
        "merchant_city": by_tag.get("60"),
    })
    account_templates = [field for field in fields if 26 <= int(field["tag"]) <= 51]
    nested_templates: list[dict] = []
    for field in account_templates:
        try:
            safe, template_issues, _raw = _safe_template(field)
            nested_templates.append(safe)
            issues.extend(template_issues)
        except TLVError:
            issues.append(f"merchant account template {field['tag']} is malformed")
    details["merchant_account_templates"] = nested_templates
    network, profile_issues = _payment_profile(by_tag.get("58"), by_tag.get("53"), nested_templates)
    details["payment_network"] = network
    issues.extend(profile_issues)
    if by_tag.get("00") != "01":
        issues.append("unsupported or missing payload format version")
    if by_tag.get("54") and not re.fullmatch(r"\d{1,13}(?:\.\d{1,2})?", by_tag["54"]):
        issues.append("invalid transaction amount format")
    if by_tag.get("53") and not re.fullmatch(r"\d{3}", by_tag["53"]):
        issues.append("invalid numeric currency code")
    if by_tag.get("58") and not re.fullmatch(r"[A-Z]{2}", by_tag["58"]):
        issues.append("invalid country code")
    if by_tag.get("59") and len(by_tag["59"].encode("utf-8")) > 25:
        issues.append("merchant name exceeds 25 UTF-8 bytes")
    if by_tag.get("60") and len(by_tag["60"].encode("utf-8")) > 15:
        issues.append("merchant city exceeds 15 UTF-8 bytes")
    crc_fields = [field for field in fields if field["tag"] == "63"]
    if crc_fields and len(crc_fields[-1]["value"]) == 4 and payload.rfind("6304") == len(payload) - 8:
        supplied = crc_fields[-1]["value"].upper()
        expected = crc16_ccitt_false(payload[:-4])
        details.update({"crc_supplied": supplied, "crc_expected": expected, "crc_valid": supplied == expected})
    if not crc_fields:
        issues.append("CRC tag is missing")
    elif not details["crc_valid"]:
        issues.append("CRC does not match")
    details["validation_issues"] = issues
    details["structure_valid"] = not issues
    return details


def iban_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    remainder = 0
    for char in numeric:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder == 1


def creditor_reference_valid(value: str) -> bool:
    """Validate an ISO 11649 RF creditor reference using its own length rules."""
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"RF\d{2}[A-Z0-9]{1,21}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    remainder = 0
    for char in numeric:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder == 1


def analyze_epc_qr(payload: str) -> dict:
    """Parse an EPC069-12 SEPA Credit Transfer QR without exposing account/name values."""
    lines = payload.replace("\r\n", "\n").split("\n")
    fields = lines + [""] * max(0, 12 - len(lines))
    amount_text = fields[7]
    amount_valid = not amount_text
    amount = None
    if amount_text:
        match = re.fullmatch(r"EUR(\d{1,8}(?:\.\d{1,2})?)", amount_text)
        if match:
            try:
                value = Decimal(match.group(1))
                amount_valid = Decimal("0.01") <= value <= Decimal("999999999.99")
                amount = str(value)
            except InvalidOperation:
                amount_valid = False
    iban = re.sub(r"\s+", "", fields[6]).upper()
    issues = []
    if fields[0] != "BCD": issues.append("service tag is not BCD")
    if fields[1] not in {"001", "002"}: issues.append("unsupported EPC version")
    if fields[2] not in {"1", "2"}: issues.append("unsupported character set")
    if fields[3] != "SCT": issues.append("identification is not SCT")
    if fields[4] and not re.fullmatch(r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", fields[4]):
        issues.append("BIC format is invalid")
    if not iban_valid(iban): issues.append("IBAN checksum or format is invalid")
    if not fields[5].strip(): issues.append("beneficiary name is missing")
    if not amount_valid: issues.append("amount is invalid or outside the EPC limit")
    if fields[8] and fields[8] not in {"CHAR", "EACT", "GDDS", "GOVT", "OTHR", "SUPP", "TRAD"}:
        issues.append("purpose code is unrecognized")
    if fields[9] and fields[10]:
        issues.append("structured and unstructured remittance fields are both populated")
    if fields[9] and not creditor_reference_valid(fields[9]):
        issues.append("structured creditor reference checksum is invalid")
    if len(payload.encode("utf-8")) > 331:
        issues.append("payload exceeds the EPC QR data limit")
    return {
        "standard": "EPC QR SEPA Credit Transfer",
        "version": fields[1] or None,
        "encoding_code": fields[2] or None,
        "bic_present": bool(fields[4]),
        "beneficiary_present": bool(fields[5].strip()),
        "iban_country": iban[:2] if len(iban) >= 2 else None,
        "iban_last4": iban[-4:] if len(iban) >= 4 else None,
        "iban_valid": iban_valid(iban),
        "currency": "EUR" if amount_text.startswith("EUR") else None,
        "amount": amount,
        "purpose": fields[8] or None,
        "reference_present": bool(fields[9] or fields[10]),
        "validation_issues": issues,
        "structure_valid": not issues,
    }


def analyze_upi_uri(payload: str) -> dict:
    query = dict(parse_qsl(urlsplit(payload).query, keep_blank_values=True))
    payee = query.get("pa", "")
    amount = query.get("am", "")
    currency = query.get("cu", "INR").upper()
    issues = []
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,256}@[A-Za-z0-9._-]{2,64}", payee):
        issues.append("missing or invalid virtual payment address")
    if amount:
        try:
            numeric = Decimal(amount)
            if numeric <= 0 or numeric > Decimal(1000000000): issues.append("amount is outside supported bounds")
        except InvalidOperation:
            issues.append("amount is invalid")
    if currency != "INR":
        issues.append("unexpected UPI currency")
    safe_payee = (payee[:2] + "••••@" + payee.rsplit("@", 1)[-1]) if "@" in payee else None
    return {
        "scheme": "UPI", "payee_present": bool(payee), "payee_masked": safe_payee,
        "payee_name_present": bool(query.get("pn")), "amount": amount or None,
        "currency": currency, "transaction_reference_present": bool(query.get("tr")),
        "validation_issues": issues, "structure_valid": not issues,
    }


def analyze_crypto_uri(payload: str) -> dict:
    parsed = urlsplit(payload)
    scheme = parsed.scheme.casefold()
    address = parsed.path or parsed.netloc
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    issues = []
    if scheme == "ethereum":
        core = address.split("@", 1)[0]
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", core): issues.append("invalid Ethereum address format")
    elif scheme == "bitcoin":
        if not re.fullmatch(r"(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[ac-hj-np-z02-9]{11,71})", address, re.IGNORECASE):
            issues.append("invalid Bitcoin address format")
    elif scheme == "litecoin" and not re.fullmatch(r"(?:[LM3][1-9A-HJ-NP-Za-km-z]{25,34}|ltc1[ac-hj-np-z02-9]{11,71})", address, re.IGNORECASE):
        issues.append("invalid Litecoin address format")
    elif scheme == "monero" and not re.fullmatch(r"[48][1-9A-HJ-NP-Za-km-z]{94,105}", address):
        issues.append("invalid Monero address format")
    amount = query.get("amount") or query.get("value")
    if amount and not re.fullmatch(r"\d+(?:\.\d+)?", amount): issues.append("invalid payment amount")
    return {
        "network": scheme, "address_present": bool(address),
        "address_sha256": hashlib.sha256(address.encode()).hexdigest() if address else None,
        "address_last6": address[-6:] if len(address) >= 6 else None,
        "amount": amount, "label_present": bool(query.get("label")),
        "validation_issues": issues, "structure_valid": not issues,
    }
