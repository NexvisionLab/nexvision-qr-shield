from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import math
import re
import unicodedata
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

import idna
import tldextract

from .models import Finding
from .offline_intel import blocklist_match, brand_domains

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
CONFUSABLES = str.maketrans({
    "а": "a", "ɑ": "a", "α": "a", "е": "e", "ε": "e", "ο": "o", "о": "o",
    "р": "p", "ρ": "p", "с": "c", "ϲ": "c", "х": "x", "χ": "x", "у": "y",
    "і": "i", "ı": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "κ": "k",
    "м": "m", "ո": "n", "ѕ": "s", "т": "t", "ν": "v", "ԝ": "w", "ℓ": "l",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4", "５": "5",
    "６": "6", "７": "7", "８": "8", "９": "9",
})
OPEN_REDIRECT_KEYS = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "return", "returnto",
    "return_url", "next", "continue", "dest", "destination", "target", "link", "goto",
}
SENSITIVE_KEYS = {"password", "passwd", "pwd", "token", "access_token", "secret", "otp", "pin", "apikey", "api_key", "client_secret", "id_token"}
EXECUTABLE_MIME_HINTS = {"application", "download", "attachment", "installer", "setup"}
ZERO_WIDTH_OR_BIDI = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202a", "\u202b", "\u202d",
    "\u202e", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069",
}


def _number_systems(text: str) -> set[str]:
    systems = set()
    for char in text:
        if char.isdecimal():
            name = unicodedata.name(char, "ASCII DIGIT")
            systems.add(name.rsplit(" DIGIT", 1)[0])
    return systems


def _restriction_level(text: str) -> str:
    if text.isascii():
        return "ASCII"
    scripts = set()
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "DEVANAGARI", "BENGALI", "TAMIL", "THAI"):
            if script in name:
                scripts.add(script)
    if len(scripts) <= 1:
        return "single-script"
    east_asian = {"LATIN", "CJK", "HIRAGANA", "KATAKANA", "HANGUL"}
    return "highly-restrictive" if scripts <= east_asian else "unrestricted-mixed-script"


def finding(code: str, title: str, detail: str, severity: str, score: int = 0, **evidence) -> Finding:
    return Finding(code, title, detail, severity, score, evidence)


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        row_min = i
        for j, char_b in enumerate(b, 1):
            value = min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_a != char_b))
            current.append(value)
            row_min = min(row_min, value)
        if row_min > limit:
            return limit + 1
        previous = current
    return previous[-1]


def confusable_skeleton(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in normalized.translate(CONFUSABLES) if not unicodedata.combining(char))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())


def _registrable(host: str) -> tuple[str, str]:
    extracted = EXTRACT(host)
    domain = extracted.domain.lower()
    registered = ".".join(part for part in (domain, extracted.suffix.lower()) if part)
    return domain, registered


def _decode_nested(value: str) -> str:
    result = value
    for _ in range(3):
        decoded = unquote(result)
        if decoded == result:
            break
        result = decoded
    return result


def _base64_preview(value: str) -> str | None:
    compact = value.strip().replace("-", "+").replace("_", "/")
    if len(compact) < 20 or len(compact) > 4096 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None
    compact += "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact, validate=True)
        text = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    printable = sum(char.isprintable() or char in "\r\n\t" for char in text) / max(1, len(text))
    return text[:300] if printable > 0.9 else None


def _parse_ipv4_number(part: str) -> tuple[int, int] | None:
    base, digits = (16, part[2:]) if part.lower().startswith("0x") else ((8, part[1:]) if len(part) > 1 and part.startswith("0") else (10, part))
    if not digits:
        return None
    try:
        return int(digits, base), base
    except ValueError:
        return None


def _obfuscated_ip(host: str) -> str | None:
    lower = host.lower().strip("[]")
    try:
        if "." not in lower:
            single = _parse_ipv4_number(lower)
            if single is None or (single[1] == 10 and len(lower) < 8):
                return None
            number = single[0]
        else:
            parts = lower.split(".")
            if not 1 <= len(parts) <= 4:
                return None
            parsed = [_parse_ipv4_number(part) for part in parts]
            if any(item is None for item in parsed):
                return None
            numbers = [item[0] for item in parsed if item]
            last_max = 256 ** (5 - len(numbers)) - 1
            if any(number > 255 for number in numbers[:-1]) or numbers[-1] > last_max:
                return None
            number = sum(value << (8 * (3 - index)) for index, value in enumerate(numbers[:-1])) + numbers[-1]
            canonical = str(ipaddress.IPv4Address(number))
            if len(parts) != 4 or any(item[1] != 10 for item in parsed if item) or canonical != lower:
                return canonical
            return None
        if 0 <= number <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(number))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def analyze_url_offline(raw_url: str, normalized_url: str, display_host: str, ascii_host: str) -> tuple[list[Finding], dict]:
    p = urlsplit(normalized_url)
    raw = raw_url.strip()
    findings: list[Finding] = []
    domain_label, registered = _registrable(ascii_host)
    try:
        unicode_host = idna.decode(ascii_host, uts46=True, std3_rules=True)
    except (UnicodeError, idna.IDNAError):
        unicode_host = display_host
    details = {
        "registrable_domain": registered or ascii_host,
        "unicode_hostname": unicode_host,
        "host_entropy": round(shannon_entropy(domain_label), 3),
        "path_entropy": round(shannon_entropy(p.path), 3),
        "nested_urls": [],
        "brand_signals": [],
        "unicode_security_profile": "UTS39-inspired restricted identifier checks; bundled confusable mapping",
        "idna_profile": "UTS46 non-transitional with STD3 rules",
        "identifier_restriction_level": _restriction_level(unicode_host),
    }

    listed, match = blocklist_match(ascii_host, normalized_url)
    if listed:
        findings.append(finding("LOCAL_BLOCKLIST", "Found in local offline blocklist", f"Matched {match}.", "critical", 85))

    invisible = [f"U+{ord(char):04X}" for char in raw if char in ZERO_WIDTH_OR_BIDI or unicodedata.category(char) in {"Cf", "Cc"}]
    if invisible:
        findings.append(finding("INVISIBLE_OR_BIDI", "Invisible or direction-control characters", f"Found {', '.join(invisible[:8])}; these can disguise displayed text.", "critical", 42))
    nfkc = unicodedata.normalize("NFKC", raw)
    if nfkc != raw and any(ord(char) > 127 for char in raw):
        findings.append(finding("COMPATIBILITY_CHARS", "Compatibility characters alter under normalization", "The payload changes under Unicode NFKC normalization.", "medium", 15))
    number_systems = _number_systems(unicode_host)
    if len(number_systems) > 1:
        findings.append(finding("MIXED_NUMBER_SYSTEMS", "Mixed Unicode number systems", f"Hostname contains digits from: {', '.join(sorted(number_systems))}.", "high", 25))

    if "\\" in raw.split("?", 1)[0]:
        findings.append(finding("BACKSLASH_CONFUSION", "Backslashes in web address", "Different parsers may interpret backslashes inconsistently.", "high", 28))
    if raw.count("@") > 1:
        findings.append(finding("MULTIPLE_AT", "Multiple @ delimiters", "Repeated user-info delimiters can confuse destination review.", "high", 24))
    if raw.count("#") > 1 or raw.count("?") > 1:
        findings.append(finding("DELIMITER_CONFUSION", "Repeated URL delimiters", "Repeated ? or # characters can obscure the meaningful part of a link.", "medium", 12))

    obfuscated = _obfuscated_ip(ascii_host)
    if obfuscated:
        findings.append(finding("OBFUSCATED_IP", "Obfuscated IPv4 destination", f"Hostname converts to {obfuscated}.", "critical", 45, decoded_ip=obfuscated))

    skeleton_host = confusable_skeleton(unicode_host)
    details["confusable_skeleton"] = skeleton_host
    brand_hits: list[tuple[str, str]] = []
    for brand, official_domains in brand_domains().items():
        official = registered in official_domains or any(registered.endswith("." + item) for item in official_domains)
        compact_brand = confusable_skeleton(brand).replace("-", "").replace(" ", "")
        compact_host = skeleton_host.replace("-", "")
        host_tokens = [confusable_skeleton(token) for token in re.split(r"[.-]", unicode_host.casefold())]
        if len(compact_brand) <= 4:
            host_has_brand = any(token == compact_brand or (token.startswith(compact_brand) and len(token) >= len(compact_brand) + 3) for token in host_tokens)
            distance = 3
        else:
            host_has_brand = compact_brand in compact_host
            distance = levenshtein(confusable_skeleton(domain_label).replace("-", ""), compact_brand, 2)
        if not official and (host_has_brand or distance <= 2):
            reason = "name present in untrusted domain" if host_has_brand else f"edit distance {distance}"
            brand_hits.append((brand, reason))
    if brand_hits:
        details["brand_signals"] = [{"brand": brand, "reason": reason} for brand, reason in brand_hits[:5]]
        brands = ", ".join(brand for brand, _ in brand_hits[:5])
        findings.append(finding("BRAND_IMPERSONATION", "Possible brand impersonation", f"Hostname resembles or contains: {brands}, but is not an approved domain.", "critical", 46))

    subdomain = EXTRACT(ascii_host).subdomain.lower()
    if subdomain and registered and any(
        len(brand.replace(" ", "")) >= 3
        and brand.replace(" ", "") in confusable_skeleton(subdomain).replace("-", "")
        and not (registered in official_domains or any(registered.endswith("." + item) for item in official_domains))
        for brand, official_domains in brand_domains().items()
    ):
        findings.append(finding("BRAND_IN_SUBDOMAIN", "Trusted-looking name appears only in a subdomain", f"The controlling domain is {registered}.", "critical", 38))

    if details["host_entropy"] >= 3.7 and len(domain_label) >= 14:
        findings.append(finding("HIGH_HOST_ENTROPY", "Random-looking domain label", f"Hostname entropy is {details['host_entropy']} bits/character.", "medium", 16))
    if sum(char.isdigit() for char in domain_label) / max(1, len(domain_label)) > 0.35 and len(domain_label) >= 8:
        findings.append(finding("NUMERIC_DOMAIN", "Digit-heavy domain", "A large share of the main domain label is numeric.", "medium", 12))
    if domain_label.count("-") >= 3 or re.search(r"(.)\1{3,}", domain_label):
        findings.append(finding("DOMAIN_PATTERN", "Unusual domain pattern", "Repeated hyphens or characters make the domain less typical.", "medium", 10))

    raw_query = parse_qsl(p.query, keep_blank_values=True)
    lower_keys = {key.casefold() for key, _ in raw_query}
    exposed = sorted(lower_keys & SENSITIVE_KEYS)
    if exposed:
        findings.append(finding("SECRET_IN_QUERY", "Sensitive value may be exposed in the URL", f"Query names include: {', '.join(exposed)}.", "high", 30))
    for key, value in raw_query:
        decoded = _decode_nested(value)
        nested = re.search(r"(?i)https?://[^\s<>]+", decoded)
        if nested:
            nested_url = nested.group(0).rstrip("'\")],")
            details["nested_urls"].append({"parameter": key, "url": nested_url})
            nested_host = urlsplit(nested_url).hostname
            cross = nested_host and nested_host.lower() != ascii_host.lower()
            severity, score = ("high", 28) if key.casefold() in OPEN_REDIRECT_KEYS or cross else ("medium", 14)
            findings.append(finding("NESTED_URL", "URL embedded inside another URL", f"Parameter '{key}' contains destination {nested_host or nested_url}.", severity, score))
        preview = _base64_preview(value)
        if preview:
            risky = bool(re.search(r"(?i)(https?://|javascript:|<script|powershell|cmd\.exe|password|token|wallet)", preview))
            findings.append(finding("BASE64_PARAMETER", "Base64-encoded query content", "Decoded content contains security-sensitive text." if risky else "A query value decodes to hidden readable text.", "high" if risky else "medium", 26 if risky else 10, decoded_sha256=hashlib.sha256(preview.encode()).hexdigest(), decoded_length=len(preview)))

    if p.path.count("//") >= 2:
        findings.append(finding("PATH_SLASH_CONFUSION", "Repeated slashes in path", "The path uses repeated slashes that may obscure its structure.", "low", 6))
    if len(p.query) > 512:
        findings.append(finding("LONG_QUERY", "Unusually long query string", f"Query length is {len(p.query)} characters.", "medium", 12))
    return findings, details
