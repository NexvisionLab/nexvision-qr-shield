from __future__ import annotations

import hashlib
import re
from urllib.parse import unquote, urlsplit

import tldextract

from .models import Finding
from .offline_intel import brand_domains
from .url_intelligence import confusable_skeleton

EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
AUTH_TERMS = {"account", "auth", "confirm", "credential", "login", "logon", "mfa", "otp", "password", "recover", "secure", "signin", "unlock", "update", "verify"}
SHARED_HOSTING = {
    "appspot.com", "azurewebsites.net", "blogspot.com", "cloudfront.net", "firebaseapp.com",
    "github.io", "gitlab.io", "netlify.app", "pages.dev", "vercel.app", "web.app", "workers.dev",
}
TUNNELS = {"loca.lt", "ngrok-free.app", "ngrok.io", "serveo.net", "trycloudflare.com"}
RISKY_EXTENSIONS = r"exe|msi|msp|scr|bat|cmd|com|ps1|vbs|js|jar|apk|dmg|pkg|iso|zip|rar|7z|hta|lnk|xll|docm|xlsm|one"


def _finding(code: str, title: str, detail: str, severity: str, score: int, **evidence) -> Finding:
    return Finding(code, title, detail, severity, score, evidence)


def _registered(host: str) -> str:
    value = EXTRACT(host)
    return (".".join(part for part in (value.domain, value.suffix) if part) if value.suffix else host).casefold()


def _gtin_valid(value: str) -> bool:
    if not re.fullmatch(r"\d{14}", value):
        return False
    total = sum(int(char) * (3 if index % 2 == 0 else 1) for index, char in enumerate(value[:-1]))
    return (10 - total % 10) % 10 == int(value[-1])


def _gs1_profile(path: str) -> dict | None:
    parts = [unquote(item) for item in path.split("/") if item]
    pairs = {parts[index]: parts[index + 1] for index in range(0, len(parts) - 1, 2) if parts[index].isdigit()}
    if "01" not in pairs:
        return None
    return {
        "standard": "GS1 Digital Link", "gtin_present": True,
        "gtin_valid": _gtin_valid(pairs["01"]),
        "serial_present": "21" in pairs, "batch_present": "10" in pairs,
        "expiry_present": "17" in pairs, "application_identifiers": sorted(pairs),
    }


def analyze_advanced_url(raw_url: str, normalized_url: str, ascii_host: str) -> tuple[list[Finding], dict]:
    raw_parts = urlsplit(raw_url if raw_url.casefold().startswith(("http://", "https://")) else "https://" + raw_url)
    normalized = urlsplit(normalized_url)
    registered = _registered(ascii_host) or ascii_host.casefold()
    non_host = unquote(f"{raw_parts.path} {raw_parts.query} {raw_parts.fragment}").casefold()
    non_host_tokens = [confusable_skeleton(token) for token in re.findall(r"[\w]+", non_host, re.UNICODE)]
    strong_claim_area = confusable_skeleton(unquote(f"{raw_parts.path} {raw_parts.fragment}").casefold()).replace("-", "").replace("_", "")
    words = set(re.findall(r"[a-z0-9]+", confusable_skeleton(non_host)))
    auth_hits = sorted(words & AUTH_TERMS)
    claimed_brands: list[str] = []
    for brand, official_domains in brand_domains().items():
        compact = confusable_skeleton(brand).replace(" ", "").replace("-", "")
        official = registered in official_domains
        brand_token = any(token == compact or (token.startswith(compact) and len(token) >= len(compact) + 3) for token in non_host_tokens)
        if not official and len(compact) >= 4 and brand_token:
            claimed_brands.append(brand)

    platform = next((suffix for suffix in sorted(SHARED_HOSTING | TUNNELS) if registered == suffix), None)
    encoded_separators = len(re.findall(r"(?i)%(?:25)?(?:2f|3a|40|5c)", raw_url))
    fragment_urls = re.findall(r"(?i)https?://[^\s<>\"']+", unquote(raw_parts.fragment))
    double_extension = re.search(rf"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:{RISKY_EXTENSIONS})(?:$|[?#])", normalized.path)
    gs1 = _gs1_profile(normalized.path)

    findings: list[Finding] = []
    strong_claims = [brand for brand in claimed_brands if confusable_skeleton(brand).replace(" ", "").replace("-", "") in strong_claim_area]
    if claimed_brands and (auth_hits or strong_claims):
        severity, score = ("critical", 44) if auth_hits else ("high", 30)
        findings.append(_finding(
            "CLAIMED_BRAND_MISMATCH", "Brand name appears outside an official domain",
            f"The path, query or fragment references {', '.join(claimed_brands[:5])}, but the controlling domain is {registered}.",
            severity, score, brands=claimed_brands[:5], controlling_domain=registered,
        ))
    if platform and ascii_host.casefold() != platform and (len(auth_hits) >= 2 or claimed_brands):
        kind = "temporary tunnel" if platform in TUNNELS else "shared hosting platform"
        findings.append(_finding(
            "HOSTED_AUTH_LURE", "Authentication lure on shared or temporary infrastructure",
            f"The destination uses a {kind} ({platform}) together with authentication or brand language.",
            "high", 27, platform=platform, authentication_terms=auth_hits,
        ))
    if len(auth_hits) >= 3:
        findings.append(_finding(
            "AUTHENTICATION_LURE_PATH", "Concentrated sign-in and verification wording",
            f"The non-domain portion contains multiple authentication cues: {', '.join(auth_hits[:8])}.",
            "medium", 16, terms=auth_hits[:8],
        ))
    if gs1:
        findings.append(_finding(
            "GS1_DIGITAL_LINK", "GS1 Digital Link product identifier",
            "The URL carries standardized product identifiers; the destination domain still requires independent verification.",
            "info", 0, gtin_valid=gs1["gtin_valid"],
        ))
        if not gs1["gtin_valid"]:
            findings.append(_finding(
                "GS1_GTIN_INVALID", "Invalid GS1 product check digit",
                "The encoded GTIN does not pass its check-digit validation.", "medium", 16,
            ))
    if fragment_urls or len(set(re.findall(r"[a-z0-9]+", unquote(raw_parts.fragment).casefold())) & AUTH_TERMS) >= 2:
        findings.append(_finding(
            "FRAGMENT_LURE", "Risk-bearing content hidden in URL fragment",
            "The browser-only fragment contains an embedded destination or multiple authentication cues.",
            "high", 22, embedded_url_count=len(fragment_urls), fragment_sha256=hashlib.sha256(raw_parts.fragment.encode()).hexdigest(),
        ))
    if double_extension:
        findings.append(_finding(
            "DOUBLE_EXTENSION_DOWNLOAD", "Download uses a deceptive double extension",
            f"The path ends with {double_extension.group(0).split('?', 1)[0]}, combining a document/image name with an executable type.",
            "critical", 48,
        ))
    if encoded_separators >= 3:
        findings.append(_finding(
            "ENCODED_URL_DELIMITERS", "URL delimiters are repeatedly encoded",
            "Repeated encoding of slash, colon, at-sign or backslash characters can obscure parser boundaries.",
            "medium", 15, encoded_separator_count=encoded_separators,
        ))
    details = {
        "controlling_domain": registered,
        "claimed_brands_outside_host": claimed_brands[:10],
        "authentication_terms": auth_hits,
        "shared_infrastructure": platform,
        "encoded_separator_count": encoded_separators,
        "fragment_present": bool(raw_parts.fragment),
        "fragment_length": len(raw_parts.fragment),
        "double_extension": bool(double_extension),
        "gs1_digital_link": gs1,
        "interpretation": "Infrastructure and lexical features are contextual signals, not reputation verdicts.",
    }
    return findings, details
