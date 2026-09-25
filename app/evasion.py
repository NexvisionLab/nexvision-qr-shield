from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
import unicodedata
from collections import deque
from urllib.parse import unquote

from .models import Finding

URL_RE = re.compile(r"(?i)https?://[^\s<>\"']+")
DANGEROUS_RE = re.compile(r"(?i)(?:javascript|data|file|smb|intent|vbscript|shell):")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9_+/-])([A-Za-z0-9_+/-]{20,4096}={0,2})(?![A-Za-z0-9_+/-])")
JSON_ESCAPE_RE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))")
SECURITY_TERMS = {
    "account", "bank", "customs", "delivery", "login", "mfa", "otp",
    "password", "payment", "refund", "secure", "suspend", "urgent", "verify", "wallet",
}
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _finding(code: str, title: str, detail: str, severity: str, score: int, **evidence) -> Finding:
    return Finding(code, title, detail, severity, score, evidence)


def _json_unescape(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1) or match.group(2), 16))
    return JSON_ESCAPE_RE.sub(replace, value)


def _decode_base64(token: str) -> str | None:
    compact = token.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not decoded or len(decoded) > 8192:
        return None
    printable = sum(char.isprintable() or char in "\r\n\t" for char in decoded) / len(decoded)
    return decoded if printable >= 0.92 else None


def _safe_url(value: str) -> str:
    from .privacy import redact_payload
    return redact_payload(value, "url")[0]


def analyze_evasion(payload: str, max_depth: int = 3, max_states: int = 16) -> tuple[list[Finding], dict]:
    """Bounded recursive decoding that stores metadata, never decoded secret-bearing bodies."""
    root = payload[:8192]
    queue: deque[tuple[str, int, tuple[str, ...]]] = deque([(root, 0, ())])
    seen = {hashlib.sha256(root.encode("utf-8", "surrogatepass")).digest()}
    layers: list[dict] = []
    hidden_urls: dict[str, set[tuple[str, ...]]] = {}
    dangerous: set[str] = set()
    root_urls = set(URL_RE.findall(root))

    while queue and len(seen) < max_states:
        value, depth, chain = queue.popleft()
        if depth >= max_depth:
            continue
        candidates: list[tuple[str, str]] = []
        if re.search(r"%[0-9a-fA-F]{2}", value):
            decoded = unquote(value)
            if decoded != value:
                candidates.append(("percent", decoded))
        entity = html.unescape(value)
        if entity != value:
            candidates.append(("html-entity", entity))
        escaped = _json_unescape(value)
        if escaped != value:
            candidates.append(("json-escape", escaped))
        base64_tokens = [value.strip()] if 20 <= len(value.strip()) <= 4096 else []
        base64_tokens.extend(match.group(1) for match in BASE64_RE.finditer(value))
        for token in dict.fromkeys(base64_tokens):
            decoded = _decode_base64(token)
            if decoded is not None and decoded != value:
                candidates.append(("base64", decoded))

        for transform, decoded in candidates[:8]:
            if len(seen) >= max_states:
                break
            digest = hashlib.sha256(decoded.encode("utf-8", "surrogatepass")).digest()
            if digest in seen:
                continue
            seen.add(digest)
            new_chain = chain + (transform,)
            urls = {item.rstrip(".,;)") for item in URL_RE.findall(decoded)}
            for url in urls - root_urls:
                # Percent-decoding an ordinary outer URL changes its text but
                # does not reveal a second destination.
                if transform == "percent" and value.casefold().startswith(("http://", "https://")) and decoded.casefold().startswith(("http://", "https://")):
                    continue
                hidden_urls.setdefault(url, set()).add(new_chain)
            dangerous.update(match.group(0).split(":", 1)[0].casefold() for match in DANGEROUS_RE.finditer(decoded))
            layers.append({
                "depth": depth + 1,
                "transform_chain": list(new_chain),
                "decoded_length": len(decoded),
                "decoded_sha256": hashlib.sha256(decoded.encode("utf-8", "surrogatepass")).hexdigest(),
                "url_count": len(urls),
                "dangerous_scheme_count": len(DANGEROUS_RE.findall(decoded)),
            })
            if len(decoded) <= 8192:
                queue.append((decoded, depth + 1, new_chain))

    normalized = unicodedata.normalize("NFKC", root).casefold()
    collapsed = re.sub(r"[^a-z0-9]+", "", normalized.translate(LEET))
    visible_terms = {term for term in SECURITY_TERMS if term in normalized}
    recovered_terms = {term for term in SECURITY_TERMS if term in collapsed and term not in visible_terms}
    zero_width = [f"U+{ord(char):04X}" for char in root if unicodedata.category(char) == "Cf"]

    findings: list[Finding] = []
    if dangerous:
        findings.append(_finding(
            "HIDDEN_DANGEROUS_SCHEME", "Dangerous action concealed by encoding",
            f"Recursive decoding exposed concealed scheme(s): {', '.join(sorted(dangerous))}.",
            "critical", 58, schemes=sorted(dangerous),
        ))
    if hidden_urls:
        strong_concealment = any(
            len(chain) >= 2 or any(item != "percent" for item in chain)
            for chains in hidden_urls.values() for chain in chains
        )
        findings.append(_finding(
            "HIDDEN_ENCODED_URL", "Web destination concealed by encoding",
            f"Bounded decoding exposed {len(hidden_urls)} URL(s) not visible in the original payload.",
            "high" if strong_concealment else "medium", 30 if strong_concealment else 14,
            urls=[_safe_url(item) for item in sorted(hidden_urls)[:5]],
        ))
    if len(recovered_terms) >= 2:
        findings.append(_finding(
            "OBFUSCATED_SECURITY_TERMS", "Security wording split or disguised",
            f"Normalization recovered disguised terms: {', '.join(sorted(recovered_terms)[:8])}.",
            "high", 24, terms=sorted(recovered_terms)[:8],
        ))
    if any(len(item["transform_chain"]) >= 2 for item in layers):
        findings.append(_finding(
            "MULTISTAGE_ENCODING", "Multiple decoding layers",
            "The payload uses a multi-stage encoding chain that reduces human readability.",
            "medium", 14, maximum_depth=max(item["depth"] for item in layers),
        ))
    details = {
        "analysis": "bounded offline recursive decoding",
        "decoded_layer_count": len(layers),
        "layers": layers,
        "hidden_url_count": len(hidden_urls),
        "recovered_obfuscated_terms": sorted(recovered_terms),
        "zero_width_codepoints": zero_width[:8],
        "budgets": {"maximum_depth": max_depth, "maximum_states": max_states, "maximum_text_length": 8192},
    }
    return findings, details
