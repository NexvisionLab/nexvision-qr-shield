from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote

from .models import Finding

DATA_FILE = Path(__file__).resolve().parent / "data" / "multilingual_scam_packs.json"
ACTION_CATEGORIES = {
    "account", "authority", "credentials", "delivery", "installation",
    "charity", "immigration", "investment", "job", "parking", "payment", "prize", "utility",
}
PRESSURE_CATEGORIES = {"threat", "urgency"}


@lru_cache(maxsize=1)
def scam_pack() -> dict:
    with DATA_FILE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    for _ in range(2):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    value = "".join(char for char in unicodedata.normalize("NFKD", value) if not unicodedata.combining(char))
    return re.sub(r"[\s_./?&=#:+-]+", " ", value).strip()


def _contains(text: str, phrase: str) -> bool:
    needle = _normalize(phrase)
    if not needle:
        return False
    if all(char.isascii() for char in needle):
        return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", text) is not None
    return needle in text


def _finding(code: str, title: str, detail: str, severity: str, score: int, **evidence) -> Finding:
    return Finding(code, title, detail, severity, score, evidence)


def analyze_multilingual_text(payload: str) -> tuple[list[Finding], dict]:
    """Detect combinations of localized scam intent without language guessing or network calls."""
    pack = scam_pack()
    source = payload[:32_768]
    text = _normalize(source)
    raw_text = unicodedata.normalize("NFKC", unquote(source)).casefold()
    signals: list[dict] = []
    categories: set[str] = set()

    for code, policy in pack["languages"].items():
        hits: dict[str, list[str]] = {}
        for category, phrases in policy["phrases"].items():
            matched = [phrase for phrase in phrases if _contains(text, phrase)]
            if matched:
                hits[category] = matched[:3]
                categories.add(category)
        if hits:
            signals.append({
                "code": code,
                "language": policy["name"],
                "possible_regions": policy["regions"],
                "categories": sorted(hits),
                "matched_phrases": {key: value for key, value in sorted(hits.items())},
            })

    awareness_hits = [phrase for phrase in pack["awareness_context"] if _contains(text, phrase)]
    country_signals = []
    for code, policy in pack["country_profiles"].items():
        matched = []
        for term in policy["distinctive_terms"]:
            if term.startswith("."):
                if re.search(re.escape(term.casefold()) + r"(?=$|[/?:#\s])", raw_text):
                    matched.append(term)
            elif _contains(text, term):
                matched.append(term)
        if matched:
            country_signals.append({"code": code, "country": policy["name"], "matched_terms": matched[:4]})

    details = {
        "policy_pack": {"id": pack["pack_id"], "version": pack["version"]},
        "language_signals": signals,
        "possible_country_signals": country_signals,
        "scam_categories": sorted(categories),
        "awareness_context": awareness_hits[:4],
        "interpretation": "Language and country values are heuristic signals, not geolocation or identity claims.",
    }
    findings: list[Finding] = []
    actionable = categories & ACTION_CATEGORIES
    pressured = categories & PRESSURE_CATEGORIES
    coordinated = bool(actionable and pressured) or len(categories) >= 3

    if awareness_hits and coordinated:
        findings.append(_finding(
            "SCAM_AWARENESS_CONTEXT", "Likely scam-awareness or protective context",
            "Risk phrases appear beside wording that warns against scams or says no action is required. Automated scoring was suppressed.",
            "info", 0, phrases=awareness_hits[:4],
        ))
    elif coordinated:
        strongest = max((len(item["categories"]) for item in signals), default=0)
        severity, score = ("high", 38) if len(categories) >= 4 or strongest >= 4 else ("medium", 30)
        languages = ", ".join(item["language"] for item in signals[:5])
        findings.append(_finding(
            "MULTILINGUAL_SOCIAL_ENGINEERING", "Coordinated social-engineering language",
            f"Localized wording combines {', '.join(sorted(categories))} signals. Language matches: {languages}.",
            severity, score, language_codes=[item["code"] for item in signals], categories=sorted(categories),
        ))
        if country_signals and ("authority" in categories or "payment" in categories):
            countries = ", ".join(item["country"] for item in country_signals[:4])
            findings.append(_finding(
                "COUNTRY_SCAM_PATTERN", "Country-specific institution or payment cue",
                f"Distinctive terms associated with {countries} appear beside authority or payment language. Verify through a separately obtained official channel.",
                "medium", 14, country_codes=[item["code"] for item in country_signals],
            ))
    return findings, details
