from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import idna

BASE = Path(__file__).resolve().parent


def _canonical_url(value: str) -> str:
    """Normalize case-insensitive URL components without changing path/query case."""
    try:
        parsed = urlsplit(value.strip())
        if not parsed.scheme or not parsed.hostname:
            return value.strip()
        host = parsed.hostname.casefold().rstrip(".")
        if not host.isascii():
            # Match the punycode form the analyzer produces for IDN hosts.
            host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = {"http": 80, "https": 443}.get(parsed.scheme.casefold())
        port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
        userinfo = ""
        if parsed.username is not None:
            userinfo = parsed.username
            if parsed.password is not None:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        # The analyzer's normalized URL always has a path and never a fragment.
        return urlunsplit((parsed.scheme.casefold(), userinfo + host + port, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError, idna.IDNAError):
        return value.strip()


@lru_cache(maxsize=1)
def intelligence_metadata() -> dict:
    manifest_path = BASE / "data" / "intelligence_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {"pack_id": "unavailable", "version": "unknown"}
    hashes = {}
    for name in ("brand_domains.json", "local_blocklist.txt", "multilingual_scam_packs.json"):
        path = BASE / "data" / name
        try:
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            hashes[name] = None
    return {**manifest, "content_sha256": hashes, "unicode_version": __import__("unicodedata").unidata_version}


@lru_cache(maxsize=1)
def brand_domains() -> dict[str, list[str]]:
    with (BASE / "data" / "brand_domains.json").open(encoding="utf-8") as handle:
        data = json.load(handle)
    return {str(k).lower(): [str(v).lower() for v in values] for k, values in data.items()}


@lru_cache(maxsize=8)
def _load_blocklist(path_value: str, modified_ns: int, size: int) -> tuple[frozenset[str], frozenset[str]]:
    domains: set[str] = set()
    urls: set[str] = set()
    path = Path(path_value)
    try:
        usable = path.is_file() and path.stat().st_size <= 25 * 1024 * 1024
    except OSError:
        usable = False
    if not usable:
        return frozenset(), frozenset()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return frozenset(), frozenset()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.casefold().startswith("url:"):
            urls.add(_canonical_url(line[4:].strip()))
        elif line.casefold().startswith("domain:"):
            domains.add(line[7:].strip().casefold().strip("."))
        elif "://" in line:
            urls.add(_canonical_url(line))
        else:
            domains.add(line.casefold().strip("."))
    return frozenset(domains), frozenset(urls)


def local_blocklist() -> tuple[frozenset[str], frozenset[str], str]:
    configured = os.getenv("QR_SHIELD_BLOCKLIST")
    path = Path(configured) if configured else BASE / "data" / "local_blocklist.txt"
    try:
        stat = path.stat(); modified_ns, size = stat.st_mtime_ns, stat.st_size
    except OSError:
        modified_ns, size = 0, 0
    domains, urls = _load_blocklist(str(path.resolve()), modified_ns, size)
    pack_id = hashlib.sha256(("\n".join(sorted(domains)) + "\n" + "\n".join(sorted(urls))).encode()).hexdigest()[:16]
    return domains, urls, f"local-pack:{pack_id}"


def blocklist_match(host: str, url: str) -> tuple[bool, str | None]:
    domains, urls, _ = local_blocklist()
    normalized_host = host.lower().strip(".")
    normalized_url = _canonical_url(url)
    if normalized_url in urls:
        return True, "exact URL"
    for domain in domains:
        if normalized_host == domain or normalized_host.endswith("." + domain):
            return True, f"domain {domain}"
    return False, None
