from __future__ import annotations

import importlib.metadata
import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
SYSTEM_PACKAGES = ("poppler-utils", "tesseract-ocr")


def locked_versions() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name, separator, version = line.partition("==")
        if not separator:
            raise SystemExit(f"requirements.lock entry is not pinned: {line}")
        pins[name.split("[", 1)[0].strip()] = version.strip()
    return pins


def dependencies() -> list[dict]:
    # The SBOM describes the pinned runtime lock; the local environment only
    # confirms (or fails to confirm) each pin, it never changes the version.
    packages = []
    for name, version in sorted(locked_versions().items(), key=lambda item: item[0].casefold()):
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            status = "locked; not installed in the SBOM build environment"
        else:
            status = "locked; installed version matches" if installed == version else f"locked; build environment has {installed}"
        packages.append({"SPDXID": f"SPDXRef-Package-{name.replace('_', '-')}", "name": name, "versionInfo": version, "supplier": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "comment": status})
    for name in SYSTEM_PACKAGES:
        packages.append({
            "SPDXID": f"SPDXRef-System-{name}",
            "name": name,
            "supplier": "Organization: Debian",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "comment": "Container system dependency; capture its exact installed version in the image SBOM.",
        })
    return packages


document = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"NexVision-QR-Shield-{VERSION}",
    "documentNamespace": f"https://nexvision.local/sbom/qr-shield/{VERSION}",
    "creationInfo": {"created": datetime.now(UTC).isoformat(), "creators": ["Tool: tools/generate_sbom.py"]},
    "packages": dependencies(),
}
(ROOT / "SBOM.spdx.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
