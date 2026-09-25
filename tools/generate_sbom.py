from __future__ import annotations

import importlib.metadata
import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
SYSTEM_PACKAGES = ("poppler-utils", "tesseract-ocr")


def dependencies() -> list[dict]:
    names = []
    for filename in ("requirements.lock",):
        for raw in (ROOT / filename).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-r")):
                continue
            name = line.split("[", 1)[0].split("=", 1)[0].split("<", 1)[0].split(">", 1)[0]
            names.append(name)
    packages = []
    declared = [
        line
        for filename in ("requirements.lock",)
        for line in (ROOT / filename).read_text(encoding="utf-8").splitlines()
    ]
    for name in sorted(set(names), key=str.casefold):
        try:
            version = importlib.metadata.version(name)
            status = "installed-and-validated"
        except importlib.metadata.PackageNotFoundError:
            version = next((line.split("==", 1)[1] for line in declared if line.startswith(name + "==")), "unknown")
            status = "declared-not-installed-in-build-environment"
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
