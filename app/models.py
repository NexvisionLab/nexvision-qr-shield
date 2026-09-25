from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from . import __version__

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    code: str
    title: str
    detail: str
    severity: Severity
    score: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    payload: str
    payload_type: str
    analyzed_at: str
    payload_sha256: str | None = None
    payload_redacted: bool = False
    sensitive_fields: list[str] = field(default_factory=list)
    sha256: str | None = None
    normalized_url: str | None = None
    display_host: str | None = None
    ascii_host: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    reputation: list[dict[str, Any]] = field(default_factory=list)
    image_analysis: dict[str, Any] = field(default_factory=dict)
    decoded_details: dict[str, Any] = field(default_factory=dict)
    evidence_integrity: dict[str, Any] = field(default_factory=dict)
    engine: dict[str, Any] = field(default_factory=lambda: {
        "name": "QR Shield Offline Detection Engine",
        "version": __version__,
        "score_type": "explainable risk index; not a probability",
        "external_api_required": False,
    })
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "Informational"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
