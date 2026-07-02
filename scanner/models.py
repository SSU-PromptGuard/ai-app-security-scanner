"""Layer A result models for PromptGuard Lite."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

_OWASP_CODE_RE = re.compile(r"LLM\d+")


def build_finding_id(
    file: str,
    rule_id: str,
    line: int,
    sink: str,
    source: str = "",
) -> str:
    """Build a stable short identifier for a structural finding."""
    raw = f"{file}|{rule_id}|{line}|{sink}|{source}".encode("utf-8", errors="replace")
    digest = hashlib.sha1(raw).hexdigest()[:12]
    return f"pg-{digest}"


@dataclass
class Finding:
    """A Layer A structural source-to-sink finding."""

    finding_id: str
    rule_id: str
    title: str
    owasp_category: str
    status: str
    severity: str
    filename: str
    line: int
    source_kind: str
    source: str
    sink_kind: str
    sink: str
    flow: str
    reason: str
    fix: str
    evidence: str
    confidence: float | str = 0.0

    @property
    def category(self) -> str:
        return self.owasp_category

    @property
    def file(self) -> str:
        return self.filename

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category
        data["file"] = self.file
        return data


@dataclass
class ScanSummary:
    total_findings: int = 0
    by_severity: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0}
    )
    by_status: dict[str, int] = field(
        default_factory=lambda: {"vulnerable": 0, "risky": 0}
    )
    by_category: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ScanSummary":
        by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_status: dict[str, int] = {"vulnerable": 0, "risky": 0}
        by_category: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_status[finding.status] = by_status.get(finding.status, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        return cls(
            total_findings=len(findings),
            by_severity=by_severity,
            by_status=by_status,
            by_category=by_category,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    ok: bool
    parse_error: str | None
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "ok": self.ok,
            "parse_error": self.parse_error,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary.to_dict(),
        }
