"""Data structures for scan findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Optional

_OWASP_CODE_RE = re.compile(r"LLM\d+")


@dataclass
class Finding:
    """A single risky source -> sink pattern detected by the static analyzer.

    This is a *candidate* risk, not a proof of exploitability. Statuses are
    intentionally hedged (risky / needs_review) where the structure alone is
    not conclusive.
    """

    rule_id: str
    owasp_category: str
    severity: str            # low | medium | high | critical
    status: str              # safe | risky | vulnerable | needs_review
    title: str
    source: str
    sink: str
    flow: str
    reason: str
    fix: str
    line: int
    confidence: str          # low | medium | high

    def owasp_codes(self) -> list[str]:
        """Return the OWASP code(s) referenced, e.g. ['LLM05']."""
        return _OWASP_CODE_RE.findall(self.owasp_category)

    def to_dict(self) -> dict:
        return asdict(self)
