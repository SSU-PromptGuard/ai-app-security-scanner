"""PromptGuard Lite static analysis package."""

from .analyzer import Analyzer, analyze_code, scan_code, scan_file
from .models import Finding, ScanResult, ScanSummary


def evaluate(*args, **kwargs):
    """Lazy compatibility wrapper to avoid importing pandas during scans."""
    from .evaluator import evaluate as _evaluate

    return _evaluate(*args, **kwargs)


__all__ = [
    "Analyzer",
    "Finding",
    "ScanResult",
    "ScanSummary",
    "analyze_code",
    "evaluate",
    "scan_code",
    "scan_file",
]
