"""Export scan findings to CSV or Markdown."""

from __future__ import annotations

import os
from typing import Iterable, List

import pandas as pd

from .models import Finding


def findings_to_dataframe(findings: Iterable[Finding]) -> pd.DataFrame:
    rows = []
    for finding in findings:
        rows.append(
            {
                "rule_id": finding.rule_id,
                "owasp_category": finding.owasp_category,
                "severity": finding.severity,
                "status": finding.status,
                "title": finding.title,
                "source": finding.source,
                "sink": finding.sink,
                "flow": finding.flow,
                "reason": finding.reason,
                "fix": finding.fix,
                "line": finding.line,
                "confidence": finding.confidence,
            }
        )
    return pd.DataFrame(rows)


def export_findings(findings: Iterable[Finding], output_path: str, fmt: str = "csv") -> str:
    fmt = (fmt or "csv").lower()
    if fmt not in {"csv", "md", "markdown"}:
        raise ValueError(f"Unsupported export format: {fmt}")

    df = findings_to_dataframe(findings)
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if fmt in {"md", "markdown"}:
        markdown = _build_markdown_report(df, output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(markdown)
    else:
        df.to_csv(output_path, index=False)

    return output_path


def _build_markdown_report(df: pd.DataFrame, output_path: str) -> str:
    title = os.path.basename(output_path)
    lines = [f"# Scan Results: {title}", "", f"- Findings: {len(df)}", ""]
    if df.empty:
        lines.append("No findings detected.")
        return "\n".join(lines) + "\n"

    lines.append("| rule_id | severity | status | source | sink | line |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for _, row in df.iterrows():
        lines.append(
            f"| {row['rule_id']} | {row['severity']} | {row['status']} | {row['source']} | {row['sink']} | {int(row['line'])} |"
        )
    return "\n".join(lines) + "\n"
