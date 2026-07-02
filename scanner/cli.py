"""Simple CLI for scanning a Python file and exporting findings."""

from __future__ import annotations

import argparse
import os
from typing import Optional

from .analyzer import analyze_code
from .exporter import export_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a Python file for LLM security risks")
    parser.add_argument("path", help="Path to the Python file to scan")
    parser.add_argument("--output", help="Output file path for exported findings")
    parser.add_argument("--format", choices=["csv", "md", "markdown"], default="csv", help="Export format")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.path):
        parser.error(f"File not found: {args.path}")

    with open(args.path, "r", encoding="utf-8") as fh:
        source = fh.read()

    findings = analyze_code(source, args.path)
    print(f"Detected {len(findings)} findings in {args.path}")

    if args.output:
        export_findings(findings, args.output, fmt=args.format)
        print(f"Exported results to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
