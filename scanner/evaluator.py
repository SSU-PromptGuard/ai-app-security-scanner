"""Evaluation of the analyzer against the labelled sample set."""

from __future__ import annotations

import os
from typing import Optional

import pandas as pd

from .analyzer import analyze_code

POSITIVE_LABELS = {"vulnerable", "risky"}


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def evaluate(project_root: str, labels_path: Optional[str] = None):
    """Scan every labelled sample and compare predictions to ground truth.

    Binary convention:
        positive = label in {vulnerable, risky}
        negative = label == safe
        predicted positive = analyzer returns >= 1 finding

    Returns ``(metrics: dict, table: pandas.DataFrame)``.
    """
    labels_path = labels_path or os.path.join(project_root, "data", "labels.csv")
    df = pd.read_csv(labels_path).fillna("")

    rows = []
    tp = fp = fn = tn = 0

    for _, row in df.iterrows():
        file_rel = str(row["file"])
        file_abs = os.path.join(project_root, file_rel)
        try:
            with open(file_abs, "r", encoding="utf-8") as f:
                source = f.read()
        except OSError:
            source = ""

        findings = [f for f in analyze_code(source, file_rel) if f.rule_id != "parse_error"]
        detected = sorted({code for f in findings for code in f.owasp_codes()})

        expected_positive = str(row["label"]).strip().lower() in POSITIVE_LABELS
        predicted_positive = len(findings) > 0

        if expected_positive and predicted_positive:
            result = "TP"; tp += 1
        elif not expected_positive and predicted_positive:
            result = "FP"; fp += 1
        elif expected_positive and not predicted_positive:
            result = "FN"; fn += 1
        else:
            result = "TN"; tn += 1

        rows.append({
            "sample_id": row["sample_id"],
            "expected_label": row["label"],
            "predicted_label": "positive" if predicted_positive else "negative",
            "expected_category": row["category"],
            "detected_categories": ", ".join(detected) if detected else "-",
            "n_findings": len(findings),
            "result": result,
        })

    total = tp + fp + fn + tn
    metrics = {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": _safe_div(tp, tp + fp),
        "recall": _safe_div(tp, tp + fn),
        "accuracy": _safe_div(tp + tn, total),
        "total": total,
    }
    table = pd.DataFrame(rows)
    return metrics, table
