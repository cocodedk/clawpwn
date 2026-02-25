"""Helpers for grouping findings."""

from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def group_by_severity(findings: list[Any]) -> dict[str, list[Any]]:
    """Group findings by normalized severity."""
    grouped = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = str(getattr(finding, "severity", "")).lower()
        if severity in grouped:
            grouped[severity].append(finding)
    return grouped
