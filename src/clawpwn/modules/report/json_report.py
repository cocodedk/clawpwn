"""JSON report rendering."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import ReportConfig


def generate_json_report(
    report_dir: Path,
    state: Any,
    findings: list[Any],
    config: ReportConfig,
) -> Path:
    """Generate a JSON report file."""
    generated_at = datetime.now()

    report_data = {
        "report_metadata": {
            "generated_at": generated_at.isoformat(),
            "tool": "ClawPwn",
            "version": "0.1.0",
        },
        "project": {
            "path": state.project_path,
            "target": state.target,
            "current_phase": state.current_phase,
            "created_at": state.created_at.isoformat()
            if hasattr(state.created_at, "isoformat")
            else str(state.created_at),
        },
        "summary": {
            "total_findings": len(findings),
            "critical": state.critical_count,
            "high": state.high_count,
        },
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "attack_type": finding.attack_type,
                "description": finding.description,
                "evidence": finding.evidence if config.include_evidence else None,
                "remediation": finding.remediation if config.include_remediation else None,
                "created_at": finding.created_at.isoformat()
                if hasattr(finding.created_at, "isoformat")
                else str(finding.created_at),
            }
            for finding in findings
        ],
    }

    report_file = report_dir / f"pentest_report_{generated_at.strftime('%Y%m%d_%H%M%S')}.json"
    report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return report_file
