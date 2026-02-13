"""Web scan executor for NLI tool agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run

from ..availability import enrich_missing_tool_error

MAX_FINDINGS_IN_RESULT = 20
MAX_EVIDENCE_CHARS = 200


def execute_web_scan(params: dict[str, Any], project_dir: Path) -> str:
    """Run web vulnerability scan and return compact result text."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.scanner import Scanner
    from clawpwn.modules.session import SessionManager
    from clawpwn.modules.webscan import (
        WebScanConfig,
        WebScanOrchestrator,
        create_default_webscan_plugins,
    )

    target = params["target"]
    depth = params.get("depth", "normal")
    vuln_cats = params.get("vuln_categories") or []
    scan_types = vuln_cats if vuln_cats else ["all"]
    tools_list = params.get("tools") or ["builtin"]
    timeout = params.get("timeout")
    concurrency = max(1, params.get("concurrency", 10))

    orchestrator = WebScanOrchestrator(
        plugins=create_default_webscan_plugins(project_dir, scanner_factory=Scanner)
    )
    config = WebScanConfig(
        depth=depth,
        timeout=timeout,
        concurrency=concurrency,
        verbose=True,
        scan_types=scan_types,
        service_keywords=params.get("service_keywords", []),
    )

    # Print plugin progress live to stdout
    def _progress(msg: str) -> None:
        print(msg)

    findings, errors = safe_async_run(
        orchestrator.scan_target_with_diagnostics(
            target, config=config, tools=tools_list, progress=_progress
        )
    )
    feedback = _collect_attack_feedback(findings)

    # Log the scan action to project database
    try:
        db_path = get_project_db_path(project_dir)
        if db_path:
            session = SessionManager(db_path)
            tools_str = ",".join(tools_list)
            cats_str = ",".join(scan_types)
            session.add_log(
                message=f"web_scan: {tools_str} [{cats_str}] depth={depth} -> {len(findings)} findings",
                level="INFO",
                phase="scan",
                details=json.dumps(
                    {
                        "tool": "web_scan",
                        "tools_used": tools_list,
                        "categories": scan_types,
                        "depth": depth,
                        "target": target,
                        "findings_count": len(findings),
                        "attack_feedback": feedback,
                    }
                ),
            )
    except Exception:
        pass  # Don't fail the scan if logging fails

    return _format_scan_findings(findings, errors, target, feedback)


def _format_scan_findings(
    findings: list, errors: list, target: str, feedback: dict[str, Any]
) -> str:
    """Compact summary of web scan results for Claude (token-efficient)."""
    parts: list[str] = [f"Scan of {target} complete."]

    if errors:
        err_lines = [enrich_missing_tool_error(f"{e.tool}: {e.message}") for e in errors]
        parts.append("Tool issues: " + "; ".join(err_lines))

    feedback_line = _render_feedback_summary(feedback)
    if feedback_line:
        parts.append(feedback_line)

    if not findings:
        parts.append("No vulnerabilities found.")
        return "\n".join(parts)

    by_sev: dict[str, int] = {}
    for f in findings:
        sr = f.to_scan_result()
        by_sev[sr.severity] = by_sev.get(sr.severity, 0) + 1

    summary = ", ".join(f"{cnt} {sev}" for sev, cnt in sorted(by_sev.items()))
    parts.append(f"Total findings: {len(findings)} ({summary}).")

    # Top findings (capped for token efficiency)
    top = sorted(findings, key=lambda f: _sev_rank(f.severity))[:MAX_FINDINGS_IN_RESULT]
    parts.append("Top findings:")
    for f in top:
        evidence = (f.evidence or "")[:MAX_EVIDENCE_CHARS]
        parts.append(f"  - [{f.severity.upper()}] {f.title} @ {f.url} ({f.attack_type})")
        if evidence:
            parts.append(f"    evidence: {evidence}")

    return "\n".join(parts)


def _sev_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def _collect_attack_feedback(findings: list) -> dict[str, Any]:
    hints: list[str] = []
    blocks: list[str] = []
    policy = "continue"
    reason = ""
    for finding in findings:
        raw = getattr(finding, "raw", None)
        if not isinstance(raw, dict):
            continue
        for hint in raw.get("feedback_hints", []):
            if hint not in hints:
                hints.append(hint)
        for block in raw.get("feedback_blocks", []):
            if block not in blocks:
                blocks.append(block)
        if raw.get("feedback_policy"):
            policy = raw["feedback_policy"]
        if raw.get("feedback_reason"):
            reason = raw["feedback_reason"]

    return {
        "hints": hints[:5],
        "blocks": blocks[:5],
        "policy": policy,
        "reason": reason,
    }


def _render_feedback_summary(feedback: dict[str, Any]) -> str:
    hints = feedback.get("hints", [])
    blocks = feedback.get("blocks", [])
    policy = feedback.get("policy", "continue")
    reason = feedback.get("reason", "")
    if not hints and not blocks:
        return ""

    parts: list[str] = ["Attack feedback:"]
    if hints:
        parts.append(f"hints={len(hints)}")
    if blocks:
        parts.append(f"blocks={len(blocks)}")
    parts.append(f"policy={policy}")
    if reason:
        parts.append(f"reason={reason}")
    return " ".join(parts)
