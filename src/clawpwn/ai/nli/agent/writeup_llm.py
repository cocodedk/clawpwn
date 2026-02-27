"""LLM-based writeup generation from scan/attack results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

_MAX_RESULT_CHARS = 500
_MAX_FINDINGS = 50

WRITEUP_PROMPT = """\
You are a penetration testing report writer. Given the scan results, findings,
and project context below, write a concise but thorough narrative writeup.

Use the following sections (in Markdown):
## Objective
## Methodology
## Steps Taken
## Tools & Techniques
## Attack Chains
## What Worked / What Didn't
## Conclusions

Keep the writeup factual — cite specific tools, ports, and findings.
If no vulnerabilities were found, say so clearly and explain what was tested.

---
Target: {target}
{objective_section}
{findings_section}
{results_section}
"""


def _build_objective_section(project_dir: Path) -> str:
    """Load the project objective from memory, if available."""
    try:
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        db_path = get_project_db_path(project_dir)
        if not db_path:
            return ""
        session = SessionManager(db_path)
        mem = session.get_memory()
        if mem and mem.objective:
            return f"Project objective: {mem.objective}"
    except Exception:
        pass
    return ""


def _build_findings_section(project_dir: Path) -> str:
    """Summarize stored findings for the prompt."""
    try:
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        db_path = get_project_db_path(project_dir)
        if not db_path:
            return ""
        session = SessionManager(db_path)
        findings = session.get_findings()
        if not findings:
            return "Findings: None recorded."
        lines = [f"Findings ({min(len(findings), _MAX_FINDINGS)} shown):"]
        for f in findings[:_MAX_FINDINGS]:
            lines.append(f"- [{f.severity.upper()}] {f.title}: {(f.description or '')[:200]}")
        return "\n".join(lines)
    except Exception:
        return ""


def _build_results_section(all_results: list[dict[str, Any]]) -> str:
    """Format step results for the prompt."""
    if not all_results:
        return "Step results: None."
    lines = ["Step results:"]
    for r in all_results:
        tool = r.get("tool", "unknown")
        desc = r.get("description", "")
        text = r.get("result", "")
        if len(text) > _MAX_RESULT_CHARS:
            text = text[:_MAX_RESULT_CHARS] + "..."
        lines.append(f"- {tool}: {desc}\n  Result: {text}")
    return "\n".join(lines)


def generate_writeup(
    llm: Any,
    target: str,
    all_results: list[dict[str, Any]],
    project_dir: Path,
) -> str:
    """Generate a narrative writeup via a single LLM call.

    Returns markdown text. Falls back to a raw results dump on failure.
    """
    prompt = WRITEUP_PROMPT.format(
        target=target,
        objective_section=_build_objective_section(project_dir),
        findings_section=_build_findings_section(project_dir),
        results_section=_build_results_section(all_results),
    )

    try:
        response = llm.chat(prompt)
        if isinstance(response, str) and response.strip():
            return response.strip()
    except Exception:
        pass

    # Fallback: raw dump
    lines = [f"# Task Writeup — {target}", ""]
    for r in all_results:
        tool = r.get("tool", "unknown")
        text = r.get("result", "(no output)")[:_MAX_RESULT_CHARS]
        lines.append(f"## {tool}\n{text}\n")
    return "\n".join(lines)
