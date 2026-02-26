"""Helper utilities for the autopilot supervisor loop."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.tool_executors import format_availability_report
from clawpwn.ai.nli.tools import get_all_tools
from clawpwn.ai.nli.tools.tool_metadata import format_speed_table

from .autopilot_prompt import AUTOPILOT_SYSTEM_PROMPT, FOLLOW_UP_DECISION_PROMPT
from .context import get_project_context

logger = logging.getLogger(__name__)

# Tools excluded from autopilot (active exploitation).
_EXCLUDED_TOOLS = {"credential_test", "run_custom_script"}


@dataclass
class AutopilotReport:
    """Result of an autopilot run."""

    cycles: int = 0
    duration_seconds: float = 0.0
    cycle_summaries: list[str] = field(default_factory=list)
    final_summary: str = ""


def filter_recon_tools(tools: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Remove exploitation tools from the tool list."""
    all_tools = tools if tools is not None else get_all_tools()
    return [t for t in all_tools if t.get("name") not in _EXCLUDED_TOOLS]


def build_system_prompt() -> str:
    """Build the autopilot-specific system prompt."""
    return AUTOPILOT_SYSTEM_PROMPT.format(
        tool_status=format_availability_report(),
        speed_table=format_speed_table(),
    )


def attach_context(base: str, project_dir: Path) -> str:
    """Append project context to the base prompt if available."""
    ctx = get_project_context(project_dir)
    if ctx:
        return f"{base}\n\nCurrent project state:\n{ctx}"
    return base


def cycle_message(cycle: int, report: AutopilotReport) -> str:
    """Compose the user message for a given cycle."""
    if cycle == 0:
        return (
            "Perform comprehensive reconnaissance and vulnerability detection "
            "on the active target. Cover all relevant categories: fingerprint, "
            "CVE research, web scanning, network scanning, and directory enumeration."
        )
    focus = getattr(report, "_next_focus", "")
    prev = report.cycle_summaries[-1][:500] if report.cycle_summaries else ""
    return (
        f"Continue recon. Focus on: {focus}\n\n"
        f"Previous cycle summary (for context, do NOT repeat already-tested areas):\n{prev}"
    )


def clear_plan(project_dir: Path) -> None:
    """Clear any existing plan so the next cycle starts fresh."""
    try:
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        db_path = get_project_db_path(project_dir)
        if db_path:
            SessionManager(db_path).clear_plan()
    except Exception:
        logger.debug("Failed to clear plan for %s", project_dir, exc_info=True)


def should_continue(
    llm: LLMClient,
    summary: str,
    project_dir: Path,
) -> tuple[bool, str]:
    """Ask a cheap model whether another cycle is warranted."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    target = ""
    try:
        db_path = get_project_db_path(project_dir)
        if db_path:
            state = SessionManager(db_path).get_state()
            target = state.target if state else ""
    except Exception:
        logger.debug("Failed to load target for follow-up", exc_info=True)

    prompt = FOLLOW_UP_DECISION_PROMPT.format(target=target, summary=summary[:2000])
    routing_model = getattr(llm, "routing_model", None)
    raw = llm.chat(prompt, model=routing_model)
    return _parse_follow_up(raw if isinstance(raw, str) else str(raw))


def _parse_follow_up(text: str) -> tuple[bool, str]:
    """Parse the JSON follow-up decision, with regex fallback."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return (bool(data.get("continue", False)), data.get("focus", ""))
    except (json.JSONDecodeError, TypeError):
        pass
    m_json = re.search(r"\{[^}]+\}", text)
    if m_json:
        try:
            data = json.loads(m_json.group())
            if isinstance(data, dict):
                return (bool(data.get("continue", False)), data.get("focus", ""))
        except (json.JSONDecodeError, TypeError):
            pass
    return (False, "")


def fmt_duration(seconds: float) -> str:
    """Format elapsed seconds as a human-readable string."""
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"


def build_final_summary(report: AutopilotReport) -> str:
    """Combine all cycle summaries into a final report."""
    parts = [
        f"Autopilot completed {report.cycles} cycle(s) in {fmt_duration(report.duration_seconds)}.",
        "",
    ]
    for i, s in enumerate(report.cycle_summaries, 1):
        parts.append(f"--- Cycle {i} ---")
        parts.append(s)
        parts.append("")
    return "\n".join(parts)
