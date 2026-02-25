"""Executors for attack plan management tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _sort_steps_by_speed(steps: list[dict[str, str]]) -> list[dict[str, str]]:
    """Sort structured plan steps fastest-first using tool profile lookup.

    No keyword matching — speed tier comes directly from the tool name
    that the LLM specified.
    """
    from clawpwn.ai.nli.tools.tool_metadata import get_profile

    def _key(step: dict[str, str]) -> tuple[int, int]:
        tool = step.get("tool", "")
        # Split "web_scan:sqlmap" into tool_name="web_scan", config="sqlmap"
        if ":" in tool:
            tool_name, config = tool.split(":", 1)
            profile = get_profile(tool_name, config)
        else:
            profile = get_profile(tool)
        return (profile.speed_tier, -profile.priority)

    return sorted(steps, key=_key)


def execute_save_plan(params: dict[str, Any], project_dir: Path) -> str:
    """Persist an attack plan to the project database.

    Steps are automatically reordered fastest-first using tool speed tiers
    looked up from the tool name — no keyword guessing.
    """
    from clawpwn.ai.nli.tools.tool_metadata import get_profile
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    raw_steps = params.get("steps", [])
    if not raw_steps:
        return "Error: plan must contain at least one step."

    db_path = get_project_db_path(project_dir)
    if not db_path:
        return "Error: no project database found."

    # Normalise: accept both list[str] (legacy) and list[dict]
    normalised: list[dict[str, str]] = []
    for item in raw_steps:
        if isinstance(item, str):
            normalised.append({"description": item.strip(), "tool": ""})
        else:
            normalised.append(
                {
                    "description": item.get("description", "").strip(),
                    "tool": item.get("tool", ""),
                }
            )

    # Sort by speed tier (fast → medium → slow)
    sorted_steps = _sort_steps_by_speed(normalised)

    session = SessionManager(db_path)
    created = session.save_plan(sorted_steps)

    lines = [f"Plan saved ({len(created)} steps, ordered fastest-first):"]
    for s in created:
        tool = s.tool or "unknown"
        if ":" in tool:
            tool_name, config = tool.split(":", 1)
            profile = get_profile(tool_name, config)
        else:
            profile = get_profile(tool)
        lines.append(
            f"  [ ] {s.step_number}. {s.description}  ({profile.label} ~{profile.est_seconds}s)"
        )
    return "\n".join(lines)


def execute_update_plan_step(params: dict[str, Any], project_dir: Path) -> str:
    """Update a plan step's status and optional result summary."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    step_number = params.get("step_number")
    status = params.get("status", "done")
    result_summary = params.get("result_summary", "")

    if step_number is None:
        return "Error: step_number is required."

    db_path = get_project_db_path(project_dir)
    if not db_path:
        return "Error: no project database found."

    session = SessionManager(db_path)
    step = session.update_step_status(step_number, status, result_summary)
    if step is None:
        return f"Error: step {step_number} not found."

    # Return current plan status so the agent sees full progress
    return session.format_plan_status()
