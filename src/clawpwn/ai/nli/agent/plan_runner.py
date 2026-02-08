"""Step execution helpers for the code-driven plan executor."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from clawpwn.ai.nli.tool_executors import dispatch_tool
from clawpwn.ai.nli.tools.tool_metadata import get_profile

from .plan_helpers import step_to_dispatch_params
from .result_builder import format_tool_call


def get_session_and_target(project_dir: Path) -> tuple[Any, str]:
    """Load session manager and active target."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    db_path = get_project_db_path(project_dir)
    if not db_path:
        return None, ""
    session = SessionManager(db_path)
    state = session.get_state()
    target = state.target if state else ""
    return session, target


def get_existing_plan(session: Any) -> list[dict[str, Any]] | None:
    """Check for a pending plan to resume."""
    if session is None:
        return None
    next_step = session.get_next_pending_step()
    if next_step is None:
        return None
    plan = session.get_plan()
    return [
        {
            "step_number": s.step_number,
            "description": s.description,
            "tool": s.tool,
            "status": s.status,
        }
        for s in plan
    ]


def group_by_tier(steps: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """Group plan steps by their speed tier."""
    tiers: dict[int, list[dict[str, Any]]] = {}
    for step in steps:
        tool = step.get("tool", "")
        if ":" in tool:
            tool_name, config = tool.split(":", 1)
            profile = get_profile(tool_name, config)
        else:
            profile = get_profile(tool)
        tier = profile.speed_tier
        tiers.setdefault(tier, []).append(step)
    return tiers


def execute_tier_parallel(
    steps: list[dict[str, Any]],
    target: str,
    context: dict[str, Any],
    project_dir: Path,
    session: Any,
    emit: Any,
    progress: list[str],
    max_workers: int = 4,
) -> list[dict[str, Any]]:
    """Execute steps in parallel within a tier using ThreadPoolExecutor."""
    if not steps:
        return []

    results: list[dict[str, Any]] = []

    def _run_step(step: dict[str, Any]) -> dict[str, Any]:
        tool_name, params = step_to_dispatch_params(step["tool"], target, context)
        result_text = dispatch_tool(tool_name, params, project_dir)
        return {
            "step_number": step["step_number"],
            "description": step["description"],
            "tool": step["tool"],
            "tool_name": tool_name,
            "params": params,
            "result_text": result_text,
            "failed": result_text.startswith("Tool '") and "failed:" in result_text,
            "result_summary": _truncate(result_text, 200),
            "status": "done",
        }

    with ThreadPoolExecutor(max_workers=min(max_workers, len(steps))) as pool:
        futures = {}
        for step in steps:
            step_num = step["step_number"]
            tool_name, params = step_to_dispatch_params(step["tool"], target, context)
            call_str = format_tool_call(tool_name, params)
            emit(f"  Step {step_num}: {call_str}")
            progress.append(f"Step {step_num}: {call_str}")
            session.update_step_status(step_num, "in_progress")
            futures[pool.submit(_run_step, step)] = step_num

        for future in as_completed(futures):
            step_num = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "step_number": step_num,
                    "description": "",
                    "tool": "",
                    "result_text": str(exc),
                    "failed": True,
                    "result_summary": f"Error: {exc}",
                    "status": "done",
                }

            results.append(result)
            session.update_step_status(step_num, "done", result["result_summary"])
            done_str = f"  ✓ Step {step_num} done"
            emit(done_str)
            progress.append(done_str)

    return results


def execute_single_step(
    step: dict[str, Any],
    target: str,
    context: dict[str, Any],
    project_dir: Path,
    session: Any,
    emit: Any,
    progress: list[str],
) -> dict[str, Any]:
    """Execute a single step sequentially."""
    step_num = step["step_number"]
    tool_name, params = step_to_dispatch_params(step["tool"], target, context)
    call_str = format_tool_call(tool_name, params)
    emit(f"  Step {step_num}: {call_str}")
    progress.append(f"Step {step_num}: {call_str}")
    session.update_step_status(step_num, "in_progress")

    try:
        result_text = dispatch_tool(tool_name, params, project_dir)
        failed = result_text.startswith("Tool '") and "failed:" in result_text
    except Exception as exc:
        result_text = str(exc)
        failed = True

    summary = _truncate(result_text, 200)
    session.update_step_status(step_num, "done", summary)
    emit(f"  ✓ Step {step_num} done")
    progress.append(f"✓ Step {step_num} done")

    return {
        "step_number": step_num,
        "description": step["description"],
        "tool": step["tool"],
        "result_text": result_text,
        "failed": failed,
        "result_summary": summary,
        "status": "done",
    }


def enrich_context(context: dict[str, Any], tier_results: list[dict[str, Any]]) -> None:
    """Extract context from tier results (app hints, technologies, etc.)."""
    for result in tier_results:
        text = result.get("result_text", "").lower()
        if result.get("tool") == "fingerprint_target":
            for app in ("phpmyadmin", "wordpress", "joomla", "jenkins", "grafana"):
                if app in text:
                    context["app_hint"] = app
                    break
            for tech in ("php", "apache", "nginx", "mysql", "postgresql", "python", "node"):
                if tech in text and tech not in context.get("techs", []):
                    context.setdefault("techs", []).append(tech)


def revision_reason(tier_results: list[dict[str, Any]]) -> str:
    """Build a reason string for plan revision."""
    failures = [r for r in tier_results if r.get("failed")]
    if failures:
        return f"{len(failures)}/{len(tier_results)} steps failed"
    blocks = [r for r in tier_results if r.get("policy_action") in ("stop_and_replan", "stop")]
    if blocks:
        return "Attack feedback signals indicate blocking/WAF"
    return "Results suggest plan adjustment needed"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len characters."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
