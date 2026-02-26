"""Step execution helpers for the code-driven plan executor."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from clawpwn.ai.nli.tool_executors import dispatch_tool
from clawpwn.ai.nli.tools.tool_metadata import get_profile

from .plan_context import enrich_context, revision_reason
from .plan_helpers import step_to_dispatch_params
from .result_builder import format_tool_call


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[:max_len] + "..."


def _step_result(
    step: dict,
    tool_name: str = "",
    params: dict | None = None,
    result_text: str = "",
    *,
    failed: bool | None = None,
) -> dict[str, Any]:
    """Build a standardised step result dict."""
    if failed is None:
        failed = result_text.startswith("Tool '") and "failed:" in result_text
    return {
        "step_number": step["step_number"],
        "description": step["description"],
        "tool": step["tool"],
        "tool_name": tool_name,
        "params": params or {},
        "result_text": result_text,
        "failed": failed,
        "result_summary": _truncate(result_text, 200),
        "status": "done",
    }


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
            "target_ports": getattr(s, "target_ports", "") or "",
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
    """Execute steps in parallel within a tier."""
    if not steps:
        return []
    results: list[dict[str, Any]] = []

    def _run_step(step: dict[str, Any]) -> dict[str, Any]:
        tn, params = step_to_dispatch_params(step["tool"], target, context)
        rt = dispatch_tool(tn, params, project_dir)
        return _step_result(step, tn, params, rt)

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

        try:
            for future in as_completed(futures):
                step_num = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = _step_result(
                        {"step_number": step_num, "description": "", "tool": ""},
                        "",
                        {},
                        str(exc),
                        failed=True,
                    )
                results.append(result)
                session.update_step_status(step_num, "done", result["result_summary"])
                done_str = f"  ✓ Step {step_num} done"
                emit(done_str)
                progress.append(done_str)
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            # Reset in-progress steps to pending so they can be resumed.
            for sn in futures.values():
                try:
                    session.update_step_status(sn, "pending")
                except Exception:
                    pass
            raise

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
    emit(f"  Step {step_num}: {format_tool_call(tool_name, params)}")
    progress.append(f"Step {step_num}: {format_tool_call(tool_name, params)}")
    session.update_step_status(step_num, "in_progress")
    try:
        rt = dispatch_tool(tool_name, params, project_dir)
    except Exception as exc:
        rt = str(exc)
    result = _step_result(step, tool_name, params, rt)
    session.update_step_status(step_num, "done", result["result_summary"])
    emit(f"  ✓ Step {step_num} done")
    progress.append(f"✓ Step {step_num} done")
    return result


# Re-export for backward compatibility
__all__ = [
    "enrich_context",
    "execute_single_step",
    "execute_tier_parallel",
    "get_existing_plan",
    "get_session_and_target",
    "group_by_tier",
    "revision_reason",
]
