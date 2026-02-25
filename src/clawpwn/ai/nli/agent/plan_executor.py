"""Code-driven plan executor: LLM plans, code executes, LLM summarizes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.ai.nli.tool_executors.plan_executors import _sort_steps_by_speed

from .plan_helpers import (
    build_plan_prompt,
    is_focused_request,
    is_llm_dependent_step,
    needs_revision,
)
from .plan_llm_calls import generate_plan, revise_plan, summarize_results
from .plan_runner import (
    enrich_context,
    execute_single_step,
    execute_tier_parallel,
    get_existing_plan,
    get_session_and_target,
    group_by_tier,
    revision_reason,
)
from .result_builder import build_result


def run_plan_executor(
    llm: Any,
    project_dir: Path,
    tools: list[dict[str, Any]],
    system_prompt: str,
    user_message: str,
    on_progress: Any | None = None,
    debug: bool = False,
) -> dict[str, Any]:
    """Execute a scan/attack request via code-driven plan execution."""
    progress_updates: list[str] = []
    is_streamed = on_progress is not None

    def _emit(message: str) -> None:
        if on_progress is not None:
            on_progress(message)

    # --- Phase 1: Get or create plan ---
    session, target = get_session_and_target(project_dir)
    if not target:
        return build_result(
            success=False,
            text="No target set. Use 'set target <url>' first.",
            action="plan",
            progress=progress_updates,
            suggestions=[],
            streamed=is_streamed,
        )

    existing_plan = get_existing_plan(session)
    if existing_plan and is_focused_request(user_message):
        _emit("New specific request — replacing previous plan...")
        progress_updates.append("Cleared stale plan for focused request")
        session.clear_plan()
        existing_plan = None
    if existing_plan:
        _emit("Resuming existing plan...")
        progress_updates.append("Resuming existing plan")
        steps = existing_plan
    else:
        _emit("Generating attack plan...")
        progress_updates.append("Generating attack plan")
        plan_prompt = build_plan_prompt(system_prompt, user_message, project_dir)
        raw_steps = generate_plan(llm, plan_prompt, user_message, tools)
        if raw_steps is None:
            from .executor import run_agent_loop

            return run_agent_loop(
                llm=llm,
                project_dir=project_dir,
                tools=tools,
                system_prompt=system_prompt,
                user_message=user_message,
                on_progress=on_progress,
                debug=debug,
            )

        # Capture target_ports from LLM output before DB save (not persisted)
        ports_from_plan = ""
        for rs in raw_steps:
            tp = rs.get("target_ports", "")
            if tp:
                ports_from_plan = tp
                break

        sorted_steps = _sort_steps_by_speed(raw_steps)
        created = session.save_plan(sorted_steps)
        steps = [
            {"step_number": s.step_number, "description": s.description, "tool": s.tool}
            for s in created
        ]

        plan_msg = f"Plan created ({len(steps)} steps, ordered fastest-first)"
        _emit(plan_msg)
        progress_updates.append(plan_msg)

    # --- Phase 2: Execute tier by tier ---
    context: dict[str, Any] = {"app_hint": "", "techs": [], "vuln_categories": []}
    if not existing_plan and ports_from_plan:
        context["target_ports"] = ports_from_plan
    all_results: list[dict[str, Any]] = []
    tiers = group_by_tier(steps)

    for tier_num in sorted(tiers.keys()):
        tier_steps = tiers[tier_num]
        tier_label = {1: "FAST", 2: "MEDIUM", 3: "SLOW"}.get(tier_num, f"TIER-{tier_num}")
        _emit(f"\n--- {tier_label} phase ({len(tier_steps)} steps) ---")
        progress_updates.append(f"--- {tier_label} phase ---")

        pending = [s for s in tier_steps if s.get("status", "pending") == "pending"]
        if not pending:
            _emit(f"  All {tier_label} steps already complete, skipping")
            continue

        executable = [s for s in pending if not is_llm_dependent_step(s["tool"])]
        llm_dependent = [s for s in pending if is_llm_dependent_step(s["tool"])]

        tier_results = execute_tier_parallel(
            executable,
            target,
            context,
            project_dir,
            session,
            _emit,
            progress_updates,
        )
        all_results.extend(tier_results)

        for step in llm_dependent:
            result = execute_single_step(
                step,
                target,
                context,
                project_dir,
                session,
                _emit,
                progress_updates,
            )
            all_results.append(result)
            tier_results.append(result)

        enrich_context(context, tier_results)

        if needs_revision(tier_results):
            _emit("Plan revision needed based on results...")
            progress_updates.append("Revising plan")
            completed = [r for r in all_results if not r.get("failed")]
            remaining_steps = []
            for t in sorted(tiers.keys()):
                if t > tier_num:
                    remaining_steps.extend(tiers[t])
            reason = revision_reason(tier_results)
            revised = revise_plan(
                llm,
                system_prompt,
                completed,
                remaining_steps,
                reason,
            )
            if revised:
                sorted_revised = _sort_steps_by_speed(revised)
                created = session.save_plan(sorted_revised)
                new_steps = [
                    {"step_number": s.step_number, "description": s.description, "tool": s.tool}
                    for s in created
                ]
                tiers = group_by_tier(new_steps)
                _emit(f"Plan revised ({len(new_steps)} steps)")
                progress_updates.append(f"Plan revised ({len(new_steps)} steps)")

    # --- Phase 3: Summarize ---
    _emit("\nGenerating summary...")
    progress_updates.append("Generating summary")
    summary = summarize_results(llm, system_prompt, all_results, target)
    _emit(summary)

    return build_result(
        success=True,
        text=summary,
        action="scan",
        progress=progress_updates,
        suggestions=[],
        streamed=is_streamed,
        model=getattr(llm, "model", None),
    )
