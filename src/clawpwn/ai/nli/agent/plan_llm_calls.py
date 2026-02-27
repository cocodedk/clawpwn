"""LLM interaction functions for the code-driven plan executor.

Only 3 LLM calls in the happy path:
1. generate_plan   — Sonnet creates the plan via save_plan tool
2. revise_plan     — Sonnet adjusts remaining steps (conditional)
3. summarize_results — Sonnet writes the final report
"""

from __future__ import annotations

from typing import Any

from .plan_optimizers import all_results_empty
from .prompt import ROUTING_MAX_TOKENS, THINKING_BUDGET
from .result_builder import split_content


def generate_plan(
    llm: Any,
    system_prompt: str,
    user_message: str,
    tools: list[dict[str, Any]],
) -> list[dict[str, str]] | None:
    """Call Sonnet once to generate a structured plan.

    The LLM is given only the ``save_plan`` tool so it must produce a
    structured plan.  We extract the steps from the tool_use block.

    Returns a list of step dicts (``{"description": ..., "tool": ...}``)
    or ``None`` if the LLM didn't call save_plan (fall back to agent loop).
    """
    # Filter tools to only save_plan
    save_plan_tools = [t for t in tools if t.get("name") == "save_plan"]
    if not save_plan_tools:
        return None

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"{user_message}\n\n"
                "Create an attack plan using the save_plan tool. "
                "Match the plan exactly to what the user asked for. "
                "If the user asked for a specific tool or test (e.g. 'run hydra', "
                "'sqlmap the login'), create a focused plan with ONLY that tool. "
                "If the user mentions specific ports (e.g. 'port 21', 'ports 80,443'), "
                "set target_ports on EVERY step and only include tools relevant to "
                "those ports/services. For non-HTTP ports (21, 22, 25, etc.), do NOT "
                "include web_scan tools — use network_scan, credential_test, and "
                "research_vulnerabilities instead. "
                "Only create a broad multi-tool plan if the user asked for a "
                "general scan or full assessment."
            ),
        }
    ]

    response = llm.chat_with_tools(
        messages=messages,
        tools=save_plan_tools,
        system_prompt=system_prompt,
        model=llm.model,
        max_tokens=ROUTING_MAX_TOKENS,
        thinking_budget=THINKING_BUDGET,
    )

    _, tool_calls = split_content(response.content)
    for tc in tool_calls:
        if tc.name == "save_plan":
            steps = tc.input.get("steps", [])
            if steps:
                return steps

    return None


def revise_plan(
    llm: Any,
    system_prompt: str,
    completed_results: list[dict[str, Any]],
    pending_steps: list[dict[str, str]],
    reason: str,
) -> list[dict[str, str]] | None:
    """Ask Sonnet to revise the remaining plan after a tier produced problems.

    Returns revised step dicts or None (keep current plan).
    """
    save_plan_tools = _get_save_plan_tool()
    if not save_plan_tools:
        return None

    completed_summary = "\n".join(
        f"- Step {r['step_number']}: {r['description']} -> {r.get('result_summary', 'done')}"
        for r in completed_results
    )
    pending_summary = "\n".join(
        f"- {s.get('description', '?')} (tool: {s.get('tool', '?')})" for s in pending_steps
    )

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"The current attack plan needs revision.\n\n"
                f"Reason: {reason}\n\n"
                f"Completed steps:\n{completed_summary}\n\n"
                f"Remaining steps (may need changes):\n{pending_summary}\n\n"
                "Please create a revised plan using save_plan. Keep completed "
                "work in mind and adjust remaining steps to address the issues."
            ),
        }
    ]

    response = llm.chat_with_tools(
        messages=messages,
        tools=save_plan_tools,
        system_prompt=system_prompt,
        model=llm.model,
        max_tokens=ROUTING_MAX_TOKENS,
        thinking_budget=THINKING_BUDGET,
    )

    _, tool_calls = split_content(response.content)
    for tc in tool_calls:
        if tc.name == "save_plan":
            steps = tc.input.get("steps", [])
            if steps:
                return steps

    return None


def summarize_results(
    llm: Any,
    system_prompt: str,
    all_results: list[dict[str, Any]],
    target: str,
) -> str:
    """Call Sonnet once to produce a final assessment report."""
    results_text = "\n".join(
        f"Step {r['step_number']}. {r['description']} "
        f"[{r.get('status', 'done')}]: {r.get('result_summary', 'no summary')}"
        for r in all_results
    )

    if all_results_empty(all_results):
        prompt = (
            f"Target: {target}\n\n"
            f"All scans completed with no findings:\n{results_text}\n\n"
            "Provide a brief summary (2-3 sentences): what was tested, "
            "that nothing was found, and 2-3 likely reasons why (host down, "
            "firewalled, wrong target, etc.). Do NOT list manual commands."
        )
    else:
        prompt = (
            f"Target: {target}\n\n"
            f"All completed scan/attack step results:\n{results_text}\n\n"
            "Provide a concise penetration test summary:\n"
            "1. Critical/high findings with exploitation details\n"
            "2. Medium/low findings\n"
            "3. Categories tested with no findings\n"
            "4. Recommended manual follow-up steps"
        )

    try:
        return llm.chat(prompt, system_prompt)
    except Exception as exc:
        return f"Summary generation failed: {exc}\n\nRaw results:\n{results_text}"


def _get_save_plan_tool() -> list[dict[str, Any]]:
    """Import and return the save_plan tool schema."""
    try:
        from clawpwn.ai.nli.tools.plan_tools import SAVE_PLAN_TOOL

        return [SAVE_PLAN_TOOL]
    except ImportError:
        return []
