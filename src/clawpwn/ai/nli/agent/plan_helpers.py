"""Intent classification and plan step mapping for the code-driven executor."""

from __future__ import annotations

from typing import Any


def classify_intent(
    llm: Any,
    user_message: str,
    has_pending_plan: bool,
) -> str:
    """Classify user intent as plan_execute or conversational.

    If a pending plan already exists, skip the LLM call entirely and return
    ``plan_execute`` so we resume where we left off.

    Returns one of: ``"plan_execute"`` | ``"conversational"``.
    """
    if has_pending_plan:
        return "plan_execute"

    # Use the cheap routing model (Haiku) for classification
    prompt = (
        "Classify this user message into exactly ONE category.\n"
        "Respond with ONLY the category name, nothing else.\n\n"
        "Categories:\n"
        "- plan_execute: user wants scanning, testing, attacking, exploiting, "
        "or any security assessment action on a target\n"
        "- conversational: user is asking a question, requesting status, "
        "asking for help, setting a target, or any non-action request\n\n"
        f'Message: "{user_message}"'
    )
    try:
        raw = llm.chat(prompt)
        if not isinstance(raw, str):
            return "conversational"
        result = raw.strip().lower()
        if "plan_execute" in result:
            return "plan_execute"
        return "conversational"
    except Exception:
        # Default to conversational on failure (safe fallback)
        return "conversational"


def step_to_dispatch_params(
    step_tool: str,
    target: str,
    context: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Map a plan step's tool field to dispatch_tool(name, params) arguments.

    Args:
        step_tool: Tool identifier from PlanStep.tool (e.g. "web_scan:sqlmap").
        target: Active target URL or IP.
        context: Runtime context dict with keys like app_hint, techs, etc.

    Returns:
        (tool_name, params) tuple ready for ``dispatch_tool()``.
    """
    app_hint = context.get("app_hint", "")
    vuln_categories = context.get("vuln_categories", [])

    # Split "web_scan:sqlmap" into ("web_scan", "sqlmap")
    if ":" in step_tool:
        base_tool, variant = step_tool.split(":", 1)
    else:
        base_tool, variant = step_tool, ""

    if base_tool == "web_scan":
        params: dict[str, Any] = {"target": target, "depth": "deep"}
        if variant:
            params["tools"] = [variant]
        if vuln_categories:
            params["vuln_categories"] = vuln_categories
        return ("web_scan", params)

    if base_tool == "network_scan":
        params = {"target": target}
        if variant == "deep":
            params["depth"] = "deep"
        elif variant == "quick":
            params["depth"] = "quick"
        else:
            params["depth"] = "deep"
        return ("network_scan", params)

    if step_tool == "discover_hosts":
        return ("discover_hosts", {"network": target})

    if base_tool == "credential_test":
        params = {"target": target}
        if variant == "hydra":
            params["tool"] = "hydra"
        if app_hint:
            params["app_hint"] = app_hint
        return ("credential_test", params)

    if step_tool == "fingerprint_target":
        return ("fingerprint_target", {"target": target})

    if step_tool == "web_search":
        query = context.get("search_query", f"vulnerabilities {target}")
        return ("web_search", {"query": query})

    if step_tool == "research_vulnerabilities":
        techs = context.get("techs", [])
        return ("research_vulnerabilities", {"target": target, "technologies": techs})

    if step_tool == "run_custom_script":
        script = context.get("script", "")
        return ("run_custom_script", {"script": script, "target": target})

    if step_tool == "suggest_tools":
        return ("suggest_tools", {"target": target})

    # Fallback: pass target as the main param
    return (base_tool or step_tool, {"target": target})


def needs_revision(tier_results: list[dict[str, Any]]) -> bool:
    """Check if the current tier's results warrant a plan revision.

    Returns True when >50% of steps failed or an attack feedback signal
    says stop/re-plan.
    """
    if not tier_results:
        return False

    failure_count = sum(1 for r in tier_results if r.get("failed"))
    if failure_count >= len(tier_results) / 2:
        return True

    for r in tier_results:
        policy = r.get("policy_action", "continue")
        if policy in ("stop_and_replan", "stop"):
            return True

    return False


def is_llm_dependent_step(step_tool: str) -> bool:
    """Return True for steps that need LLM-generated params."""
    return step_tool in ("run_custom_script", "suggest_tools")
