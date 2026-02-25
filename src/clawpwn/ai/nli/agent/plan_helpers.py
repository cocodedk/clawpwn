"""Intent classification and plan step mapping for the code-driven executor."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# External tool names that signal a focused (non-exhaustive) request.
_SPECIFIC_TOOL_RE = re.compile(
    r"\b(hydra|sqlmap|nikto|nuclei|nmap|wpscan|testssl|feroxbuster|"
    r"gobuster|dirb|masscan|whatweb|wafw00f|sslscan|zap|burp|"
    r"metasploit|msfconsole)\b",
    re.IGNORECASE,
)


def classify_intent(
    llm: Any,
    user_message: str,
    has_pending_plan: bool,
) -> str:
    """Classify user intent as plan_execute or conversational."""
    if has_pending_plan:
        return "plan_execute"

    # Use the cheap routing model (Haiku) for classification
    prompt = (
        "Classify this user message into exactly ONE category.\n"
        "Respond with ONLY the category name, nothing else.\n\n"
        "Categories:\n"
        "- plan_execute: user wants to EXECUTE a scan, attack, or security "
        "assessment action against a target right now\n"
        "- conversational: user is asking a question, wants information, "
        "wants you to write/show/explain a command, requesting status, "
        "asking for help, setting a target, or any non-execution request. "
        "Phrases like 'write the command', 'show me', 'what command', "
        "'how do I', 'explain' are conversational even if they mention "
        "tools or testing\n\n"
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
    target_ports = context.get("target_ports", "")

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
        svc_kw = [s["product"] for s in context.get("services", []) if s.get("product")]
        if svc_kw:
            params["service_keywords"] = svc_kw
        return ("web_scan", params)

    if base_tool == "network_scan":
        params = {"target": target}
        if variant == "deep":
            params["depth"] = "deep"
        elif variant == "quick":
            params["depth"] = "quick"
        else:
            params["depth"] = "deep"
        if target_ports:
            params["ports"] = target_ports
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
        services = context.get("services", [])
        if services:
            svc = services[0]
            return (
                "research_vulnerabilities",
                {
                    "service": svc["product"],
                    "version": "",
                    "target": target,
                },
            )
        return ("research_vulnerabilities", {"service": target, "version": ""})

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


def is_focused_request(user_message: str) -> bool:
    """Return True if the user asked for a specific tool or narrow action."""
    return bool(_SPECIFIC_TOOL_RE.search(user_message))


def build_plan_prompt(
    system_prompt: str,
    user_message: str,
    project_dir: Path,
) -> str:
    """Return focused prompt for specific-tool requests, else full prompt."""
    if not is_focused_request(user_message):
        return system_prompt

    from clawpwn.ai.nli.tool_executors import format_availability_report
    from clawpwn.ai.nli.tools.tool_metadata import format_speed_table

    from .context import get_project_context
    from .prompt import FOCUSED_PLAN_PROMPT

    base = FOCUSED_PLAN_PROMPT.format(
        tool_status=format_availability_report(),
        speed_table=format_speed_table(),
    )
    ctx = get_project_context(project_dir)
    return f"{base}\n\nCurrent project state:\n{ctx}" if ctx else base
