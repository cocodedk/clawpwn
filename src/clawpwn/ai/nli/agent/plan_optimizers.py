"""Post-processing optimizations for plan execution.

Prune wasteful plan steps and detect when further scanning is pointless.
"""

from __future__ import annotations

from typing import Any

_EMPTY_RESULT_INDICATORS = (
    "0 open ports",
    "no open ports",
    "0 findings",
    "research failed",
    "no results",
    "no vulnerabilities",
    "0 hosts",
)


def is_empty_research(step: dict[str, Any], context: dict[str, Any]) -> bool:
    """Return True when a research_vulnerabilities step has no useful service info.

    If no scans have discovered services yet (empty context), the research call
    would just query a bare IP and return nothing useful.
    """
    tool = step.get("tool", "")
    if not tool.startswith("research_vulnerabilities"):
        return False
    # If context already has discovered tech/categories, research is useful
    if context.get("techs") or context.get("vuln_categories"):
        return False
    if context.get("app_hint"):
        return False
    return True


def prune_empty_research(
    steps: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Remove research_vulnerabilities steps that have no useful service context."""
    return [s for s in steps if not is_empty_research(s, context)]


def tier_found_nothing(tier_results: list[dict[str, Any]]) -> bool:
    """Return True when no step failed but all results indicate empty output."""
    if not tier_results:
        return False
    for r in tier_results:
        if r.get("failed"):
            return False
        text = (r.get("result_text") or r.get("result_summary") or "").lower()
        if not any(indicator in text for indicator in _EMPTY_RESULT_INDICATORS):
            return False
    return True


def should_skip_remaining(
    completed_tools: set[str],
    remaining_tiers: dict[int, list[dict[str, Any]]],
) -> bool:
    """Return True if all remaining steps use tool types already executed."""
    for tier_steps in remaining_tiers.values():
        for step in tier_steps:
            tool = step.get("tool", "")
            # Normalise tool:config → base tool name
            base_tool = tool.split(":")[0] if ":" in tool else tool
            if base_tool not in completed_tools:
                return False
    return True


def all_results_empty(results: list[dict[str, Any]]) -> bool:
    """Return True when every result indicates nothing was found."""
    if not results:
        return True
    for r in results:
        text = (r.get("result_summary") or r.get("result_text") or "").lower()
        if not any(indicator in text for indicator in _EMPTY_RESULT_INDICATORS):
            return False
    return True
