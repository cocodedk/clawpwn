"""Execute tool calls requested by the Claude agent.

Each public ``execute_*`` function takes the tool-call ``input`` dict and a
``project_dir`` and returns a plain-text result string that gets sent back to
Claude as a ``tool_result``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .attack_executors import execute_credential_test, execute_run_custom_script
from .availability import (
    EXTERNAL_TOOLS,
    check_tool_availability,
    enrich_missing_tool_error,
    execute_check_available_tools,
    execute_suggest_tools,
    format_availability_report,
)
from .command_executor import execute_run_command
from .plan_executors import execute_save_plan, execute_update_plan_step
from .recon_executors import execute_fetch_url, execute_fingerprint_target, execute_web_search
from .scan_executors import (
    execute_discover_hosts,
    execute_network_scan,
    execute_web_scan,
)
from .support_executors import (
    execute_check_status,
    execute_list_recent_artifacts,
    execute_research_vulnerabilities,
    execute_set_target,
    execute_show_help,
)

__all__ = [
    "EXTERNAL_TOOLS",
    "check_tool_availability",
    "dispatch_tool",
    "enrich_missing_tool_error",
    "execute_check_available_tools",
    "execute_check_status",
    "execute_credential_test",
    "execute_fetch_url",
    "execute_discover_hosts",
    "execute_fingerprint_target",
    "execute_list_recent_artifacts",
    "execute_network_scan",
    "execute_research_vulnerabilities",
    "execute_run_command",
    "execute_run_custom_script",
    "execute_save_plan",
    "execute_set_target",
    "execute_show_help",
    "execute_suggest_tools",
    "execute_update_plan_step",
    "execute_web_scan",
    "execute_web_search",
    "format_availability_report",
]

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

TOOL_EXECUTORS: dict[str, Any] = {
    "web_scan": execute_web_scan,
    "network_scan": execute_network_scan,
    "discover_hosts": execute_discover_hosts,
    "check_status": execute_check_status,
    "set_target": execute_set_target,
    "research_vulnerabilities": execute_research_vulnerabilities,
    "show_help": execute_show_help,
    "list_recent_artifacts": execute_list_recent_artifacts,
    "check_available_tools": execute_check_available_tools,
    "suggest_tools": execute_suggest_tools,
    "web_search": execute_web_search,
    "fingerprint_target": execute_fingerprint_target,
    "fetch_url": execute_fetch_url,
    "credential_test": execute_credential_test,
    "run_custom_script": execute_run_custom_script,
    "run_command": execute_run_command,
    "save_plan": execute_save_plan,
    "update_plan_step": execute_update_plan_step,
}


# Tools that require real user confirmation before execution.
_APPROVAL_REQUIRED_TOOLS = {"run_command", "run_custom_script"}


def _prompt_user_approval(name: str, params: dict[str, Any]) -> bool:
    """Prompt the user for real approval of a dangerous tool call.

    Returns True only if the user explicitly approves.
    """
    if name == "run_command":
        label = "shell command"
        detail = params.get("command", "(empty)")
    else:
        label = "custom script"
        detail = params.get("script", "(empty)")

    desc = params.get("description", "")
    print(f"\n[!] AI wants to run a {label}:")
    if desc:
        print(f"    Description: {desc}")
    # Show first 500 chars to avoid flooding the terminal
    preview = detail if len(detail) <= 500 else detail[:500] + "\n    ... (truncated)"
    print(f"    {preview}")

    try:
        response = input("\nApprove? (yes/no): ").lower().strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Not approved.")
        return False
    return response in ("yes", "y")


def dispatch_tool(name: str, params: dict[str, Any], project_dir: Path) -> str:
    """Run the named tool and return a result string.

    Unknown tool names and execution errors are returned as error text
    (not raised) so Claude can react gracefully.

    Note: stdout is NOT redirected during execution.  An earlier
    ``_run_quiet()`` wrapper used ``contextlib.redirect_stdout`` to suppress
    noisy ``print()`` calls, but it corrupted ``sys.stdout`` when the plan
    executor ran multiple tools concurrently via ``ThreadPoolExecutor``.
    """
    import time

    from clawpwn.utils.debug import debug_tool_execution, is_debug_enabled

    # Gate dangerous tools behind real user confirmation.
    # The LLM's user_approved flag is ignored — only interactive consent counts.
    if name in _APPROVAL_REQUIRED_TOOLS:
        if _prompt_user_approval(name, params):
            params = {**params, "user_approved": True}
        else:
            return f"User declined to run this {name.replace('_', ' ')}."

    # Log tool start if debug enabled
    if is_debug_enabled():
        debug_tool_execution(tool_name=name, params=params, start=True)

    start_time = time.time()
    executor = TOOL_EXECUTORS.get(name)
    if executor is None:
        result = f"Unknown tool: {name}"
    else:
        try:
            result = executor(params, project_dir)
        except Exception as exc:
            result = enrich_missing_tool_error(f"Tool '{name}' failed: {exc}")

    # Log tool completion if debug enabled
    if is_debug_enabled():
        elapsed = time.time() - start_time
        debug_tool_execution(
            tool_name=name,
            params=params,
            start=False,
            elapsed=elapsed,
            result_size=len(result) if result else 0,
        )

    return result
