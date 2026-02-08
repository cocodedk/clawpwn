"""Speed tiers, priority scores, and estimated durations for each tool+config.

Used by the planner to order steps fastest-first and by the agent context to
show the LLM how expensive each action is.

Speed tiers:
  1 = fast   (~seconds)   — recon, lookups, credential/wordlist tests
  2 = medium (~1-3 min)   — builtin scanner, nikto, nuclei
  3 = slow   (~5-15 min)  — sqlmap deep, wpscan, testssl, fuzzing, deep netscan

Priority scores (higher = run sooner within the same speed tier):
  Higher priority means the tool is more likely to produce actionable results
  quickly, so it should run before lower-priority tools of the same speed.
  Credential/wordlist attacks have HIGH priority because if they succeed,
  expensive scanning becomes unnecessary.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolProfile:
    """Performance and priority profile for a tool or tool+config combo."""

    speed_tier: int  # 1=fast, 2=medium, 3=slow
    priority: int  # Higher = run first within same tier (1-10)
    est_seconds: int  # Rough estimate for display
    label: str  # Human-readable speed label


# Base tool profiles (default config).
# For tools where depth/config matters, depth-specific overrides are below.
TOOL_PROFILES: dict[str, ToolProfile] = {
    # --- Tier 1: Fast (seconds) ---
    "fingerprint_target": ToolProfile(1, 10, 5, "fast"),
    "check_status": ToolProfile(1, 10, 1, "fast"),
    "web_search": ToolProfile(1, 9, 5, "fast"),
    "research_vulnerabilities": ToolProfile(1, 9, 5, "fast"),
    "set_target": ToolProfile(1, 10, 1, "fast"),
    "show_help": ToolProfile(1, 1, 1, "fast"),
    "check_available_tools": ToolProfile(1, 2, 1, "fast"),
    "list_recent_artifacts": ToolProfile(1, 1, 1, "fast"),
    "suggest_tools": ToolProfile(1, 1, 1, "fast"),
    "save_plan": ToolProfile(1, 10, 1, "fast"),
    "update_plan_step": ToolProfile(1, 10, 1, "fast"),
    # Credential/wordlist tests: high ROI — if creds work, skip expensive scans
    "credential_test": ToolProfile(1, 8, 15, "fast"),
    "credential_test:hydra": ToolProfile(1, 8, 30, "fast"),
    "web_scan:builtin": ToolProfile(2, 7, 60, "medium"),
    "web_scan:nikto": ToolProfile(2, 6, 90, "medium"),
    "web_scan:nuclei": ToolProfile(2, 7, 120, "medium"),
    "discover_hosts": ToolProfile(2, 5, 60, "medium"),
    "network_scan:quick": ToolProfile(2, 6, 30, "medium"),
    # --- Tier 3: Slow (5-15 minutes) ---
    "web_scan:sqlmap": ToolProfile(3, 7, 600, "slow"),
    "web_scan:wpscan": ToolProfile(3, 6, 300, "slow"),
    "web_scan:testssl": ToolProfile(3, 5, 300, "slow"),
    "web_scan:feroxbuster": ToolProfile(3, 4, 600, "slow"),
    "web_scan:ffuf": ToolProfile(3, 4, 600, "slow"),
    "web_scan:zap": ToolProfile(3, 3, 900, "slow"),
    "network_scan:deep": ToolProfile(3, 5, 600, "slow"),
    "run_custom_script": ToolProfile(3, 2, 60, "slow"),
}

# Fallback for unknown tools
_DEFAULT_PROFILE = ToolProfile(2, 5, 60, "medium")


def get_profile(tool_name: str, config: str | None = None) -> ToolProfile:
    """Look up the profile for a tool, optionally with a config qualifier.

    Tries ``tool_name:config`` first, then ``tool_name`` base profile.
    """
    if config:
        key = f"{tool_name}:{config}"
        if key in TOOL_PROFILES:
            return TOOL_PROFILES[key]
    return TOOL_PROFILES.get(tool_name, _DEFAULT_PROFILE)


def format_speed_table() -> str:
    """Build a compact speed reference for the system prompt."""
    lines = [
        "TOOL SPEED REFERENCE (order your plan fastest-first):",
        "  FAST (~seconds, HIGH ROI): fingerprint_target, web_search, research_vulnerabilities,",
        "    credential_test (default creds, hydra wordlist) — if creds work, skip expensive scans!",
        "  MEDIUM (~1-3 min): builtin scanner, nikto, nuclei, network_scan quick, discover_hosts",
        "  SLOW (~5-15 min): sqlmap deep, wpscan, testssl, feroxbuster, ffuf, zap, network_scan deep",
    ]
    return "\n".join(lines)
