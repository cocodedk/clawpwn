"""Individual health-check functions for ``clawpwn doctor``.

System-level checks live here; environment/project checks are in
``doctor_env_checks.py``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of a single diagnostic check."""

    name: str
    status: str  # "pass", "fail", "warn"
    message: str
    fix: str = ""


# ---------------------------------------------------------------------------
# Tool importance tiers (doctor-specific, not modifying EXTERNAL_TOOLS)
# ---------------------------------------------------------------------------

CORE_TOOLS: set[str] = {"nmap"}
RECOMMENDED_TOOLS: set[str] = {"naabu", "nuclei", "nikto", "sqlmap", "hydra"}
OPTIONAL_TOOLS: set[str] = {
    "rustscan",
    "masscan",
    "feroxbuster",
    "ffuf",
    "searchsploit",
    "zap",
    "wpscan",
    "testssl",
    "aws",
}

RAW_SCAN_TOOLS = ("nmap", "naabu", "masscan")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_python_version() -> CheckResult:
    """Verify Python >= 3.12."""
    v = sys.version_info
    ver = f"{v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) >= (3, 12):
        return CheckResult("Python version", "pass", f"Python {ver}")
    return CheckResult(
        "Python version", "fail", f"Python {ver} (requires >= 3.12)", fix="Install Python 3.12+"
    )


def check_external_tools() -> list[CheckResult]:
    """Check external tool availability, grouped by importance tier."""
    from clawpwn.ai.nli.tool_executors.availability import EXTERNAL_TOOLS, check_tool_availability

    status = check_tool_availability()
    results: list[CheckResult] = []

    for tier_name, tier_set, fail_level in [
        ("Core tools", CORE_TOOLS, "fail"),
        ("Recommended tools", RECOMMENDED_TOOLS, "warn"),
        ("Optional tools", OPTIONAL_TOOLS, "warn"),
    ]:
        known = [t for t in tier_set if t in EXTERNAL_TOOLS]
        installed = [t for t in known if status.get(t)]
        missing = [t for t in known if not status.get(t)]

        if not missing:
            label = ", ".join(sorted(installed))
            if len(installed) > 4:
                shown = sorted(installed)[:3]
                label = ", ".join(shown) + f" (+{len(installed) - 3} more)"
            results.append(CheckResult(tier_name, "pass", f"{tier_name}: {label}"))
        else:
            installs = [f"  Install: {EXTERNAL_TOOLS[t]['install']}" for t in sorted(missing)]
            fix = "\n".join(installs)
            results.append(
                CheckResult(
                    tier_name,
                    fail_level,
                    f"{tier_name} missing: {', '.join(sorted(missing))}",
                    fix=fix,
                )
            )
    return results


def check_privileges() -> CheckResult:
    """Check raw-scan capabilities for nmap/naabu/masscan."""
    from clawpwn.ai.nli.tool_executors.availability import check_tool_availability
    from clawpwn.utils.privileges import can_raw_scan, is_root

    if is_root():
        return CheckResult("Privileges", "pass", "Running as root")

    status = check_tool_availability()
    lacking: list[str] = []
    for tool in RAW_SCAN_TOOLS:
        if status.get(tool) and not can_raw_scan(tool):
            lacking.append(tool)

    if not lacking:
        return CheckResult("Privileges", "pass", "Raw scan privileges OK")

    tools_str = ", ".join(lacking)
    fix_parts = [f"sudo setcap cap_net_raw+ep $(which {t})" for t in lacking]
    return CheckResult(
        "Privileges",
        "warn",
        f"{tools_str} lack cap_net_raw",
        fix="\n".join(fix_parts),
    )


def check_wordlists() -> CheckResult:
    """Check for available wordlists."""
    from clawpwn.ai.nli.tool_executors.availability import discover_wordlists

    found = discover_wordlists()
    if found:
        names = [Path(w["path"]).name for w in found[:3]]
        label = ", ".join(names)
        if len(found) > 3:
            label += ", ..."
        return CheckResult("Wordlists", "pass", f"Wordlists: {len(found)} found ({label})")
    return CheckResult(
        "Wordlists",
        "warn",
        "No wordlists found",
        fix="Install SecLists or place wordlists in /usr/share/wordlists/",
    )


def mask_key(key: str) -> str:
    """Mask an API key for display."""
    if len(key) > 12:
        return key[:10] + "..." + key[-4:]
    return "***"
