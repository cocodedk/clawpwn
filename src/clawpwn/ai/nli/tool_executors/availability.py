"""External tool registry and availability checking."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# External tool registry (binary name + install instructions)
# ---------------------------------------------------------------------------

EXTERNAL_TOOLS: dict[str, dict[str, str]] = {
    "nmap": {"binary": "nmap", "install": "sudo apt install nmap"},
    "rustscan": {"binary": "rustscan", "install": "cargo install rustscan"},
    "masscan": {"binary": "masscan", "install": "sudo apt install masscan"},
    "nuclei": {
        "binary": "nuclei",
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "nikto": {"binary": "nikto", "install": "sudo apt install nikto"},
    "feroxbuster": {"binary": "feroxbuster", "install": "cargo install feroxbuster"},
    "ffuf": {"binary": "ffuf", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    "zap": {
        "binary": "zaproxy",
        "install": "sudo apt install zaproxy  # or Docker: docker pull zaproxy/zap-stable",
    },
    "sqlmap": {"binary": "sqlmap", "install": "sudo apt install sqlmap"},
    "wpscan": {"binary": "wpscan", "install": "sudo gem install wpscan"},
    "testssl": {
        "binary": "testssl.sh",
        "install": "sudo apt install testssl.sh  # or: git clone https://github.com/drwetter/testssl.sh",
    },
}


def check_tool_availability() -> dict[str, bool]:
    """Return {tool_name: is_installed} for every known external tool."""
    return {name: shutil.which(info["binary"]) is not None for name, info in EXTERNAL_TOOLS.items()}


def format_availability_report() -> str:
    """Human-readable availability report for injection into system prompt."""
    status = check_tool_availability()
    installed = [n for n, ok in status.items() if ok]
    missing = [n for n, ok in status.items() if not ok]
    parts: list[str] = []
    if installed:
        parts.append(f"Installed: {', '.join(installed)}.")
    if missing:
        details = "; ".join(f"{n} ({EXTERNAL_TOOLS[n]['install']})" for n in missing)
        parts.append(f"Not installed: {details}.")
    return " ".join(parts) or "No external tools registered."


def enrich_missing_tool_error(message: str) -> str:
    """If *message* mentions a missing binary, append install instructions."""
    msg_lower = message.lower()
    for _name, info in EXTERNAL_TOOLS.items():
        if info["binary"] in msg_lower and "not found" in msg_lower:
            return f"{message}  Install with: {info['install']}"
    return message


def execute_check_available_tools(_params: dict[str, Any], _project_dir: Path) -> str:
    """Return installed / missing status with install commands."""
    return format_availability_report()


def execute_suggest_tools(params: dict[str, Any], _project_dir: Path) -> str:
    """Format tool suggestions from Claude for display."""
    suggestions = params.get("suggestions", [])
    if not suggestions:
        return "No tool suggestions."
    lines: list[str] = ["Recommended tools:"]
    for s in suggestions:
        lines.append(f"\n• {s.get('name', '?')} — {s.get('reason', '')}")
        lines.append(f"  Install: {s.get('install_command', 'N/A')}")
        lines.append(f"  Usage:   {s.get('example_usage', 'N/A')}")
    return "\n".join(lines)
