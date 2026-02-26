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
    "naabu": {
        "binary": "naabu",
        "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "nuclei": {
        "binary": "nuclei",
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    "nikto": {"binary": "nikto", "install": "sudo apt install nikto"},
    "feroxbuster": {"binary": "feroxbuster", "install": "cargo install feroxbuster"},
    "ffuf": {"binary": "ffuf", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    "searchsploit": {"binary": "searchsploit", "install": "sudo apt install exploitdb"},
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
    "hydra": {"binary": "hydra", "install": "sudo apt install hydra"},
}


def check_tool_availability() -> dict[str, bool]:
    """Return {tool_name: is_installed} for every known external tool."""
    return {name: _find_binary(info["binary"]) is not None for name, info in EXTERNAL_TOOLS.items()}


def _find_binary(name: str) -> str | None:
    """Find a binary via PATH + common install locations."""
    import os

    found = shutil.which(name)
    if found:
        return found
    home = Path.home()
    go_bin = os.environ.get("GOBIN", "")
    go_path = os.environ.get("GOPATH", str(home / "go"))
    extra = [Path(go_bin)] if go_bin else []
    extra.append(Path(go_path) / "bin")
    for d in [home / ".local" / "bin", home / ".cargo" / "bin", Path("/usr/local/bin"), *extra]:
        candidate = d / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def discover_wordlists() -> list[dict[str, str]]:
    """Find available password/wordlist files on the system."""
    import os

    candidates = [
        os.environ.get("CLAWPWN_CRED_WORDLIST", ""),
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        str(Path.home() / ".local/share/clawpwn/wordlists/rockyou.txt"),
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
        "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt",
        str(Path.home() / ".local/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"),
        str(Path.home() / ".local/share/clawpwn/wordlists/seclists-10k-most-common.txt"),
        str(Path.home() / ".local/share/clawpwn/wordlists/clawpwn-default-passwords.txt"),
    ]
    # Scan password-specific directories for additional files
    password_dirs = [
        Path("/usr/share/wordlists"),
        Path("/usr/share/seclists/Passwords"),
        Path("/usr/share/seclists/Usernames"),
        Path.home() / ".local/share/clawpwn/wordlists",
        Path.home() / ".local/share/seclists/Passwords",
        Path.home() / ".local/share/seclists/Usernames",
    ]
    for d in password_dirs:
        if d.is_dir():
            for f in d.rglob("*.txt"):
                candidates.append(str(f))

    seen: set[str] = set()
    found: list[dict[str, str]] = []
    for path_str in candidates:
        if not path_str:
            continue
        p = Path(path_str)
        resolved = str(p.resolve()) if p.exists() else ""
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        try:
            size_mb = p.stat().st_size / (1024 * 1024)
            found.append({"path": str(p), "size": f"{size_mb:.1f}MB"})
        except OSError:
            continue
    return found


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

    wordlists = discover_wordlists()
    if wordlists:
        wl_summary = "; ".join(f"{w['path']} ({w['size']})" for w in wordlists[:8])
        parts.append(f"Wordlists: {wl_summary}.")
    else:
        parts.append("Wordlists: none found. Run install.sh to set up password lists.")

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
