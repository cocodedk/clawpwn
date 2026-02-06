"""Executors for support tools (status, target, research, help)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


def execute_check_status(_params: dict[str, Any], project_dir: Path) -> str:
    """Return current project status."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    db_path = get_project_db_path(project_dir)
    if not db_path:
        return "Project storage not found. Run 'clawpwn init' first."
    session = SessionManager(db_path)
    state = session.get_state()
    if not state:
        return "No project state found."
    return (
        f"Target: {state.target or 'Not set'}\n"
        f"Phase: {state.current_phase}\n"
        f"Findings: {state.findings_count} "
        f"({state.critical_count} critical, {state.high_count} high)"
    )


def execute_set_target(params: dict[str, Any], project_dir: Path) -> str:
    """Set the active project target."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    target = params["target"]
    db_path = get_project_db_path(project_dir)
    if not db_path:
        return "Project storage not found. Run 'clawpwn init' first."
    session = SessionManager(db_path)
    session.set_target(target)
    return f"Target set to: {target}"


def execute_research_vulnerabilities(params: dict[str, Any], _project_dir: Path) -> str:
    """Research known CVEs / exploits for a service."""
    from clawpwn.modules.vulndb import VulnDB

    service = params["service"]
    version = params.get("version", "")
    try:
        vulndb = VulnDB()
        results = safe_async_run(vulndb.research_service(service, version))
        cves = results.get("cves", [])
        exploits = results.get("exploits", [])
        return (
            f"Research for {service} {version}:\n  CVEs: {len(cves)}\n  Exploits: {len(exploits)}"
        )
    except Exception as exc:
        return f"Research failed: {exc}"


def execute_show_help(params: dict[str, Any], _project_dir: Path) -> str:
    """Return help text for a topic (thin wrapper)."""
    from clawpwn.ai.nli.help_topics import HELP_TOPICS

    topic = params.get("topic", "").lower().strip()
    if topic in HELP_TOPICS:
        return HELP_TOPICS[topic]
    topics = ", ".join(sorted(HELP_TOPICS.keys()))
    return f"Unknown topic '{topic}'. Available: {topics}"
