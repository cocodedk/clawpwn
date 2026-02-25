"""Executors for support tools (status, target, research, help)."""

from __future__ import annotations

from datetime import datetime
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
    status_text = (
        f"Target: {state.target or 'Not set'}\n"
        f"Phase: {state.current_phase}\n"
        f"Findings: {state.findings_count} "
        f"({state.critical_count} critical, {state.high_count} high)"
    )
    latest_script = _latest_custom_script(project_dir)
    if latest_script is not None:
        status_text += f"\nLatest script artifact: {latest_script}"
    return status_text


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


def execute_list_recent_artifacts(params: dict[str, Any], project_dir: Path) -> str:
    """List recent script/evidence/report artifacts from the project workspace."""
    kind = str(params.get("kind", "all")).strip().lower() or "all"
    raw_limit = params.get("limit", 5)
    try:
        limit = max(1, int(raw_limit))
    except (TypeError, ValueError):
        limit = 5

    directories = {
        "scripts": project_dir / "exploits",
        "evidence": project_dir / "evidence",
        "reports": project_dir / "report",
    }
    selected: list[tuple[str, Path]] = []
    if kind == "all":
        selected = list(directories.items())
    elif kind in directories:
        selected = [(kind, directories[kind])]
    else:
        return "Unknown artifact kind. Use one of: all, scripts, evidence, reports."

    artifacts: list[tuple[float, str, Path]] = []
    for category, path in selected:
        if not path.exists():
            continue
        for file_path in path.iterdir():
            if not file_path.is_file():
                continue
            try:
                mtime = file_path.stat().st_mtime
            except OSError:
                continue
            artifacts.append((mtime, category, file_path))

    if not artifacts:
        kinds = ", ".join(cat for cat, _ in selected)
        return f"No artifacts found in: {kinds}."

    artifacts.sort(key=lambda item: item[0], reverse=True)
    lines = [f"Recent artifacts ({min(limit, len(artifacts))}):"]
    for mtime, category, file_path in artifacts[:limit]:
        ts = datetime.fromtimestamp(mtime).isoformat(timespec="seconds")
        lines.append(f"- [{category}] {file_path} (updated {ts})")
    return "\n".join(lines)


def _latest_custom_script(project_dir: Path) -> Path | None:
    exploits_dir = project_dir / "exploits"
    if not exploits_dir.exists():
        return None

    scripts = sorted(
        (path for path in exploits_dir.glob("custom_script_*.py") if path.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return scripts[0] if scripts else None
