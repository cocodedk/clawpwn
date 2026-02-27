"""Executor for the generate_writeup tool."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def execute_generate_writeup(params: dict[str, Any], project_dir: Path) -> str:
    """Generate a writeup from the most recent plan results."""
    from clawpwn.ai.llm import LLMClient
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    db_path = get_project_db_path(project_dir)
    if not db_path:
        return "Error: no project database found."

    session = SessionManager(db_path)
    project = session.get_project()
    if not project:
        return "Error: no active project."

    target = project.target or "unknown"
    steps = session.get_plan()
    all_results: list[dict[str, Any]] = []
    for s in steps:
        all_results.append(
            {
                "tool": s.tool or "unknown",
                "description": s.description,
                "result": s.result_summary or "",
            }
        )

    if not all_results:
        return "No plan steps found — nothing to write up."

    from clawpwn.ai.nli.agent.writeup_io import save_writeup
    from clawpwn.ai.nli.agent.writeup_llm import generate_writeup

    llm = LLMClient(project_dir=project_dir)
    content = generate_writeup(llm, target, all_results, project_dir)
    path = save_writeup(session, content, target, project_dir)
    return f"Writeup saved to {path}"
