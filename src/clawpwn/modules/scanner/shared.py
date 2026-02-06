"""Shared scanner utilities."""

from pathlib import Path

from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


def load_session(project_dir: Path | None) -> SessionManager | None:
    """Create a session manager when a valid project db exists."""
    if not project_dir:
        return None

    db_path = get_project_db_path(project_dir)
    if db_path and db_path.exists():
        return SessionManager(db_path)
    return None
