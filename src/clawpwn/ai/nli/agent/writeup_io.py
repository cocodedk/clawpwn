"""Writeup persistence: DB + markdown file on disk."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


def save_writeup(session, content: str, target: str, project_dir: Path) -> Path:
    """Persist writeup to DB and write a markdown file to disk.

    Returns the path to the written markdown file.
    """
    safe_target = re.sub(r"[^\w.-]", "_", target)[:60]
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    title = f"Writeup — {target} ({timestamp})"

    session.save_writeup(title=title, content=content)

    writeups_dir = project_dir / "writeups"
    writeups_dir.mkdir(parents=True, exist_ok=True)
    filename = f"writeup_{safe_target}_{timestamp}.md"
    path = writeups_dir / filename
    path.write_text(content, encoding="utf-8")
    return path
