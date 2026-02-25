"""Natural language interface package."""

from pathlib import Path
from typing import Any

from clawpwn.ai.nli.interface import NaturalLanguageInterface


def process_nl_command(command: str, project_dir: Path) -> dict[str, Any]:
    """Process a natural language command."""
    nli = NaturalLanguageInterface(project_dir)
    try:
        return nli.process_command(command)
    finally:
        nli.close()


__all__ = ["NaturalLanguageInterface", "process_nl_command"]
