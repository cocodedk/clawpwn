"""Runtime access to public CLI facade symbols.

Command modules resolve dependencies from ``clawpwn.cli`` at call time so tests can
monkeypatch facade-level symbols (for example ``require_project`` or ``Scanner``).
"""

from importlib import import_module
from types import ModuleType


def cli_module() -> ModuleType:
    """Return the public CLI facade module."""
    return import_module("clawpwn.cli")
