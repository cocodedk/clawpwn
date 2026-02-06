"""Runtime dependency access for NetworkDiscovery mixins."""

from importlib import import_module
from types import ModuleType


def network_module() -> ModuleType:
    """Return public network module for monkeypatch-friendly dependency lookup."""
    return import_module("clawpwn.modules.network")
