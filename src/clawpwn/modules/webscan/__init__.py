"""Modular web scanner orchestration and plugin interfaces."""

from .base import WebScannerPlugin
from .factory import create_default_webscan_plugins
from .models import WebScanConfig, WebScanError, WebScanFinding
from .orchestrator import WebScanOrchestrator
from .plugins import BuiltinWebScannerPlugin

__all__ = [
    "BuiltinWebScannerPlugin",
    "WebScanConfig",
    "WebScanError",
    "create_default_webscan_plugins",
    "WebScanFinding",
    "WebScanOrchestrator",
    "WebScannerPlugin",
]
