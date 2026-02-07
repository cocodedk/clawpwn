"""Executors for scanning tools (web, network, discovery)."""

from .discovery import execute_discover_hosts
from .network import execute_network_scan
from .web import execute_web_scan

__all__ = [
    "execute_web_scan",
    "execute_network_scan",
    "execute_discover_hosts",
]
