"""Base contract for modular web scanner plugins."""

from abc import ABC, abstractmethod

from .models import WebScanConfig, WebScanFinding


class WebScannerPlugin(ABC):
    """Plugin interface for web vulnerability scanners."""

    name: str

    @abstractmethod
    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        """Run the plugin against one target URL."""
