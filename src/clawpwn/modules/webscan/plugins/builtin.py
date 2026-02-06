"""Builtin web scanner plugin adapter."""

from collections.abc import Callable
from pathlib import Path

from clawpwn.modules.scanner import ScanConfig, Scanner

from ..base import WebScannerPlugin
from ..models import WebScanConfig, WebScanFinding


class BuiltinWebScannerPlugin(WebScannerPlugin):
    """Adapter around the existing ClawPwn web scanner."""

    name = "builtin"

    def __init__(
        self,
        project_dir: Path | None = None,
        scanner_factory: Callable[[Path | None], object] | None = None,
    ):
        self.project_dir = project_dir
        self._scanner_factory = scanner_factory or Scanner

    async def scan(self, target: str, config: WebScanConfig) -> list[WebScanFinding]:
        scanner = self._scanner_factory(self.project_dir)
        scan_config = ScanConfig(
            target=target,
            scan_types=config.scan_types,
            depth=config.depth,
            timeout=config.timeout,
            follow_redirects=config.follow_redirects,
        )
        findings = await scanner.scan(target, scan_config)
        return [WebScanFinding.from_scan_result(finding, tool=self.name) for finding in findings]
