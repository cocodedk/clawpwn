"""Active scanner implementation."""

from pathlib import Path

from clawpwn.tools.http import HTTPClient, HTTPResponse

from .active_checks_misc import test_command_injection, test_idor, test_path_traversal
from .active_checks_sql_xss import test_sql_injection, test_xss
from .models import ScanResult
from .shared import load_session

# Maps scan_types category keys to the check methods they enable.
_CATEGORY_CHECK_MAP: dict[str, tuple[str, ...]] = {
    "sqli": ("sql_injection",),
    "xss": ("xss",),
    "path_traversal": ("path_traversal",),
    "command_injection": ("command_injection",),
    "idor": ("idor",),
}


class ActiveScanner:
    """Active scanner that sends test payloads to detect vulnerabilities."""

    def __init__(self, project_dir: Path | None = None):
        self.project_dir = project_dir
        self.session = load_session(project_dir)

    async def scan_target(
        self,
        target: str,
        depth: str = "normal",
        scan_types: list[str] | None = None,
    ) -> list[ScanResult]:
        """Actively scan a target for vulnerabilities.

        When *scan_types* contains specific categories (e.g. ``["sqli"]``),
        only the matching checks are executed. ``["all"]`` (the default)
        runs every check.
        """
        enabled = self._enabled_checks(scan_types)
        findings: list[ScanResult] = []

        async with HTTPClient() as client:
            base_response = await client.get(target)
            if "sql_injection" in enabled:
                findings.extend(await self._test_sql_injection(client, target, depth))
            if "xss" in enabled:
                findings.extend(await self._test_xss(client, target, depth))
            if "path_traversal" in enabled:
                findings.extend(await self._test_path_traversal(client, target))
            if "command_injection" in enabled:
                findings.extend(await self._test_command_injection(client, target))
            if "idor" in enabled:
                findings.extend(await self._test_idor(client, target, base_response))

        return findings

    @staticmethod
    def _enabled_checks(scan_types: list[str] | None) -> set[str]:
        """Resolve scan_types into the set of individual check names to run."""
        if not scan_types or "all" in scan_types:
            return {"sql_injection", "xss", "path_traversal", "command_injection", "idor"}
        checks: set[str] = set()
        for cat in scan_types:
            checks.update(_CATEGORY_CHECK_MAP.get(cat, ()))
        return checks or {"sql_injection", "xss", "path_traversal", "command_injection", "idor"}

    async def _test_sql_injection(
        self,
        client: HTTPClient,
        target: str,
        depth: str,
    ) -> list[ScanResult]:
        return await test_sql_injection(client, target, depth)

    async def _test_xss(self, client: HTTPClient, target: str, depth: str) -> list[ScanResult]:
        return await test_xss(client, target, depth)

    async def _test_path_traversal(self, client: HTTPClient, target: str) -> list[ScanResult]:
        return await test_path_traversal(client, target)

    async def _test_command_injection(self, client: HTTPClient, target: str) -> list[ScanResult]:
        return await test_command_injection(client, target)

    async def _test_idor(
        self,
        client: HTTPClient,
        target: str,
        base_response: HTTPResponse,
    ) -> list[ScanResult]:
        return await test_idor(client, target, base_response)
