"""Active scanner implementation."""

from pathlib import Path

from clawpwn.tools.http import HTTPClient, HTTPResponse

from .active_checks_misc import test_command_injection, test_idor, test_path_traversal
from .active_checks_sql_xss import test_sql_injection, test_xss
from .models import ScanResult
from .shared import load_session


class ActiveScanner:
    """Active scanner that sends test payloads to detect vulnerabilities."""

    def __init__(self, project_dir: Path | None = None):
        self.project_dir = project_dir
        self.session = load_session(project_dir)

    async def scan_target(self, target: str, depth: str = "normal") -> list[ScanResult]:
        """Actively scan a target for vulnerabilities."""
        findings: list[ScanResult] = []

        async with HTTPClient() as client:
            base_response = await client.get(target)
            findings.extend(await self._test_sql_injection(client, target, depth))
            findings.extend(await self._test_xss(client, target, depth))
            findings.extend(await self._test_path_traversal(client, target))
            findings.extend(await self._test_command_injection(client, target))
            findings.extend(await self._test_idor(client, target, base_response))

        return findings

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
