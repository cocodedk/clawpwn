"""Passive scanner implementation."""

from pathlib import Path

from clawpwn.tools.http import HTTPResponse

from .models import ScanResult
from .passive_checks import (
    check_error_patterns,
    check_information_disclosure,
    check_security_headers,
)
from .shared import load_session


class PassiveScanner:
    """Passive scanner that analyzes responses without sending test payloads."""

    def __init__(self, project_dir: Path | None = None):
        self.project_dir = project_dir
        self.session = load_session(project_dir)

    async def scan_response(self, response: HTTPResponse) -> list[ScanResult]:
        """Passively scan an HTTP response for issues."""
        findings: list[ScanResult] = []
        findings.extend(self._check_security_headers(response))
        findings.extend(self._check_information_disclosure(response))
        findings.extend(self._check_error_patterns(response))
        return findings

    def _check_security_headers(self, response: HTTPResponse) -> list[ScanResult]:
        return check_security_headers(response)

    def _check_information_disclosure(self, response: HTTPResponse) -> list[ScanResult]:
        return check_information_disclosure(response)

    def _check_error_patterns(self, response: HTTPResponse) -> list[ScanResult]:
        return check_error_patterns(response)
