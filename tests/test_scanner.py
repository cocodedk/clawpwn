"""Tests for the scanner module."""

import pytest
import respx
from httpx import Response
from pathlib import Path

from clawpwn.modules.scanner import (
    PassiveScanner,
    ActiveScanner,
    Scanner,
    ScanConfig,
    ScanResult,
)
from clawpwn.tools.http import HTTPResponse


class TestPassiveScanner:
    """Test passive scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_response_basic(self, project_dir: Path):
        """Test basic response scanning."""
        scanner = PassiveScanner(project_dir)

        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html>Test</html>",
            cookies={},
            response_time=0.5,
        )

        findings = await scanner.scan_response(response)

        # Should return a list (even if empty)
        assert isinstance(findings, list)

    def test_detect_missing_security_headers(self, project_dir: Path):
        """Test detection of missing security headers."""
        scanner = PassiveScanner(project_dir)

        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                # Missing important security headers
            },
            body="<html>Test</html>",
            cookies={},
            response_time=0.5,
        )

        findings = scanner._check_security_headers(response)

        # Should detect missing headers
        assert len(findings) > 0
        assert any("Missing Security Headers" in f.title for f in findings)

    def test_detect_server_version_disclosure(self, project_dir: Path):
        """Test detection of server version disclosure."""
        scanner = PassiveScanner(project_dir)

        response = HTTPResponse(
            url="https://example.com",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Server": "nginx/1.18.0",
            },
            body="<html>Test</html>",
            cookies={},
            response_time=0.5,
        )

        findings = scanner._check_information_disclosure(response)

        # Should detect version disclosure
        assert any("Server Version" in f.title for f in findings)

    def test_detect_sql_error(self, project_dir: Path):
        """Test detection of SQL error messages."""
        scanner = PassiveScanner(project_dir)

        response = HTTPResponse(
            url="https://example.com/login?id=1",
            status_code=500,
            headers={"Content-Type": "text/html"},
            body="You have an error in your SQL syntax near '1=1'",
            cookies={},
            response_time=0.5,
        )

        findings = scanner._check_error_patterns(response)

        # Should detect SQL error
        assert any("SQL" in f.title for f in findings)

    def test_detect_api_key_exposure(self, project_dir: Path):
        """Test detection of API key exposure."""
        scanner = PassiveScanner(project_dir)

        response = HTTPResponse(
            url="https://example.com/api/config",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"api_key": "sk_test_redacted"}',
            cookies={},
            response_time=0.5,
        )

        findings = scanner._check_information_disclosure(response)

        # Should detect API key
        assert any("API Key" in f.title for f in findings)


class TestActiveScanner:
    """Test active scanning functionality."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_test_sql_injection(self, project_dir: Path):
        """Test SQL injection detection."""
        scanner = ActiveScanner(project_dir)

        # Mock vulnerable endpoint
        route = respx.get("https://example.com/search").mock(
            return_value=Response(200, text="You have an error in your SQL syntax")
        )

        # Create HTTP client to use
        from clawpwn.tools.http import HTTPClient

        async with HTTPClient() as client:
            findings = await scanner._test_sql_injection(
                client, "https://example.com/search?q=test", "normal"
            )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    @respx.mock
    async def test_test_xss(self, project_dir: Path):
        """Test XSS detection."""
        scanner = ActiveScanner(project_dir)

        # Mock endpoint that reflects input
        route = respx.get("https://example.com/search").mock(
            return_value=Response(200, text='<script>alert("XSS")</script>')
        )

        from clawpwn.tools.http import HTTPClient

        async with HTTPClient() as client:
            findings = await scanner._test_xss(
                client, "https://example.com/search?q=test", "normal"
            )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    @respx.mock
    async def test_test_path_traversal(self, project_dir: Path):
        """Test path traversal detection."""
        scanner = ActiveScanner(project_dir)

        # Mock endpoint vulnerable to path traversal
        route = respx.get("https://example.com/file").mock(
            return_value=Response(200, text="root:x:0:0:root:/root:/bin/bash")
        )

        from clawpwn.tools.http import HTTPClient

        async with HTTPClient() as client:
            findings = await scanner._test_path_traversal(
                client, "https://example.com/file"
            )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    @respx.mock
    async def test_test_command_injection(self, project_dir: Path):
        """Test command injection detection."""
        scanner = ActiveScanner(project_dir)

        # Mock endpoint vulnerable to command injection
        route = respx.get("https://example.com/ping").mock(
            return_value=Response(
                200, text="uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            )
        )

        from clawpwn.tools.http import HTTPClient

        async with HTTPClient() as client:
            findings = await scanner._test_command_injection(
                client, "https://example.com/ping"
            )

        assert isinstance(findings, list)


class TestScannerIntegration:
    """Test the main Scanner class."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_target(self, project_dir: Path):
        """Test scanning a target."""
        scanner = Scanner(project_dir)

        # Mock the target
        route = respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="<html><body>Test</body></html>",
                headers={"Server": "nginx/1.18.0"},
            )
        )

        config = ScanConfig(target="https://example.com", depth="quick")

        findings = await scanner.scan("https://example.com", config)

        # Should return a list of findings
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_finds_security_headers_issue(self, project_dir: Path):
        """Test that scan detects missing security headers."""
        scanner = Scanner(project_dir)

        # Mock response with missing headers
        route = respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="<html><body>Test</body></html>",
                headers={"Server": "nginx/1.18.0"},  # Missing security headers
            )
        )

        config = ScanConfig(target="https://example.com", depth="quick")
        findings = await scanner.scan("https://example.com", config)

        # Should find at least one issue (missing headers)
        assert len(findings) > 0
        assert any("Missing Security Headers" in f.title for f in findings)


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        result = ScanResult(
            title="Test Finding",
            severity="high",
            description="A test finding",
            url="https://example.com",
            attack_type="SQL Injection",
            evidence="Payload: ' OR 1=1--",
            remediation="Use parameterized queries",
            confidence="high",
        )

        assert result.title == "Test Finding"
        assert result.severity == "high"
        assert result.confidence == "high"

    def test_scan_result_defaults(self):
        """Test ScanResult default values."""
        result = ScanResult(
            title="Test",
            severity="low",
            description="Test description",
            url="https://example.com",
            attack_type="Test",
        )

        assert result.evidence == ""
        assert result.remediation == ""
        assert result.confidence == "medium"


class TestScanConfig:
    """Test ScanConfig dataclass."""

    def test_scan_config_defaults(self):
        """Test ScanConfig default values."""
        config = ScanConfig(target="https://example.com")

        assert config.target == "https://example.com"
        assert config.scan_types == ["all"]
        assert config.depth == "normal"
        assert config.threads == 10
        assert config.timeout == 30.0
        assert config.follow_redirects is True

    def test_scan_config_custom_values(self):
        """Test ScanConfig with custom values."""
        config = ScanConfig(
            target="https://example.com",
            scan_types=["sqli", "xss"],
            depth="deep",
            threads=20,
            timeout=60.0,
            follow_redirects=False,
        )

        assert config.scan_types == ["sqli", "xss"]
        assert config.depth == "deep"
        assert config.threads == 20
