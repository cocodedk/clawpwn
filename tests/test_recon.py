"""Tests for reconnaissance/fingerprinting module."""

import pytest
import respx
from httpx import Response

from clawpwn.modules.recon import FingerprintResult, fingerprint_target


class TestFingerprinting:
    """Test target fingerprinting functionality."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprint_basic(self):
        """Test basic fingerprinting."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="<html><head><title>Test Site</title></head><body>Content</body></html>",
                headers={
                    "Server": "nginx/1.18.0",
                    "X-Powered-By": "PHP/7.4.3",
                    "Content-Type": "text/html",
                },
            )
        )

        result = await fingerprint_target("https://example.com")

        assert result.server == "nginx/1.18.0"
        assert "nginx/1.18.0" in result.technologies
        assert "PHP/7.4.3" in result.technologies
        assert result.title == "Test Site"

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprint_version_detection(self):
        """Test version detection in HTML."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="""
                <html>
                <head><title>phpMyAdmin 4.8.1</title></head>
                <body>
                <!-- WordPress 5.8.1 -->
                </body>
                </html>
                """,
                headers={"Server": "Apache/2.4.41"},
            )
        )

        result = await fingerprint_target("https://example.com")

        assert result.title == "phpMyAdmin 4.8.1"
        assert any("phpMyAdmin" in hint for hint in result.version_hints)

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprint_security_headers(self):
        """Test missing security headers detection."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="<html><body>Test</body></html>",
                headers={
                    "Server": "nginx",
                    "Content-Type": "text/html",
                    # Missing security headers
                },
            )
        )

        result = await fingerprint_target("https://example.com")

        assert len(result.security_headers_missing) > 0
        header_names = [h.lower() for h in result.security_headers_missing]
        assert (
            "x-frame-options" in header_names
            or "X-Frame-Options" in result.security_headers_missing
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprint_robots_txt(self):
        """Test robots.txt detection."""
        respx.get("https://example.com").mock(
            return_value=Response(200, text="<html><body>Main</body></html>", headers={})
        )
        respx.get("https://example.com/robots.txt").mock(
            return_value=Response(200, text="User-agent: *\nDisallow: /admin")
        )

        result = await fingerprint_target("https://example.com")

        assert any("robots.txt" in path for path in result.exposed_paths)

    @respx.mock
    @pytest.mark.asyncio
    async def test_fingerprint_admin_paths(self):
        """Test common admin path detection."""
        respx.get("https://example.com").mock(
            return_value=Response(200, text="<html><body>Main</body></html>", headers={})
        )
        respx.get("https://example.com/admin").mock(return_value=Response(200, text="Admin"))
        respx.get("https://example.com/login").mock(return_value=Response(302, text="Redirect"))
        respx.get("https://example.com/setup").mock(return_value=Response(404))

        result = await fingerprint_target("https://example.com")

        # At least some exposed paths should be found (admin and/or login)
        assert len(result.exposed_paths) > 0

    @pytest.mark.asyncio
    async def test_fingerprint_result_dataclass(self):
        """Test FingerprintResult dataclass."""
        result = FingerprintResult(
            server="nginx/1.18.0",
            technologies=["nginx", "PHP"],
            version_hints=["PHP 7.4"],
            exposed_paths=["/admin"],
            security_headers_missing=["X-Frame-Options"],
            title="Test Site",
        )

        assert result.server == "nginx/1.18.0"
        assert len(result.technologies) == 2
        assert result.error is None
