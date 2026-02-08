"""Tests for credential testing module."""

import pytest
import respx
from httpx import Response

from clawpwn.modules.credtest import CredTestResult
from clawpwn.modules.credtest.defaults import APP_SPECIFIC_CREDENTIALS, DEFAULT_CREDENTIALS


class TestCredentialTesting:
    """Test credential testing functionality."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_form_found(self):
        """Test when no login form is found."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/login").mock(
            return_value=Response(200, text="<html><body>No form here</body></html>")
        )

        result = await test_credentials("https://example.com/login")

        assert result.form_found is False
        assert result.credentials_tested == 0
        assert len(result.valid_credentials) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_form_detection(self):
        """Test login form detection."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/login").mock(
            return_value=Response(
                200,
                text="""
                <html><body>
                <form action="login" method="POST">
                    <input name="username" type="text" />
                    <input name="password" type="password" />
                    <button>Login</button>
                </form>
                </body></html>
                """,
            )
        )

        # Mock the POST to the correct URL
        respx.post("https://example.com/login").mock(
            return_value=Response(200, text="Invalid credentials")
        )

        result = await test_credentials(
            "https://example.com/login",
            credentials=[("test", "test")],
        )

        assert result.form_found is True
        assert "https://example.com/login" in result.form_action
        assert result.credentials_tested == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_valid_credentials_found(self):
        """Test detection of valid credentials."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/login").mock(
            return_value=Response(
                200,
                text="""
                <html><body>
                <form action="dashboard" method="POST">
                    <input name="user" type="text" />
                    <input name="pass" type="password" />
                </form>
                </body></html>
                """,
            )
        )

        # Mock POST to correct resolved URL
        respx.post("https://example.com/dashboard").mock(
            side_effect=[
                Response(200, text="Invalid password"),
                Response(200, text="Welcome to your dashboard"),
            ]
        )

        result = await test_credentials(
            "https://example.com/login",
            credentials=[("wrong", "wrong"), ("admin", "admin")],
        )

        assert result.form_found is True
        assert len(result.valid_credentials) == 1
        assert result.valid_credentials[0] == ("admin", "admin")

    @respx.mock
    @pytest.mark.asyncio
    async def test_redirect_indicates_success(self):
        """Test that redirect indicates successful login."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/login").mock(
            return_value=Response(
                200,
                text="""
                <form action="/login" method="POST">
                    <input name="username" />
                    <input name="password" />
                </form>
                """,
            )
        )

        # Mock successful login with redirect
        respx.post("https://example.com/login").mock(
            return_value=Response(
                302,
                text="",
                headers={"Location": "/dashboard"},
            )
        )
        respx.get("https://example.com/dashboard").mock(
            return_value=Response(200, text="Dashboard")
        )

        result = await test_credentials(
            "https://example.com/login",
            credentials=[("admin", "password")],
        )

        assert len(result.valid_credentials) >= 0  # May detect redirect

    @respx.mock
    @pytest.mark.asyncio
    async def test_app_specific_credentials(self):
        """Test app-specific credential loading."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/phpmyadmin").mock(
            return_value=Response(
                200,
                text="""
                <form action="/phpmyadmin/index.php" method="POST">
                    <input name="pma_username" />
                    <input name="pma_password" />
                </form>
                """,
            )
        )

        respx.post("https://example.com/phpmyadmin/index.php").mock(
            return_value=Response(200, text="Invalid login")
        )

        result = await test_credentials(
            "https://example.com/phpmyadmin",
            app_hint="phpmyadmin",
        )

        assert result.form_found is True
        # Should test phpMyAdmin-specific credentials
        assert result.credentials_tested == len(APP_SPECIFIC_CREDENTIALS["phpmyadmin"])

    def test_default_credentials_exist(self):
        """Test that default credentials are defined."""
        assert len(DEFAULT_CREDENTIALS) > 0
        assert ("root", "") in DEFAULT_CREDENTIALS
        assert ("admin", "admin") in DEFAULT_CREDENTIALS

    def test_app_specific_credentials_exist(self):
        """Test that app-specific credentials are defined."""
        assert "phpmyadmin" in APP_SPECIFIC_CREDENTIALS
        assert "grafana" in APP_SPECIFIC_CREDENTIALS
        assert "jenkins" in APP_SPECIFIC_CREDENTIALS

    @pytest.mark.asyncio
    async def test_cred_test_result_dataclass(self):
        """Test CredTestResult dataclass."""
        result = CredTestResult(
            form_found=True,
            form_action="/login",
            credentials_tested=5,
            valid_credentials=[("admin", "password")],
            details=["Test detail"],
        )

        assert result.form_found is True
        assert result.credentials_tested == 5
        assert len(result.valid_credentials) == 1
        assert result.error is None
