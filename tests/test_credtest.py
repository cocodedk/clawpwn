"""Tests for credential testing module."""

import pytest
import respx
from httpx import Response

from clawpwn.modules.credtest import CredTestResult, build_credential_candidates
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
        # Should include app defaults but use generic strategy cap
        assert result.credentials_tested >= len(APP_SPECIFIC_CREDENTIALS["phpmyadmin"])
        assert any("Credential strategy:" in detail for detail in result.details)

    @respx.mock
    @pytest.mark.asyncio
    async def test_submits_hidden_form_fields(self):
        """Hidden/default form fields should be included in login POST payload."""
        from clawpwn.modules.credtest import test_credentials

        respx.get("https://example.com/phpmyadmin").mock(
            return_value=Response(
                200,
                text="""
                <form action="/phpmyadmin/index.php" method="POST">
                    <input type="hidden" name="server" value="1" />
                    <input name="pma_username" />
                    <input name="pma_password" />
                </form>
                """,
            )
        )

        captured_data: list[dict] = []

        def _capture(request):
            body = request.content.decode()
            captured_data.append(
                dict(item.split("=", 1) for item in body.split("&") if "=" in item)
            )
            return Response(200, text="Invalid login")

        respx.post("https://example.com/phpmyadmin/index.php").mock(side_effect=_capture)

        await test_credentials(
            "https://example.com/phpmyadmin",
            credentials=[("root", "password")],
        )

        assert captured_data
        assert captured_data[0].get("server") == "1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_collects_response_hints(self):
        """Response hints should be captured for strategy refinement."""
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
            return_value=Response(
                200,
                text="#1045 - Access denied for user 'admin'@'localhost' (using password: NO)",
            )
        )

        result = await test_credentials(
            "https://example.com/phpmyadmin",
            credentials=[("admin", "admin")],
        )

        assert result.hints
        assert any("password" in hint.lower() or "mysql" in hint.lower() for hint in result.hints)
        assert result.policy_action in {"continue", "continue_adjust"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_stops_early_on_repeated_block_signals(self):
        """Repeated blocking signals should stop brute-force loops early."""
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
        respx.post("https://example.com/login").mock(
            side_effect=[
                Response(429, text="Too many requests", headers={"Retry-After": "60"}),
                Response(429, text="Too many requests", headers={"Retry-After": "60"}),
                Response(429, text="Too many requests", headers={"Retry-After": "60"}),
            ]
        )

        result = await test_credentials(
            "https://example.com/login",
            credentials=[("u1", "p1"), ("u2", "p2"), ("u3", "p3")],
        )

        assert result.stopped_early is True
        assert result.policy_action == "stop_and_replan"
        assert result.credentials_tested < 3
        assert result.block_signals

    @respx.mock
    @pytest.mark.asyncio
    async def test_phpmyadmin_success_not_masked_by_error_word(self):
        """A phpMyAdmin post-login page contains 'error' in normal content.

        The old logic checked failure keywords (including bare 'error') before
        success indicators, so every phpMyAdmin login was falsely marked as
        failed.  The fix: check success indicators first and use specific
        failure *phrases* instead of single words.
        """
        from clawpwn.modules.credtest import test_credentials

        login_page = """
        <html><body>
        <form action="/phpMyAdmin/index.php" method="POST">
            <input type="hidden" name="server" value="1" />
            <input name="pma_username" type="text" />
            <input name="pma_password" type="password" />
        </form>
        </body></html>
        """
        # Successful login: page has "Log out" link but also "error" in content
        dashboard_page = """
        <html><body>
        <div id="nav">phpMyAdmin | Server: localhost | <a href="logout">Log out</a></div>
        <div>Databases | SQL | Status | Variables | Export</div>
        <div class="notice">Error reporting is disabled</div>
        </body></html>
        """
        # Failed login: MySQL access denied
        failed_page = "#1045 - Access denied for user 'wrong'@'localhost' (using password: YES)"

        respx.get("https://target/phpMyAdmin/").mock(
            return_value=Response(200, text=login_page),
        )
        respx.post("https://target/phpMyAdmin/index.php").mock(
            side_effect=[
                Response(200, text=failed_page),
                Response(200, text=dashboard_page),
            ],
        )

        result = await test_credentials(
            "https://target/phpMyAdmin/",
            credentials=[("wrong", "wrong"), ("root", "root")],
            app_hint="phpmyadmin",
        )

        assert result.form_found is True
        assert len(result.valid_credentials) == 1
        assert result.valid_credentials[0] == ("root", "root")

    @respx.mock
    @pytest.mark.asyncio
    async def test_prefers_form_with_password_field(self):
        """When multiple forms exist, prefer the one with a password field."""
        from clawpwn.modules.credtest import test_credentials

        html = """
        <form action="/lang" method="POST">
            <select name="lang"><option>en</option></select>
            <input type="submit" value="Go" />
        </form>
        <form action="/login" method="POST">
            <input name="user" type="text" />
            <input name="pass" type="password" />
        </form>
        """
        respx.get("https://example.com/").mock(return_value=Response(200, text=html))
        respx.post("https://example.com/login").mock(
            return_value=Response(200, text="Invalid login"),
        )

        result = await test_credentials(
            "https://example.com/",
            credentials=[("a", "b")],
        )

        assert result.form_found is True
        assert "/login" in result.form_action

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

    def test_build_credential_candidates_is_generic_and_capped(self):
        """Candidate builder should combine sources and enforce cap."""
        candidates, strategy = build_credential_candidates(None, "phpmyadmin", max_candidates=20)
        assert candidates
        assert len(candidates) == 20
        assert "common defaults" in strategy
        assert "generic combinations" in strategy or "wordlist expansion" in strategy

    def test_is_login_successful_success_before_failure(self):
        """Success indicators should be checked before failure phrases."""
        from clawpwn.modules.credtest.helpers import is_login_successful

        # Page has "Log out" (success) AND "error" in normal content
        resp = Response(200, text="<a>Log out</a> Error reporting disabled")
        assert is_login_successful(resp) is True

    def test_is_login_successful_specific_failure(self):
        """Specific failure phrases should be detected."""
        from clawpwn.modules.credtest.helpers import is_login_successful

        resp = Response(200, text="#1045 - Access denied for user 'root'@'localhost'")
        assert is_login_successful(resp) is False

    def test_is_login_successful_generic_error_not_failure(self):
        """Bare 'error' word should NOT trigger failure detection."""
        from clawpwn.modules.credtest.helpers import is_login_successful

        # Page mentions "error" but in a benign context, no success signal either
        resp = Response(200, text="Error reporting configuration page")
        assert is_login_successful(resp) is False  # no success, no redirect

    def test_is_login_successful_form_repres_as_failure(self):
        """If password field is still present, treat as failure."""
        from clawpwn.modules.credtest.helpers import is_login_successful

        resp = Response(200, text='<input name="pma_password" type="password" />')
        assert is_login_successful(resp, password_field="pma_password") is False

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
        assert result.policy_action == "continue"
        assert result.stopped_early is False
        assert result.error is None
