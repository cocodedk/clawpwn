"""Tests for new tool executors (recon and attack)."""

from pathlib import Path

import respx
from httpx import Response

from clawpwn.ai.nli.tool_executors import (
    execute_credential_test,
    execute_fingerprint_target,
    execute_run_custom_script,
    execute_web_search,
)
from clawpwn.modules.credtest import CredTestResult


class TestReconExecutors:
    """Test reconnaissance tool executors."""

    def test_execute_web_search(self, project_dir: Path, monkeypatch):
        """Test web search executor."""

        # Mock web_search function
        async def mock_web_search(query, max_results):
            from clawpwn.modules.websearch import SearchResult

            return [
                SearchResult(title="Result 1", url="https://example.com/1", snippet="Snippet 1"),
                SearchResult(title="Result 2", url="https://example.com/2", snippet="Snippet 2"),
            ]

        monkeypatch.setattr("clawpwn.modules.websearch.web_search", mock_web_search)

        result = execute_web_search(
            {"query": "test query", "max_results": 2},
            project_dir,
        )

        assert "Result 1" in result
        assert "https://example.com/1" in result
        assert "Snippet 1" in result

    def test_execute_web_search_missing_query(self, project_dir: Path):
        """Test web search executor with missing query."""
        result = execute_web_search({}, project_dir)

        assert "Error" in result
        assert "required" in result.lower()

    @respx.mock
    def test_execute_fingerprint_target(self, project_dir: Path):
        """Test fingerprint target executor."""
        respx.get("https://example.com").mock(
            return_value=Response(
                200,
                text="<html><head><title>Test Site</title></head></html>",
                headers={"Server": "nginx/1.18.0"},
            )
        )

        result = execute_fingerprint_target(
            {"target": "https://example.com"},
            project_dir,
        )

        assert "nginx/1.18.0" in result
        assert "Test Site" in result

    def test_execute_fingerprint_target_missing_url(self, project_dir: Path):
        """Test fingerprint executor with missing target."""
        result = execute_fingerprint_target({}, project_dir)

        assert "Error" in result
        assert "required" in result.lower()


class TestAttackExecutors:
    """Test attack tool executors."""

    @respx.mock
    def test_execute_credential_test(self, project_dir: Path):
        """Test credential test executor."""
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
            return_value=Response(200, text="Invalid credentials")
        )

        result = execute_credential_test(
            {"target": "https://example.com/login", "credentials": [["admin", "admin"]]},
            project_dir,
        )

        assert "Credential testing results" in result
        assert "Credentials tested: 1" in result

    def test_execute_credential_test_missing_target(self, project_dir: Path):
        """Test credential test executor with missing target."""
        result = execute_credential_test({}, project_dir)

        assert "Error" in result
        assert "required" in result.lower()

    @respx.mock
    def test_execute_credential_test_with_app_hint(self, project_dir: Path):
        """Test credential test with app hint."""
        respx.get("https://example.com/phpmyadmin").mock(
            return_value=Response(
                200,
                text="""
                <form action="/login" method="POST">
                    <input name="pma_username" />
                    <input name="pma_password" />
                </form>
                """,
            )
        )
        respx.post("https://example.com/login").mock(return_value=Response(200, text="Invalid"))

        result = execute_credential_test(
            {"target": "https://example.com/phpmyadmin", "app_hint": "phpmyadmin"},
            project_dir,
        )

        assert "Credential testing results" in result

    def test_execute_credential_test_with_hydra_tool(self, project_dir: Path, monkeypatch):
        """Hydra backend should be selected when tool=hydra is provided."""

        async def mock_hydra(_target, _credentials, _app_hint):
            return CredTestResult(
                form_found=True,
                form_action="https://example.com/login",
                credentials_tested=1,
                valid_credentials=[("admin", "admin")],
                details=["Hydra exit code: 0"],
            )

        monkeypatch.setattr(
            "clawpwn.modules.credtest.test_credentials_with_hydra",
            mock_hydra,
        )

        result = execute_credential_test(
            {
                "target": "https://example.com/login",
                "tool": "hydra",
                "credentials": [["admin", "admin"]],
            },
            project_dir,
        )

        assert "Tool: hydra" in result
        assert "VALID CREDENTIALS FOUND" in result
        assert "admin:admin" in result

    def test_execute_credential_test_with_hydra_cross_checks_builtin(
        self, project_dir: Path, monkeypatch
    ):
        """Hydra misses should trigger builtin cross-check and guidance."""

        async def mock_hydra(_target, _credentials, _app_hint):
            return CredTestResult(
                form_found=True,
                form_action="https://example.com/login",
                credentials_tested=2,
                valid_credentials=[],
                details=["Hydra exit code: 0"],
            )

        async def mock_builtin(_target, _credentials, _app_hint):
            return CredTestResult(
                form_found=True,
                form_action="https://example.com/login",
                credentials_tested=2,
                valid_credentials=[("root", "password")],
                details=["Builtin form test matched dashboard signal"],
            )

        monkeypatch.setattr(
            "clawpwn.modules.credtest.test_credentials_with_hydra",
            mock_hydra,
        )
        monkeypatch.setattr(
            "clawpwn.modules.credtest.test_credentials",
            mock_builtin,
        )

        result = execute_credential_test(
            {
                "target": "https://example.com/login",
                "tool": "hydra",
                "credentials": [["root", "password"]],
            },
            project_dir,
        )

        assert "Hydra vs builtin cross-check" in result
        assert "Builtin detected valid credentials that hydra missed" in result
        assert "root:password" in result
        assert "Troubleshooting notes" in result

    def test_execute_credential_test_rejects_invalid_tool(self, project_dir: Path):
        """Credential test should reject unknown backend selectors."""
        result = execute_credential_test(
            {"target": "https://example.com/login", "tool": "unknown"},
            project_dir,
        )

        assert "Error" in result
        assert "tool must be one of" in result

    def test_execute_run_custom_script_success(self, project_dir: Path):
        """Test custom script executor with successful script."""
        script = 'print("Hello from script")'

        result = execute_run_custom_script(
            {
                "script": script,
                "description": "Test script",
                "timeout": 5,
                "user_approved": True,
            },
            project_dir,
        )

        assert "Test script" in result
        assert "Script completed successfully" in result or "Hello from script" in result

    def test_execute_run_custom_script_missing_script(self, project_dir: Path):
        """Test custom script executor with missing script."""
        result = execute_run_custom_script(
            {"description": "Test"},
            project_dir,
        )

        assert "Error" in result
        assert "required" in result.lower()

    def test_execute_run_custom_script_with_error(self, project_dir: Path):
        """Test custom script executor with failing script."""
        script = """
import sys
print("Error message")
sys.exit(1)
"""

        result = execute_run_custom_script(
            {
                "script": script,
                "description": "Failing script",
                "timeout": 5,
                "user_approved": True,
            },
            project_dir,
        )

        assert "Failing script" in result
        assert "exit" in result.lower()

    def test_execute_run_custom_script_adds_validation_note(self, project_dir: Path):
        """Heuristic exploit output should include a confidence warning."""
        script = 'print("HTTP 302 redirect observed - potential bypass")'

        result = execute_run_custom_script(
            {
                "script": script,
                "description": "Heuristic SQLi check",
                "timeout": 5,
                "user_approved": True,
            },
            project_dir,
        )

        assert "Validation note:" in result

    def test_execute_run_custom_script_requires_explicit_approval(self, project_dir: Path):
        """Custom script executor must not run without explicit approval."""
        script = 'print("should not run")'

        result = execute_run_custom_script(
            {"script": script, "description": "Blocked script", "timeout": 5},
            project_dir,
        )

        assert "Approval required" in result
