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

    def test_execute_run_custom_script_success(self, project_dir: Path):
        """Test custom script executor with successful script."""
        script = 'print("Hello from script")'

        result = execute_run_custom_script(
            {"script": script, "description": "Test script", "timeout": 5},
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
            {"script": script, "description": "Failing script", "timeout": 5},
            project_dir,
        )

        assert "Failing script" in result
        assert "exit" in result.lower()
