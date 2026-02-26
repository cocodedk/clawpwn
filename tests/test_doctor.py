"""Tests for ``clawpwn doctor`` health-check command."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from clawpwn.cli_commands.doctor_checks import (
    CheckResult,
    check_external_tools,
    check_privileges,
    check_python_version,
    check_wordlists,
)
from clawpwn.cli_commands.doctor_env_checks import (
    check_api_key,
    check_api_key_valid,
    check_llm_provider,
    check_project_status,
)

ALL_TOOLS_TRUE = {
    "nmap": True,
    "naabu": True,
    "nuclei": True,
    "nikto": True,
    "sqlmap": True,
    "hydra": True,
    "rustscan": True,
    "masscan": True,
    "feroxbuster": True,
    "ffuf": True,
    "searchsploit": True,
    "zap": True,
    "wpscan": True,
    "testssl": True,
}


# ---------------------------------------------------------------------------
# CheckResult dataclass
# ---------------------------------------------------------------------------


class TestCheckResult:
    def test_defaults(self):
        r = CheckResult(name="t", status="pass", message="ok")
        assert r.fix == ""

    def test_with_fix(self):
        r = CheckResult(name="t", status="fail", message="bad", fix="do this")
        assert r.fix == "do this"


# ---------------------------------------------------------------------------
# check_python_version
# ---------------------------------------------------------------------------


class TestPythonVersion:
    def test_current_python_passes(self):
        result = check_python_version()
        assert result.status == "pass"
        assert "Python" in result.message

    def test_old_python_fails(self):
        fake_info = SimpleNamespace(major=3, minor=11, micro=0)
        with patch("clawpwn.cli_commands.doctor_checks.sys") as mock_sys:
            mock_sys.version_info = fake_info
            result = check_python_version()
        assert result.status == "fail"
        assert "3.11" in result.message


# ---------------------------------------------------------------------------
# check_llm_provider
# ---------------------------------------------------------------------------


class TestLLMProvider:
    def test_provider_configured(self):
        with patch("clawpwn.config.getters.get_llm_provider", return_value="anthropic"):
            result = check_llm_provider(None)
        assert result.status == "pass"
        assert "anthropic" in result.message

    def test_provider_default(self):
        result = check_llm_provider(None)
        assert result.status == "pass"


# ---------------------------------------------------------------------------
# check_api_key
# ---------------------------------------------------------------------------


class TestAPIKey:
    def test_key_present(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-test-key-1234")
        result = check_api_key(None)
        assert result.status == "pass"
        assert "..." in result.message

    def test_key_missing(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("CLAWPWN_LLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("CLAWPWN_LLM_PROVIDER", "anthropic")
        result = check_api_key(None)
        assert result.status == "fail"


# ---------------------------------------------------------------------------
# check_api_key_valid
# ---------------------------------------------------------------------------


class TestAPIKeyValid:
    def test_skipped_when_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("CLAWPWN_LLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("CLAWPWN_LLM_PROVIDER", "anthropic")
        result = check_api_key_valid(None)
        assert result.status == "warn"
        assert "Skipped" in result.message

    def test_valid_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        mock_client = MagicMock()
        mock_client.chat.return_value = "pong"
        with patch("clawpwn.ai.llm.LLMClient", return_value=mock_client):
            result = check_api_key_valid(None)
        assert result.status == "pass"

    def test_auth_error(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-bad")
        mock_client = MagicMock()
        mock_client.chat.side_effect = Exception("401 authentication_error")
        with patch("clawpwn.ai.llm.LLMClient", return_value=mock_client):
            result = check_api_key_valid(None)
        assert result.status == "fail"

    def test_network_error(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        mock_client = MagicMock()
        mock_client.chat.side_effect = Exception("Connection refused")
        with patch("clawpwn.ai.llm.LLMClient", return_value=mock_client):
            result = check_api_key_valid(None)
        assert result.status == "warn"


# ---------------------------------------------------------------------------
# check_external_tools
# ---------------------------------------------------------------------------


class TestExternalTools:
    def test_all_installed(self):
        with patch(
            "clawpwn.ai.nli.tool_executors.availability.check_tool_availability",
            return_value=ALL_TOOLS_TRUE,
        ):
            results = check_external_tools()
        assert all(r.status == "pass" for r in results)

    def test_nmap_missing_is_fail(self):
        availability = {**ALL_TOOLS_TRUE, "nmap": False}
        with patch(
            "clawpwn.ai.nli.tool_executors.availability.check_tool_availability",
            return_value=availability,
        ):
            results = check_external_tools()
        core = [r for r in results if "Core" in r.name]
        assert core[0].status == "fail"

    def test_recommended_missing_is_warn(self):
        availability = {**ALL_TOOLS_TRUE, "naabu": False, "nuclei": False}
        with patch(
            "clawpwn.ai.nli.tool_executors.availability.check_tool_availability",
            return_value=availability,
        ):
            results = check_external_tools()
        rec = [r for r in results if "Recommended" in r.name]
        assert rec[0].status == "warn"
        assert "naabu" in rec[0].message


# ---------------------------------------------------------------------------
# check_privileges
# ---------------------------------------------------------------------------


class TestPrivileges:
    def test_root(self):
        with patch("clawpwn.utils.privileges.is_root", return_value=True):
            result = check_privileges()
        assert result.status == "pass"

    def test_non_root_with_capabilities(self):
        with (
            patch(
                "clawpwn.ai.nli.tool_executors.availability.check_tool_availability",
                return_value={"nmap": True, "naabu": False, "masscan": False},
            ),
            patch("clawpwn.utils.privileges.is_root", return_value=False),
            patch("clawpwn.utils.privileges.can_raw_scan", return_value=True),
        ):
            result = check_privileges()
        assert result.status == "pass"


# ---------------------------------------------------------------------------
# check_wordlists
# ---------------------------------------------------------------------------


class TestWordlists:
    def test_wordlists_found(self):
        fake = [{"path": "/usr/share/wordlists/rockyou.txt", "size": "134.0MB"}]
        with patch(
            "clawpwn.ai.nli.tool_executors.availability.discover_wordlists",
            return_value=fake,
        ):
            result = check_wordlists()
        assert result.status == "pass"
        assert "1 found" in result.message

    def test_no_wordlists(self):
        with patch(
            "clawpwn.ai.nli.tool_executors.availability.discover_wordlists",
            return_value=[],
        ):
            result = check_wordlists()
        assert result.status == "warn"


# ---------------------------------------------------------------------------
# check_project_status
# ---------------------------------------------------------------------------


class TestProjectStatus:
    def test_no_project(self):
        assert check_project_status(None) is None

    def test_project_healthy(self, project_dir: Path, initialized_db: Path):
        env_path = project_dir / ".clawpwn" / ".env"
        env_path.write_text("CLAWPWN_LLM_PROVIDER=anthropic\n")

        import sqlite3

        conn = sqlite3.connect(str(initialized_db))
        conn.execute(
            "INSERT INTO projects (path, target) VALUES (?, '10.0.0.1')",
            (str(project_dir),),
        )
        conn.commit()
        conn.close()

        result = check_project_status(project_dir)
        assert result is not None
        assert result.status == "pass"
        assert "target set" in result.message

    def test_project_no_env(self, project_dir: Path, initialized_db: Path):
        result = check_project_status(project_dir)
        assert result is not None
        assert result.status == "warn"
        assert ".env missing" in result.message


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestDoctorCLI:
    def test_doctor_runs(self):
        """Smoke test: doctor command registers and can be invoked."""
        from typer.testing import CliRunner

        from clawpwn.cli_commands.shared import app

        runner = CliRunner()
        # Patch the API validation at source to avoid real HTTP calls
        with patch(
            "clawpwn.cli_commands.doctor_env_checks.check_api_key_valid",
            return_value=CheckResult("API key valid", "warn", "Skipped"),
        ):
            result = runner.invoke(app, ["doctor"])
        assert "ClawPwn Doctor" in result.output
        assert "Summary:" in result.output
