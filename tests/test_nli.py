"""Tests for natural language interface (with mocked LLM)."""

from pathlib import Path
from unittest.mock import Mock, patch

from clawpwn.ai.nli import NaturalLanguageInterface, process_nl_command


class TestParseIntentResponse:
    """Tests for _parse_intent_response."""

    def test_parse_intent_response_parses_all_fields(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            response_text = (
                "INTENT: scan\nTARGET: https://example.com\nPARAMETERS: quick\nCONFIDENCE: high"
            )
            parsed = nli._parse_intent_response(response_text)
            assert parsed["intent"] == "scan"
            assert parsed["target"] == "https://example.com"
            assert parsed["parameters"] == "quick"
            assert parsed["confidence"] == "high"
        finally:
            nli.close()

    def test_parse_intent_response_defaults_unknown(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            parsed = nli._parse_intent_response("")
            assert parsed["intent"] == "unknown"
            assert parsed["target"] == ""
            assert parsed["confidence"] == "low"
        finally:
            nli.close()


class TestProcessCommand:
    """Tests for process_command with mocked LLM."""

    def test_process_command_help_returns_help_action(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(return_value="INTENT: help\nTARGET: \nPARAMETERS: \nCONFIDENCE: high")
        try:
            result = nli.process_command("help me")
            assert result["action"] == "help"
            assert "success" in result
            assert "Available Commands" in result.get("response", "")
        finally:
            nli.close()

    def test_process_command_error_when_llm_raises(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(side_effect=RuntimeError("API error"))
        try:
            result = nli.process_command("anything")
            assert result["success"] is False
            assert result["action"] == "error"
            assert "Error" in result.get("response", "")
        finally:
            nli.close()

    def test_process_command_unknown_intent(self, project_dir: Path, mock_env_vars: None) -> None:
        nli = NaturalLanguageInterface(project_dir)
        # First call: intent parsing; second call: _handle_unknown asks LLM for help text
        nli.llm.chat = Mock(
            side_effect=[
                "INTENT: unknown\nTARGET: \nPARAMETERS: \nCONFIDENCE: low",
                "Try 'scan example.com' or 'help' for options.",
            ]
        )
        try:
            result = nli.process_command("gibberish")
            assert result["action"] == "unknown"
            assert "response" in result
        finally:
            nli.close()

    def test_process_command_handle_exploit_returns_message(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(
            return_value="INTENT: exploit\nTARGET: \nPARAMETERS: \nCONFIDENCE: high"
        )
        try:
            result = nli.process_command("exploit the vulnerability")
            assert result["action"] == "exploit"
            assert result["success"] is False
            assert "killchain" in result.get("response", "").lower()
        finally:
            nli.close()


class TestHandleStatus:
    """Tests for _handle_status path via process_command."""

    def test_process_command_status_with_project(
        self, project_dir: Path, mock_env_vars: None, initialized_db: Path, session_manager
    ) -> None:
        session_manager.create_project(str(project_dir))
        session_manager.set_target("https://example.com")
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(
            return_value="INTENT: check_status\nTARGET: \nPARAMETERS: \nCONFIDENCE: high"
        )
        try:
            result = nli.process_command("what is the status?")
            assert result["action"] == "status"
            assert result["success"] is True
            assert "Target" in result.get("response", "") or "Findings" in result.get(
                "response", ""
            )
        finally:
            nli.close()


class TestNliHelpers:
    """Tests for NLI helper methods."""

    def test_extract_url_finds_http(self, project_dir: Path, mock_env_vars: None) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._extract_url("scan https://example.com/path") == "https://example.com/path"
            assert nli._extract_url("no url here") is None
        finally:
            nli.close()

    def test_extract_network_finds_cidr(self, project_dir: Path, mock_env_vars: None) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._extract_network("discover 192.168.1.0/24") == "192.168.1.0/24"
            assert nli._extract_network("no network") is None
        finally:
            nli.close()

    def test_get_current_target_returns_none_without_project(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            # project_dir has .clawpwn but no db initialized or no project
            result = nli._get_current_target()
            assert result is None or result == ""
        finally:
            nli.close()


class TestProcessNlCommand:
    """Tests for process_nl_command convenience function."""

    def test_process_nl_command_returns_result(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        with patch("clawpwn.ai.nli.NaturalLanguageInterface") as mock_nli_class:
            mock_instance = Mock()
            mock_instance.process_command = Mock(
                return_value={"success": True, "action": "help", "response": "Help text"}
            )
            mock_instance.close = Mock()
            mock_nli_class.return_value = mock_instance

            result = process_nl_command("help", project_dir)

            assert result["action"] == "help"
            mock_instance.process_command.assert_called_once_with("help")
            mock_instance.close.assert_called_once()
