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

    def test_process_command_nl_help_search_without_help_keyword(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(side_effect=AssertionError("LLM should not be called for help lookup"))
        try:
            result = nli.process_command("how do i restart console")
            assert result["action"] == "help"
            assert result["success"] is True
            assert "restart" in result.get("response", "").lower()
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

    def test_process_command_skips_memory_context_for_explicit_target(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(
            return_value=(
                "ACTION: scan\nTARGET: 172.17.0.2\nPARAMS: {}\n"
                "CONFIDENCE: high\nNEEDS_INPUT: no\nQUESTION:"
            )
        )
        nli._build_memory_context = Mock(return_value="Objective: test")  # type: ignore[method-assign]
        nli._execute_intent = Mock(  # type: ignore[method-assign]
            return_value={"success": True, "action": "scan", "response": "ok"}
        )
        try:
            result = nli.process_command("scan 172.17.0.2")
            assert result["action"] == "scan"
            nli._build_memory_context.assert_not_called()  # type: ignore[attr-defined]
            system_prompt = nli.llm.chat.call_args[0][1]
            assert "Project context:" not in system_prompt
        finally:
            nli.close()

    def test_process_command_includes_compact_memory_for_follow_up(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(
            return_value=(
                "ACTION: scan\nTARGET: \nPARAMS: {}\nCONFIDENCE: high\nNEEDS_INPUT: no\nQUESTION:"
            )
        )
        nli._build_memory_context = Mock(return_value="Objective: continue test")  # type: ignore[method-assign]
        nli._execute_intent = Mock(  # type: ignore[method-assign]
            return_value={"success": True, "action": "scan", "response": "ok"}
        )
        try:
            result = nli.process_command("scan it again")
            assert result["action"] == "scan"
            nli._build_memory_context.assert_called_once_with(compact=True)  # type: ignore[attr-defined]
            system_prompt = nli.llm.chat.call_args[0][1]
            assert "Project context:\nObjective: continue test" in system_prompt
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

    def test_process_command_scan_ip_uses_network_discovery(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
        monkeypatch,
    ) -> None:
        from clawpwn.modules.network import HostInfo

        session_manager.create_project(str(project_dir))
        session_manager.set_target("192.168.1.10")
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(return_value="INTENT: scan\nTARGET: \nPARAMETERS: \nCONFIDENCE: high")

        async def fake_scan_host(*args, **kwargs):
            return HostInfo(ip="192.168.1.10", open_ports=[22, 80], services=[])

        monkeypatch.setattr(
            "clawpwn.modules.network.NetworkDiscovery.scan_host", fake_scan_host, raising=True
        )

        class FakeScanner:
            async def scan(self, *args, **kwargs):
                raise AssertionError("Web scanner should not run for raw IP target")

        monkeypatch.setattr("clawpwn.modules.scanner.Scanner", lambda *_: FakeScanner())

        try:
            result = nli.process_command("find open ports")
            assert result["success"] is True
            assert "Open ports" in result.get("response", "")
            assert result.get("executed_command") == "!scan --scanner nmap --depth deep --verbose"
            assert "Running host scan on 192.168.1.10" in result.get("execution_note", "")
        finally:
            nli.close()

    def test_process_command_scan_ip_defaults_to_nmap_deep_verbose(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
        monkeypatch,
    ) -> None:
        from clawpwn.modules.network import HostInfo

        session_manager.create_project(str(project_dir))
        session_manager.set_target("172.17.0.2")
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(return_value="INTENT: scan\nTARGET: \nPARAMETERS: \nCONFIDENCE: high")

        captured_kwargs = {}

        async def fake_scan_host(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return HostInfo(ip="172.17.0.2", open_ports=[21, 22], services=[])

        monkeypatch.setattr(
            "clawpwn.modules.network.NetworkDiscovery.scan_host", fake_scan_host, raising=True
        )

        class FakeScanner:
            async def scan(self, *args, **kwargs):
                raise AssertionError("Web scanner should not run for raw IP target")

        monkeypatch.setattr("clawpwn.modules.scanner.Scanner", lambda *_: FakeScanner())

        try:
            result = nli.process_command("scan the target")
            assert result["success"] is True
            assert captured_kwargs.get("scanner_type") == "nmap"
            assert captured_kwargs.get("scan_type") == "deep"
            assert captured_kwargs.get("full_scan") is True
            assert captured_kwargs.get("verify_tcp") is True
            assert captured_kwargs.get("verbose") is True
            assert result.get("executed_command") == "!scan --scanner nmap --depth deep --verbose"
            assert "Running host scan on 172.17.0.2" in result.get("execution_note", "")
        finally:
            nli.close()

    def test_process_command_scan_ports_needs_target_cidr(
        self, project_dir: Path, mock_env_vars: None, initialized_db: Path, session_manager
    ) -> None:
        session_manager.create_project(str(project_dir))
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(return_value="INTENT: scan\nTARGET: \nPARAMETERS: \nCONFIDENCE: high")
        try:
            result = nli.process_command("find open ports")
            assert result["success"] is False
            assert result["action"] == "scan"
            assert "CIDR" in result.get("response", "") or "192.168.1.0/24" in result.get(
                "response", ""
            )
        finally:
            nli.close()

    def test_process_command_blocks_out_of_scope_target(
        self, project_dir: Path, mock_env_vars: None, initialized_db: Path, session_manager
    ) -> None:
        session_manager.create_project(str(project_dir))
        session_manager.set_target("https://example.com")
        nli = NaturalLanguageInterface(project_dir)
        nli.llm.chat = Mock(
            return_value="INTENT: scan\nTARGET: https://other.com\nPARAMETERS: \nCONFIDENCE: high"
        )
        try:
            result = nli.process_command("scan https://other.com")
            assert result["success"] is False
            assert result["action"] == "blocked"
            assert "Out of scope" in result.get("response", "")
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

    def test_ports_spec_maps_all_to_full_range(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._ports_spec({"ports": "all"}) == "1-65535"
            assert nli._ports_spec({"ports": "full"}) == "1-65535"
        finally:
            nli.close()

    def test_ports_spec_rejects_invalid_text(self, project_dir: Path, mock_env_vars: None) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._ports_spec({"ports": "abc"}) is None
            assert nli._ports_spec({"ports": "top"}) is None
        finally:
            nli.close()

    def test_ports_spec_accepts_numeric_formats(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._ports_spec({"ports": "80,443"}) == "80,443"
            assert nli._ports_spec({"ports": "1-1024"}) == "1-1024"
        finally:
            nli.close()

    def test_should_include_memory_context_for_follow_up(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._should_include_memory_context("scan it again") is True
        finally:
            nli.close()

    def test_should_not_include_memory_context_for_explicit_target(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._should_include_memory_context("scan 172.17.0.2") is False
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
