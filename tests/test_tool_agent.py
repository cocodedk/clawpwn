"""Tests for the Claude tool-use agent, tool definitions, and tool executors."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from clawpwn.ai.nli.agent import ToolUseAgent
from clawpwn.ai.nli.tool_executors import (
    EXTERNAL_TOOLS,
    TOOL_EXECUTORS,
    check_tool_availability,
    dispatch_tool,
    execute_check_available_tools,
    execute_suggest_tools,
    format_availability_report,
)
from clawpwn.ai.nli.tools import FAST_PATH_TOOLS, get_all_tools

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class TestToolDefinitions:
    """Validate Anthropic tool schemas."""

    def test_get_all_tools_returns_list(self) -> None:
        tools = get_all_tools()
        assert isinstance(tools, list)
        assert len(tools) >= 9

    def test_each_tool_has_required_fields(self) -> None:
        for tool in get_all_tools():
            assert "name" in tool, f"Missing name in {tool}"
            assert "description" in tool, f"Missing description in {tool.get('name')}"
            assert "input_schema" in tool, f"Missing input_schema in {tool.get('name')}"
            schema = tool["input_schema"]
            assert schema.get("type") == "object", f"Schema type must be object for {tool['name']}"

    def test_tool_names_are_unique(self) -> None:
        names = [t["name"] for t in get_all_tools()]
        assert len(names) == len(set(names))

    def test_fast_path_tools_are_subset_of_all(self) -> None:
        all_names = {t["name"] for t in get_all_tools()}
        assert FAST_PATH_TOOLS.issubset(all_names)

    def test_web_scan_has_required_target(self) -> None:
        ws = next(t for t in get_all_tools() if t["name"] == "web_scan")
        assert "target" in ws["input_schema"].get("required", [])

    def test_suggest_tools_schema_has_suggestions(self) -> None:
        st = next(t for t in get_all_tools() if t["name"] == "suggest_tools")
        props = st["input_schema"].get("properties", {})
        assert "suggestions" in props
        assert props["suggestions"]["type"] == "array"


# ---------------------------------------------------------------------------
# Tool executors
# ---------------------------------------------------------------------------


class TestToolExecutors:
    """Test individual tool executor functions."""

    def test_all_tools_have_executors(self) -> None:
        for tool in get_all_tools():
            assert tool["name"] in TOOL_EXECUTORS, f"No executor for {tool['name']}"

    def test_dispatch_unknown_tool(self, project_dir: Path, mock_env_vars: None) -> None:
        result = dispatch_tool("nonexistent", {}, project_dir)
        assert "Unknown tool" in result

    def test_dispatch_tool_catches_exceptions(self, project_dir: Path, mock_env_vars: None) -> None:
        with patch.dict(
            TOOL_EXECUTORS, {"broken": Mock(side_effect=RuntimeError("boom"))}, clear=False
        ):
            result = dispatch_tool("broken", {}, project_dir)
            assert "failed" in result.lower()

    def test_execute_check_available_tools(self, project_dir: Path, mock_env_vars: None) -> None:
        result = execute_check_available_tools({}, project_dir)
        assert isinstance(result, str)
        # Should mention at least some tools
        assert "nstalled" in result or "No external" in result

    def test_execute_suggest_tools_formats_output(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        params = {
            "suggestions": [
                {
                    "name": "sqlmap",
                    "reason": "Advanced SQL injection",
                    "install_command": "sudo apt install sqlmap",
                    "example_usage": "sqlmap -u http://target/page?id=1",
                },
            ]
        }
        result = execute_suggest_tools(params, project_dir)
        assert "sqlmap" in result
        assert "sudo apt install sqlmap" in result

    def test_execute_suggest_tools_empty(self, project_dir: Path, mock_env_vars: None) -> None:
        result = execute_suggest_tools({"suggestions": []}, project_dir)
        assert "No tool suggestions" in result

    def test_execute_check_status_no_db(self, project_dir: Path, mock_env_vars: None) -> None:
        # project_dir has .clawpwn but no initialised DB
        result = dispatch_tool("check_status", {}, project_dir)
        assert "not found" in result.lower() or "no project" in result.lower()

    def test_execute_set_target(
        self, project_dir: Path, mock_env_vars: None, initialized_db: Path, session_manager
    ) -> None:
        session_manager.create_project(str(project_dir))
        result = dispatch_tool("set_target", {"target": "http://example.com"}, project_dir)
        assert "http://example.com" in result

    def test_execute_show_help_valid_topic(self, project_dir: Path, mock_env_vars: None) -> None:
        result = dispatch_tool("show_help", {"topic": "scan"}, project_dir)
        assert isinstance(result, str)
        assert len(result) > 10

    def test_execute_show_help_invalid_topic(self, project_dir: Path, mock_env_vars: None) -> None:
        result = dispatch_tool("show_help", {"topic": "nonexistent"}, project_dir)
        assert "Unknown topic" in result


# ---------------------------------------------------------------------------
# Availability helpers
# ---------------------------------------------------------------------------


class TestToolAvailability:
    """Test the external tool availability system."""

    def test_check_tool_availability_returns_dict(self) -> None:
        status = check_tool_availability()
        assert isinstance(status, dict)
        assert set(status.keys()) == set(EXTERNAL_TOOLS.keys())
        for v in status.values():
            assert isinstance(v, bool)

    def test_format_availability_report_is_string(self) -> None:
        report = format_availability_report()
        assert isinstance(report, str)
        assert len(report) > 0

    @patch("clawpwn.ai.nli.tool_executors.availability.shutil.which", return_value=None)
    def test_all_missing(self, _mock_which: Mock) -> None:
        report = format_availability_report()
        assert "Not installed" in report
        for name in EXTERNAL_TOOLS:
            assert name in report

    @patch("clawpwn.ai.nli.tool_executors.availability.shutil.which", return_value="/usr/bin/x")
    def test_all_installed(self, _mock_which: Mock) -> None:
        report = format_availability_report()
        assert "Installed" in report
        assert "Not installed" not in report


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def _make_text_block(text: str):
    return SimpleNamespace(type="text", text=text)


def _make_tool_use_block(name: str, tool_input: dict, tool_id: str = "toolu_1"):
    return SimpleNamespace(type="tool_use", name=name, input=tool_input, id=tool_id)


def _make_response(content: list, stop_reason: str = "end_turn"):
    return SimpleNamespace(content=content, stop_reason=stop_reason)


class TestToolUseAgent:
    """Test the ToolUseAgent loop with mocked LLM."""

    def _make_agent(self, project_dir: Path) -> ToolUseAgent:
        llm = Mock()
        llm.provider = "anthropic"
        return ToolUseAgent(llm, project_dir)

    def test_direct_text_response(self, project_dir: Path, mock_env_vars: None) -> None:
        """Claude responds with text only — no tool call."""
        agent = self._make_agent(project_dir)
        agent.llm.chat_with_tools = Mock(return_value=_make_response([_make_text_block("Hello!")]))
        result = agent.run("hi")
        assert result["success"] is True
        assert "Hello!" in result["response"]

    def test_single_tool_call_fast_path(self, project_dir: Path, mock_env_vars: None) -> None:
        """Simple fast-path tool (check_status) skips analysis round-trip."""
        agent = self._make_agent(project_dir)

        agent.llm.chat_with_tools = Mock(
            return_value=_make_response(
                [_make_tool_use_block("check_status", {})],
                stop_reason="tool_use",
            )
        )

        with patch(
            "clawpwn.ai.nli.agent.executor.dispatch_tool",
            return_value="Target: example.com",
        ):
            result = agent.run("what is the status")

        assert result["success"] is True
        assert "example.com" in result["response"]
        # Should NOT have been called a second time (fast path)
        assert agent.llm.chat_with_tools.call_count == 1

    def test_tool_call_with_analysis(self, project_dir: Path, mock_env_vars: None) -> None:
        """Non-fast-path tool (web_scan) gets an analysis round-trip."""
        agent = self._make_agent(project_dir)

        scan_response = _make_response(
            [
                _make_text_block("Scanning phpMyAdmin for SQL injection..."),
                _make_tool_use_block("web_scan", {"target": "http://target/phpmyadmin"}),
            ],
            stop_reason="tool_use",
        )
        analysis_response = _make_response(
            [_make_text_block("Found 2 SQL injection vulnerabilities.")]
        )
        agent.llm.chat_with_tools = Mock(side_effect=[scan_response, analysis_response])

        with patch(
            "clawpwn.ai.nli.agent.executor.dispatch_tool",
            return_value="Total findings: 2 (2 critical).",
        ):
            result = agent.run("scan for sql injection http://target/phpmyadmin")

        assert result["success"] is True
        assert "2 SQL injection" in result["response"]
        assert agent.llm.chat_with_tools.call_count == 2

    def test_suggest_tools_captured(self, project_dir: Path, mock_env_vars: None) -> None:
        """suggest_tools tool call populates the suggestions field."""
        agent = self._make_agent(project_dir)

        suggestions_input = {
            "suggestions": [
                {
                    "name": "sqlmap",
                    "reason": "Deep SQLi",
                    "install_command": "apt install sqlmap",
                    "example_usage": "sqlmap -u ...",
                }
            ]
        }
        call1 = _make_response(
            [_make_tool_use_block("suggest_tools", suggestions_input)],
            stop_reason="tool_use",
        )
        call2 = _make_response([_make_text_block("I recommend sqlmap.")])
        agent.llm.chat_with_tools = Mock(side_effect=[call1, call2])

        result = agent.run("what tools should I use?")

        assert result["success"] is True
        assert len(result.get("suggestions", [])) == 1
        assert result["suggestions"][0]["name"] == "sqlmap"

    def test_max_rounds_limit(self, project_dir: Path, mock_env_vars: None) -> None:
        """Agent stops after MAX_TOOL_ROUNDS to prevent runaway loops."""
        agent = self._make_agent(project_dir)

        # Always returns a tool call — should be capped
        tool_response = _make_response(
            [_make_tool_use_block("check_available_tools", {})],
            stop_reason="tool_use",
        )
        # Override FAST_PATH_TOOLS so check_available_tools doesn't fast-path
        with (
            patch("clawpwn.ai.nli.agent.loop.FAST_PATH_TOOLS", frozenset()),
            patch("clawpwn.ai.nli.agent.executor.dispatch_tool", return_value="tools: nmap"),
        ):
            agent.llm.chat_with_tools = Mock(return_value=tool_response)
            result = agent.run("loop test")

        assert result["success"] is True
        # Should have been called exactly MAX_TOOL_ROUNDS times
        from clawpwn.ai.nli.agent import MAX_TOOL_ROUNDS

        assert agent.llm.chat_with_tools.call_count == MAX_TOOL_ROUNDS

    def test_system_prompt_includes_tool_status(
        self, project_dir: Path, mock_env_vars: None
    ) -> None:
        agent = self._make_agent(project_dir)
        assert "External tool status:" in agent._system_prompt


# ---------------------------------------------------------------------------
# NLI provider routing
# ---------------------------------------------------------------------------


class TestNLIProviderRouting:
    """Verify NLI delegates to agent vs text-parse based on provider."""

    def test_openai_uses_text_parse(self, project_dir: Path, mock_env_vars: None) -> None:
        from clawpwn.ai.nli import NaturalLanguageInterface

        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._use_tool_agent is False  # mock_env_vars sets provider=openai
        finally:
            nli.close()

    def test_anthropic_uses_tool_agent(
        self, project_dir: Path, mock_env_vars: None, monkeypatch
    ) -> None:
        from clawpwn.ai.nli import NaturalLanguageInterface

        monkeypatch.setenv("CLAWPWN_LLM_PROVIDER", "anthropic")
        nli = NaturalLanguageInterface(project_dir)
        try:
            assert nli._use_tool_agent is True
        finally:
            nli.close()

    def test_force_legacy_disables_agent(
        self, project_dir: Path, mock_env_vars: None, monkeypatch
    ) -> None:
        from clawpwn.ai.nli import NaturalLanguageInterface

        monkeypatch.setenv("CLAWPWN_LLM_PROVIDER", "anthropic")
        nli = NaturalLanguageInterface(project_dir)
        nli.force_legacy = True
        try:
            assert nli._use_tool_agent is False
        finally:
            nli.close()


# ---------------------------------------------------------------------------
# Orchestrator decision mixin
# ---------------------------------------------------------------------------


class TestDecisionMixinToolUse:
    """Test orchestrator decision_mixin tool-use path."""

    def test_decide_via_tools_parses_tool_call(self) -> None:
        from clawpwn.ai.orchestrator.decision_mixin import DecisionMixin
        from clawpwn.ai.orchestrator.models import ActionType, KillChainState, Phase

        mixin = DecisionMixin()
        mixin.kill_chain_state = KillChainState(
            current_phase=Phase.RECONNAISSANCE, target="http://test"
        )

        tool_input = {
            "action": "scan",
            "target": "http://test",
            "reason": "Start recon",
            "risk": "low",
            "needs_approval": False,
        }
        response = _make_response(
            [_make_tool_use_block("decide_action", tool_input)],
            stop_reason="tool_use",
        )
        mixin.llm = Mock()
        mixin.llm.provider = "anthropic"
        mixin.llm.chat_with_tools = Mock(return_value=response)

        action = mixin._decide_via_tools(Phase.RECONNAISSANCE, "What next?")
        assert action.action_type == ActionType.SCAN
        assert action.reason == "Start recon"
        assert action.target == "http://test"
