"""Tests for the code-driven plan executor: end-to-end, routing, and focused prompt wiring."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


def _make_tool_use_block(name: str, tool_input: dict, tool_id: str = "toolu_1"):
    return SimpleNamespace(type="tool_use", name=name, input=tool_input, id=tool_id)


def _make_text_block(text: str):
    return SimpleNamespace(type="text", text=text)


def _make_response(content: list):
    return SimpleNamespace(content=content, stop_reason="tool_use", model="test")


_SAVE_PLAN_TOOL = {
    "name": "save_plan",
    "description": "test",
    "input_schema": {"type": "object", "properties": {}, "required": []},
}


# ---------------------------------------------------------------------------
# run_plan_executor end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("mock_env_vars", "initialized_db")
class TestRunPlanExecutor:
    """End-to-end plan executor tests with mocked LLM and dispatch."""

    def test_full_flow_generates_and_executes_plan(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/phpmyadmin/")

        llm = Mock()
        llm.model = "claude-sonnet-4-6"

        plan_response = _make_response(
            [
                _make_tool_use_block(
                    "save_plan",
                    {
                        "steps": [
                            {"description": "Fingerprint target", "tool": "fingerprint_target"},
                            {"description": "SQLi scan", "tool": "web_scan:sqlmap"},
                        ]
                    },
                )
            ]
        )
        llm.chat_with_tools = Mock(return_value=plan_response)
        llm.chat = Mock(return_value="Summary: 2 vulnerabilities found")

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Finding: SQLi in login form",
        ):
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=[_SAVE_PLAN_TOOL],
                system_prompt="You are a pentester",
                user_message="scan the target",
            )

        assert result["success"] is True
        assert "Summary" in result["response"] or "vulnerabilities" in result["response"]

    def test_no_target_returns_error(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        # No target set

        llm = Mock()
        result = run_plan_executor(
            llm=llm,
            project_dir=project_dir,
            tools=[],
            system_prompt="",
            user_message="scan",
        )

        assert result["success"] is False
        assert "target" in result["response"].lower()

    def test_fallback_to_agent_loop_when_no_plan_generated(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/")

        llm = Mock()
        llm.model = "claude-sonnet-4-6"

        text_response = SimpleNamespace(
            content=[_make_text_block("I'll scan the target")],
            stop_reason="end_turn",
            model="test",
        )
        llm.chat_with_tools = Mock(return_value=text_response)

        with patch(
            "clawpwn.ai.nli.agent.executor.run_agent_loop",
            return_value={"success": True, "response": "Fallback to loop"},
        ) as mock_loop:
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=[_SAVE_PLAN_TOOL],
                system_prompt="",
                user_message="scan",
            )

        mock_loop.assert_called_once()
        assert result["response"] == "Fallback to loop"


# ---------------------------------------------------------------------------
# Plan resumption
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("mock_env_vars", "initialized_db")
class TestResumeFromPending:
    """Test plan resumption when pending steps exist."""

    def test_resumes_existing_plan(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/")

        session_manager.save_plan(
            [
                {"description": "Fingerprint", "tool": "fingerprint_target"},
                {"description": "SQLi scan", "tool": "web_scan:sqlmap"},
            ]
        )
        session_manager.update_step_status(1, "done", "Apache/PHP detected")

        llm = Mock()
        llm.model = "claude-sonnet-4-6"
        llm.chat = Mock(return_value="Summary: resumed and completed")

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="SQLi found",
        ):
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=[],
                system_prompt="",
                user_message="scan",
            )

        # Should NOT have called chat_with_tools (no new plan generation)
        llm.chat_with_tools.assert_not_called()
        assert result["success"] is True

    def test_replace_plan_clears_stale_plan(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        """replace_plan=True should replace a pending broad plan."""
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("192.168.1.10")

        # Simulate a stale broad plan with pending steps
        session_manager.save_plan(
            [
                {"description": "Fingerprint", "tool": "fingerprint_target"},
                {"description": "Full web scan", "tool": "web_scan:feroxbuster"},
            ]
        )
        session_manager.update_step_status(1, "done", "Apache detected")

        llm = Mock()
        llm.model = "claude-sonnet-4-6"

        plan_response = _make_response(
            [
                _make_tool_use_block(
                    "save_plan",
                    {
                        "steps": [
                            {"description": "Hydra FTP", "tool": "credential_test:hydra"},
                        ]
                    },
                )
            ]
        )
        llm.chat_with_tools = Mock(return_value=plan_response)
        llm.chat = Mock(return_value="Summary: tested FTP credentials")

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Hydra found weak creds",
        ):
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=[_SAVE_PLAN_TOOL],
                system_prompt="EXHAUSTIVE",
                user_message="run hydra against ftp port 21",
                replace_plan=True,
            )

        # Should have generated a NEW plan (called chat_with_tools)
        llm.chat_with_tools.assert_called_once()
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Agent routing (ToolUseAgent.run dispatches correctly)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("mock_env_vars")
class TestAgentRouting:
    """Test that ToolUseAgent.run routes to the right executor."""

    def test_conversational_routes_to_agent_loop(
        self,
        project_dir: Path,
    ) -> None:
        from clawpwn.ai.nli.agent import ToolUseAgent

        llm = Mock()
        llm.provider = "anthropic"
        agent = ToolUseAgent(llm, project_dir)

        with (
            patch(
                "clawpwn.ai.nli.agent.plan_helpers.classify_intent",
                return_value="conversational",
            ),
            patch(
                "clawpwn.ai.nli.agent.loop.run_agent_loop",
                return_value={"success": True, "response": "Hello"},
            ) as mock_loop,
        ):
            result = agent.run("what did you find?")

        mock_loop.assert_called_once()
        assert result["response"] == "Hello"

    def test_plan_execute_routes_to_plan_executor(
        self,
        project_dir: Path,
    ) -> None:
        from clawpwn.ai.nli.agent import ToolUseAgent

        llm = Mock()
        llm.provider = "anthropic"
        agent = ToolUseAgent(llm, project_dir)

        with (
            patch(
                "clawpwn.ai.nli.agent.plan_helpers.classify_intent",
                return_value="plan_execute",
            ),
            patch(
                "clawpwn.ai.nli.agent.plan_executor.run_plan_executor",
                return_value={"success": True, "response": "Scan complete"},
            ) as mock_plan,
        ):
            result = agent.run("scan the target")

        mock_plan.assert_called_once()
        assert result["response"] == "Scan complete"


# ---------------------------------------------------------------------------
# Focused prompt wiring
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("mock_env_vars", "initialized_db")
class TestFocusedPromptWiring:
    """Test that run_plan_executor passes focused prompt for specific requests."""

    def test_focused_request_uses_focused_prompt(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("192.168.1.10")

        llm = Mock()
        llm.model = "claude-sonnet-4-6"

        plan_response = _make_response(
            [
                _make_tool_use_block(
                    "save_plan",
                    {
                        "steps": [
                            {"description": "Hydra FTP", "tool": "credential_test:hydra"},
                        ]
                    },
                )
            ]
        )
        llm.chat_with_tools = Mock(return_value=plan_response)
        llm.chat = Mock(return_value="Summary: tested FTP credentials")

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Hydra found weak creds",
        ):
            run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=[_SAVE_PLAN_TOOL],
                system_prompt="EXHAUSTIVE vulnerability discovery",
                user_message="run hydra against ftp",
            )

        # The system_prompt passed to chat_with_tools should be the focused
        # one, not the full exhaustive prompt
        call_kwargs = llm.chat_with_tools.call_args
        prompt_used = call_kwargs.kwargs.get(
            "system_prompt", call_kwargs[1].get("system_prompt", "")
        )
        assert "EXHAUSTIVE" not in prompt_used
        assert "SPECIFIC tool or action" in prompt_used


# ---------------------------------------------------------------------------
# Result-query routing: "list ports" → conversational with port data
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("mock_env_vars", "initialized_db")
class TestResultQueryRouting:
    """Prove that result-query messages route to agent loop with port context."""

    def test_list_ports_routes_to_agent_loop_not_plan(
        self,
        project_dir: Path,
        session_manager,
    ) -> None:
        """'list all detected ports' → classify_intent returns conversational
        → agent loop is called (no plan executor) and receives port context."""
        from clawpwn.ai.nli.agent import ToolUseAgent

        session_manager.create_project(str(project_dir))
        session_manager.set_target("192.168.1.10")
        session_manager.add_log(
            message="network_scan completed",
            level="INFO",
            phase="scan",
            details=json.dumps(
                {
                    "tool": "network_scan",
                    "scanner": "nmap",
                    "depth": "deep",
                    "target": "192.168.1.10",
                    "open_ports": [22, 80, 443, 3306],
                    "open_ports_count": 4,
                }
            ),
        )

        llm = Mock()
        llm.provider = "anthropic"
        # classify_intent calls llm.chat — return "conversational"
        llm.chat.return_value = "conversational"
        agent = ToolUseAgent(llm, project_dir)

        with (
            patch(
                "clawpwn.ai.nli.agent.loop.run_agent_loop",
                return_value={"success": True, "response": "Ports: 22, 80, 443, 3306"},
            ) as mock_loop,
            patch(
                "clawpwn.ai.nli.agent.plan_executor.run_plan_executor",
            ) as mock_plan,
        ):
            result = agent.run("list all the detected ports")

        # Agent loop was called, NOT the plan executor
        mock_loop.assert_called_once()
        mock_plan.assert_not_called()
        assert result["success"] is True

        # The system prompt passed to the agent loop contains port data
        call_kwargs = mock_loop.call_args
        system_prompt = call_kwargs.kwargs.get(
            "system_prompt", call_kwargs[1].get("system_prompt", "")
        )
        assert "22" in system_prompt
        assert "3306" in system_prompt

    def test_scan_request_still_routes_to_plan_executor(
        self,
        project_dir: Path,
    ) -> None:
        """'scan ports 1-1000' must still route to plan executor, not conversational."""
        from clawpwn.ai.nli.agent import ToolUseAgent

        llm = Mock()
        llm.provider = "anthropic"
        llm.chat.return_value = "plan_execute"
        agent = ToolUseAgent(llm, project_dir)

        with (
            patch(
                "clawpwn.ai.nli.agent.loop.run_agent_loop",
            ) as mock_loop,
            patch(
                "clawpwn.ai.nli.agent.plan_executor.run_plan_executor",
                return_value={"success": True, "response": "Scan started"},
            ) as mock_plan,
        ):
            result = agent.run("scan ports 1-1000")

        mock_plan.assert_called_once()
        mock_loop.assert_not_called()
        assert result["success"] is True
