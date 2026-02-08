"""Tests for the code-driven plan executor."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from clawpwn.ai.nli.agent.plan_helpers import (
    classify_intent,
    is_llm_dependent_step,
    needs_revision,
    step_to_dispatch_params,
)

# ---------------------------------------------------------------------------
# classify_intent
# ---------------------------------------------------------------------------


class TestClassifyIntent:
    """Test intent classification routing."""

    def test_pending_plan_bypasses_llm(self) -> None:
        llm = Mock()
        result = classify_intent(llm, "scan the target", has_pending_plan=True)
        assert result == "plan_execute"
        llm.chat.assert_not_called()

    def test_scan_message_classified_as_plan_execute(self) -> None:
        llm = Mock()
        llm.chat.return_value = "plan_execute"
        result = classify_intent(llm, "scan the target", has_pending_plan=False)
        assert result == "plan_execute"

    def test_conversational_message(self) -> None:
        llm = Mock()
        llm.chat.return_value = "conversational"
        result = classify_intent(llm, "what did you find?", has_pending_plan=False)
        assert result == "conversational"

    def test_llm_returns_non_string_defaults_conversational(self) -> None:
        llm = Mock()
        llm.chat.return_value = 42
        result = classify_intent(llm, "scan", has_pending_plan=False)
        assert result == "conversational"

    def test_llm_exception_defaults_conversational(self) -> None:
        llm = Mock()
        llm.chat.side_effect = RuntimeError("API error")
        result = classify_intent(llm, "scan", has_pending_plan=False)
        assert result == "conversational"

    def test_mock_llm_returns_mock_defaults_conversational(self) -> None:
        """Ensure plain Mock() (no return_value) doesn't accidentally match."""
        llm = Mock()
        # llm.chat() returns a Mock, not a string
        result = classify_intent(llm, "scan", has_pending_plan=False)
        assert result == "conversational"


# ---------------------------------------------------------------------------
# step_to_dispatch_params
# ---------------------------------------------------------------------------


class TestStepToDispatchParams:
    """Test mapping plan steps to dispatch_tool parameters."""

    def test_web_scan_sqlmap(self) -> None:
        name, params = step_to_dispatch_params("web_scan:sqlmap", "http://target/", {})
        assert name == "web_scan"
        assert params["target"] == "http://target/"
        assert params["tools"] == ["sqlmap"]
        assert params["depth"] == "deep"

    def test_web_scan_builtin(self) -> None:
        name, params = step_to_dispatch_params("web_scan:builtin", "http://target/", {})
        assert name == "web_scan"
        assert params["tools"] == ["builtin"]

    def test_web_scan_with_categories(self) -> None:
        name, params = step_to_dispatch_params(
            "web_scan:nuclei", "http://target/", {"vuln_categories": ["sqli", "xss"]}
        )
        assert name == "web_scan"
        assert params["vuln_categories"] == ["sqli", "xss"]

    def test_network_scan_deep(self) -> None:
        name, params = step_to_dispatch_params("network_scan:deep", "192.168.1.10", {})
        assert name == "network_scan"
        assert params["target"] == "192.168.1.10"
        assert params["depth"] == "deep"

    def test_network_scan_quick(self) -> None:
        name, params = step_to_dispatch_params("network_scan:quick", "192.168.1.10", {})
        assert name == "network_scan"
        assert params["depth"] == "quick"

    def test_credential_test_default(self) -> None:
        name, params = step_to_dispatch_params(
            "credential_test", "http://target/login", {"app_hint": "phpmyadmin"}
        )
        assert name == "credential_test"
        assert params["target"] == "http://target/login"
        assert params["app_hint"] == "phpmyadmin"

    def test_credential_test_hydra(self) -> None:
        name, params = step_to_dispatch_params("credential_test:hydra", "http://target/login", {})
        assert name == "credential_test"
        assert params["tool"] == "hydra"

    def test_fingerprint_target(self) -> None:
        name, params = step_to_dispatch_params("fingerprint_target", "http://target/", {})
        assert name == "fingerprint_target"
        assert params["target"] == "http://target/"

    def test_web_search(self) -> None:
        name, params = step_to_dispatch_params(
            "web_search", "http://target/", {"search_query": "CVE phpmyadmin"}
        )
        assert name == "web_search"
        assert params["query"] == "CVE phpmyadmin"

    def test_web_search_default_query(self) -> None:
        name, params = step_to_dispatch_params("web_search", "http://target/", {})
        assert name == "web_search"
        assert "target" in params["query"]

    def test_research_vulnerabilities(self) -> None:
        name, params = step_to_dispatch_params(
            "research_vulnerabilities", "http://target/", {"techs": ["php", "apache"]}
        )
        assert name == "research_vulnerabilities"
        assert params["technologies"] == ["php", "apache"]

    def test_discover_hosts(self) -> None:
        name, params = step_to_dispatch_params("discover_hosts", "192.168.1.0/24", {})
        assert name == "discover_hosts"
        assert params["network"] == "192.168.1.0/24"

    def test_run_custom_script(self) -> None:
        name, params = step_to_dispatch_params(
            "run_custom_script", "http://target/", {"script": "echo test"}
        )
        assert name == "run_custom_script"
        assert params["script"] == "echo test"

    def test_suggest_tools(self) -> None:
        name, params = step_to_dispatch_params("suggest_tools", "http://target/", {})
        assert name == "suggest_tools"

    def test_unknown_tool_fallback(self) -> None:
        name, params = step_to_dispatch_params("unknown_tool", "http://target/", {})
        assert name == "unknown_tool"
        assert params["target"] == "http://target/"


# ---------------------------------------------------------------------------
# needs_revision
# ---------------------------------------------------------------------------


class TestNeedsRevision:
    """Test plan revision trigger logic."""

    def test_empty_results(self) -> None:
        assert needs_revision([]) is False

    def test_all_success(self) -> None:
        results = [{"failed": False}, {"failed": False}, {"failed": False}]
        assert needs_revision(results) is False

    def test_majority_failure(self) -> None:
        results = [{"failed": True}, {"failed": True}, {"failed": False}]
        assert needs_revision(results) is True

    def test_half_failure(self) -> None:
        results = [{"failed": True}, {"failed": False}]
        assert needs_revision(results) is True

    def test_stop_and_replan_policy(self) -> None:
        results = [{"failed": False, "policy_action": "stop_and_replan"}]
        assert needs_revision(results) is True

    def test_stop_policy(self) -> None:
        results = [{"failed": False, "policy_action": "stop"}]
        assert needs_revision(results) is True

    def test_continue_policy_no_failures(self) -> None:
        results = [{"failed": False, "policy_action": "continue"}]
        assert needs_revision(results) is False


# ---------------------------------------------------------------------------
# is_llm_dependent_step
# ---------------------------------------------------------------------------


class TestIsLLMDependentStep:
    """Test LLM dependency detection."""

    def test_run_custom_script_is_dependent(self) -> None:
        assert is_llm_dependent_step("run_custom_script") is True

    def test_suggest_tools_is_dependent(self) -> None:
        assert is_llm_dependent_step("suggest_tools") is True

    def test_web_scan_is_not_dependent(self) -> None:
        assert is_llm_dependent_step("web_scan:sqlmap") is False

    def test_fingerprint_is_not_dependent(self) -> None:
        assert is_llm_dependent_step("fingerprint_target") is False

    def test_credential_test_is_not_dependent(self) -> None:
        assert is_llm_dependent_step("credential_test") is False


# ---------------------------------------------------------------------------
# Plan executor integration
# ---------------------------------------------------------------------------


def _make_tool_use_block(name: str, tool_input: dict, tool_id: str = "toolu_1"):
    return SimpleNamespace(type="tool_use", name=name, input=tool_input, id=tool_id)


def _make_text_block(text: str):
    return SimpleNamespace(type="text", text=text)


def _make_response(content: list):
    return SimpleNamespace(content=content, stop_reason="tool_use", model="test")


class TestExecuteTier:
    """Test parallel tier execution with mocked dispatch."""

    def test_parallel_execution_collects_results(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_runner import execute_tier_parallel

        session_manager.create_project(str(project_dir))
        session_manager.save_plan(
            [
                {"description": "Fingerprint", "tool": "fingerprint_target"},
                {"description": "Web search", "tool": "web_search"},
            ]
        )

        steps = [
            {"step_number": 1, "description": "Fingerprint", "tool": "fingerprint_target"},
            {"step_number": 2, "description": "Web search", "tool": "web_search"},
        ]

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Result: all good",
        ):
            results = execute_tier_parallel(
                steps,
                "http://target/",
                {},
                project_dir,
                session_manager,
                emit=lambda msg: None,
                progress=[],
            )

        assert len(results) == 2
        assert all(not r["failed"] for r in results)

    def test_failed_dispatch_marked_as_failed(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_runner import execute_tier_parallel

        session_manager.create_project(str(project_dir))
        session_manager.save_plan(
            [
                {"description": "Bad scan", "tool": "web_scan:sqlmap"},
            ]
        )

        steps = [
            {"step_number": 1, "description": "Bad scan", "tool": "web_scan:sqlmap"},
        ]

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Tool 'web_scan' failed: connection refused",
        ):
            results = execute_tier_parallel(
                steps,
                "http://target/",
                {},
                project_dir,
                session_manager,
                emit=lambda msg: None,
                progress=[],
            )

        assert len(results) == 1
        assert results[0]["failed"] is True


class TestRunPlanExecutor:
    """End-to-end plan executor tests with mocked LLM and dispatch."""

    def test_full_flow_generates_and_executes_plan(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/phpmyadmin/")

        # Mock LLM
        llm = Mock()
        llm.model = "claude-sonnet-4-5-20250929"

        # generate_plan call returns save_plan tool use
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

        # summarize_results call
        llm.chat = Mock(return_value="Summary: 2 vulnerabilities found")

        tools = [
            {
                "name": "save_plan",
                "description": "test",
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }
        ]

        with patch(
            "clawpwn.ai.nli.agent.plan_runner.dispatch_tool",
            return_value="Finding: SQLi in login form",
        ):
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=tools,
                system_prompt="You are a pentester",
                user_message="scan the target",
            )

        assert result["success"] is True
        assert "Summary" in result["response"] or "vulnerabilities" in result["response"]

    def test_no_target_returns_error(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
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
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/")

        llm = Mock()
        llm.model = "claude-sonnet-4-5-20250929"

        # LLM doesn't call save_plan — returns text only
        text_response = SimpleNamespace(
            content=[_make_text_block("I'll scan the target")],
            stop_reason="end_turn",
            model="test",
        )
        llm.chat_with_tools = Mock(return_value=text_response)

        tools = [
            {
                "name": "save_plan",
                "description": "test",
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }
        ]

        with patch(
            "clawpwn.ai.nli.agent.executor.run_agent_loop",
            return_value={"success": True, "response": "Fallback to loop"},
        ) as mock_loop:
            result = run_plan_executor(
                llm=llm,
                project_dir=project_dir,
                tools=tools,
                system_prompt="",
                user_message="scan",
            )

        mock_loop.assert_called_once()
        assert result["response"] == "Fallback to loop"


class TestResumeFromPending:
    """Test plan resumption when pending steps exist."""

    def test_resumes_existing_plan(
        self,
        project_dir: Path,
        mock_env_vars: None,
        initialized_db: Path,
        session_manager,
    ) -> None:
        from clawpwn.ai.nli.agent.plan_executor import run_plan_executor

        session_manager.create_project(str(project_dir))
        session_manager.set_target("http://target/")

        # Create a plan with first step done, second pending
        session_manager.save_plan(
            [
                {"description": "Fingerprint", "tool": "fingerprint_target"},
                {"description": "SQLi scan", "tool": "web_scan:sqlmap"},
            ]
        )
        session_manager.update_step_status(1, "done", "Apache/PHP detected")

        llm = Mock()
        llm.model = "claude-sonnet-4-5-20250929"
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


class TestContextEnrichment:
    """Test context extraction from tier results."""

    def test_enrich_detects_phpmyadmin(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "fingerprint_target",
                "result_text": "Server: Apache, Technology: phpMyAdmin 5.2, PHP 8.1",
            }
        ]
        enrich_context(context, results)
        assert context["app_hint"] == "phpmyadmin"
        assert "php" in context["techs"]
        assert "apache" in context["techs"]

    def test_enrich_detects_wordpress(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "fingerprint_target",
                "result_text": "WordPress 6.4 on nginx with MySQL",
            }
        ]
        enrich_context(context, results)
        assert context["app_hint"] == "wordpress"
        assert "nginx" in context["techs"]
        assert "mysql" in context["techs"]

    def test_enrich_no_fingerprint_no_change(self) -> None:
        from clawpwn.ai.nli.agent.plan_runner import enrich_context

        context: dict = {"app_hint": "", "techs": []}
        results = [
            {
                "tool": "web_scan:builtin",
                "result_text": "Found phpMyAdmin vulnerability",
            }
        ]
        enrich_context(context, results)
        # Only fingerprint_target results trigger enrichment
        assert context["app_hint"] == ""


# ---------------------------------------------------------------------------
# Routing integration (ToolUseAgent.run dispatches correctly)
# ---------------------------------------------------------------------------


class TestAgentRouting:
    """Test that ToolUseAgent.run routes to the right executor."""

    def test_conversational_routes_to_agent_loop(
        self,
        project_dir: Path,
        mock_env_vars: None,
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
        mock_env_vars: None,
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
