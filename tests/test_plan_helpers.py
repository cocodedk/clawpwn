"""Tests for plan_helpers: intent classification, step mapping, and focused request detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from clawpwn.ai.nli.agent.plan_helpers import (
    build_plan_prompt,
    classify_intent,
    is_focused_request,
    is_llm_dependent_step,
    needs_revision,
    step_to_dispatch_params,
)

# ---------------------------------------------------------------------------
# classify_intent
# ---------------------------------------------------------------------------


class TestClassifyIntent:
    """Test intent classification routing."""

    def test_pending_plan_resume_uses_llm(self) -> None:
        llm = Mock()
        llm.chat.return_value = "plan_resume"
        result = classify_intent(llm, "continue", has_pending_plan=True)
        assert result == "plan_execute"
        llm.chat.assert_called_once()

    def test_pending_plan_new_request(self) -> None:
        llm = Mock()
        llm.chat.return_value = "plan_new"
        result = classify_intent(llm, "scan ports 1-100", has_pending_plan=True)
        assert result == "plan_new"

    def test_pending_plan_conversational(self) -> None:
        llm = Mock()
        llm.chat.return_value = "conversational"
        result = classify_intent(llm, "what did you find?", has_pending_plan=True)
        assert result == "conversational"

    def test_pending_plan_llm_failure_defaults_resume(self) -> None:
        llm = Mock()
        llm.chat.side_effect = RuntimeError("API error")
        result = classify_intent(llm, "scan", has_pending_plan=True)
        assert result == "plan_execute"

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

    def test_result_query_prompt_includes_examples_fresh(self) -> None:
        """Verify _classify_fresh prompt mentions result-query phrases."""
        from clawpwn.ai.nli.agent.intent import _classify_fresh

        llm = Mock()
        llm.chat.return_value = "conversational"
        _classify_fresh(llm, "list all detected ports")
        prompt = llm.chat.call_args[0][0]
        assert "list ports" in prompt
        assert "show findings" in prompt

    def test_result_query_prompt_includes_examples_pending(self) -> None:
        """Verify _classify_with_pending prompt mentions result-query phrases."""
        from clawpwn.ai.nli.agent.intent import _classify_with_pending

        llm = Mock()
        llm.chat.return_value = "conversational"
        _classify_with_pending(llm, "what ports are open")
        prompt = llm.chat.call_args[0][0]
        assert "list ports" in prompt
        assert "show findings" in prompt


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

    def test_research_vulnerabilities_no_services(self) -> None:
        name, params = step_to_dispatch_params(
            "research_vulnerabilities", "http://target/", {"techs": ["php", "apache"]}
        )
        assert name == "research_vulnerabilities"
        assert params["service"] == "http://target/"

    def test_research_vulnerabilities_with_services(self) -> None:
        ctx = {"services": [{"port": 21, "product": "vsftpd 2.3.4"}]}
        name, params = step_to_dispatch_params("research_vulnerabilities", "192.168.1.10", ctx)
        assert name == "research_vulnerabilities"
        assert params["service"] == "vsftpd 2.3.4"

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
# is_focused_request
# ---------------------------------------------------------------------------


class TestIsFocusedRequest:
    """Test detection of specific-tool requests."""

    def test_hydra_is_focused(self) -> None:
        assert is_focused_request("run hydra against ftp on msf2") is True

    def test_sqlmap_is_focused(self) -> None:
        assert is_focused_request("sqlmap the login page") is True

    def test_nmap_is_focused(self) -> None:
        assert is_focused_request("nmap port 21") is True

    def test_nikto_is_focused(self) -> None:
        assert is_focused_request("run nikto against the target") is True

    def test_nuclei_is_focused(self) -> None:
        assert is_focused_request("nuclei scan") is True

    def test_wpscan_is_focused(self) -> None:
        assert is_focused_request("run wpscan") is True

    def test_general_scan_is_not_focused(self) -> None:
        assert is_focused_request("scan the target") is False

    def test_full_assessment_is_not_focused(self) -> None:
        assert is_focused_request("run a full security assessment") is False

    def test_what_did_you_find_is_not_focused(self) -> None:
        assert is_focused_request("what did you find?") is False

    def test_case_insensitive(self) -> None:
        assert is_focused_request("Run HYDRA against FTP") is True


# ---------------------------------------------------------------------------
# build_plan_prompt
# ---------------------------------------------------------------------------


class TestBuildPlanPrompt:
    """Test system prompt selection for plan generation."""

    def test_general_request_keeps_full_prompt(self) -> None:
        result = build_plan_prompt("full system prompt", "scan the target", Path("/tmp"))
        assert result == "full system prompt"

    def test_focused_request_uses_focused_prompt(self) -> None:
        result = build_plan_prompt("full system prompt", "run hydra against ftp", Path("/tmp"))
        assert "full system prompt" not in result
        assert "SPECIFIC tool or action" in result
        assert "EXACTLY what was asked" in result

    def test_focused_prompt_does_not_contain_exhaustive_mandate(self) -> None:
        result = build_plan_prompt("full system prompt", "run sqlmap on login", Path("/tmp"))
        assert "EXHAUSTIVE" not in result
        assert "COVERAGE MANDATE" not in result
