"""Tests for new tool schemas and registration."""

from clawpwn.ai.nli.tool_executors import TOOL_EXECUTORS
from clawpwn.ai.nli.tools import (
    CREDENTIAL_TEST_TOOL,
    FINGERPRINT_TARGET_TOOL,
    RUN_CUSTOM_SCRIPT_TOOL,
    WEB_SEARCH_TOOL,
    get_all_tools,
)


class TestToolSchemas:
    """Test tool schema definitions."""

    def test_web_search_tool_schema(self):
        """Test WEB_SEARCH_TOOL schema structure."""
        assert WEB_SEARCH_TOOL["name"] == "web_search"
        assert "description" in WEB_SEARCH_TOOL
        assert "input_schema" in WEB_SEARCH_TOOL
        assert "query" in WEB_SEARCH_TOOL["input_schema"]["properties"]
        assert "query" in WEB_SEARCH_TOOL["input_schema"]["required"]

    def test_fingerprint_target_tool_schema(self):
        """Test FINGERPRINT_TARGET_TOOL schema structure."""
        assert FINGERPRINT_TARGET_TOOL["name"] == "fingerprint_target"
        assert "description" in FINGERPRINT_TARGET_TOOL
        assert "target" in FINGERPRINT_TARGET_TOOL["input_schema"]["properties"]
        assert "target" in FINGERPRINT_TARGET_TOOL["input_schema"]["required"]

    def test_credential_test_tool_schema(self):
        """Test CREDENTIAL_TEST_TOOL schema structure."""
        assert CREDENTIAL_TEST_TOOL["name"] == "credential_test"
        assert "description" in CREDENTIAL_TEST_TOOL
        assert "target" in CREDENTIAL_TEST_TOOL["input_schema"]["properties"]
        assert "credentials" in CREDENTIAL_TEST_TOOL["input_schema"]["properties"]
        assert "app_hint" in CREDENTIAL_TEST_TOOL["input_schema"]["properties"]
        assert "target" in CREDENTIAL_TEST_TOOL["input_schema"]["required"]

    def test_run_custom_script_tool_schema(self):
        """Test RUN_CUSTOM_SCRIPT_TOOL schema structure."""
        assert RUN_CUSTOM_SCRIPT_TOOL["name"] == "run_custom_script"
        assert "description" in RUN_CUSTOM_SCRIPT_TOOL
        assert "script" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["properties"]
        assert "description" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["properties"]
        assert "timeout" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["properties"]
        assert "script" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["required"]


class TestToolRegistration:
    """Test tool registration in dispatcher."""

    def test_all_new_tools_in_get_all_tools(self):
        """Test that all new tools are registered in get_all_tools()."""
        all_tools = get_all_tools()
        tool_names = {tool["name"] for tool in all_tools}

        assert "web_search" in tool_names
        assert "fingerprint_target" in tool_names
        assert "credential_test" in tool_names
        assert "run_custom_script" in tool_names

    def test_all_new_tools_have_executors(self):
        """Test that all new tools have executor functions."""
        assert "web_search" in TOOL_EXECUTORS
        assert "fingerprint_target" in TOOL_EXECUTORS
        assert "credential_test" in TOOL_EXECUTORS
        assert "run_custom_script" in TOOL_EXECUTORS

    def test_executor_functions_are_callable(self):
        """Test that all executor functions are callable."""
        assert callable(TOOL_EXECUTORS["web_search"])
        assert callable(TOOL_EXECUTORS["fingerprint_target"])
        assert callable(TOOL_EXECUTORS["credential_test"])
        assert callable(TOOL_EXECUTORS["run_custom_script"])

    def test_get_all_tools_returns_valid_schemas(self):
        """Test that get_all_tools returns valid tool schemas."""
        all_tools = get_all_tools()

        for tool in all_tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "type" in tool["input_schema"]
            assert "properties" in tool["input_schema"]


class TestToolActionMap:
    """Test TOOL_ACTION_MAP updates."""

    def test_tool_action_map_has_new_tools(self):
        """Test that TOOL_ACTION_MAP includes new tools."""
        from clawpwn.ai.nli.agent.prompt import TOOL_ACTION_MAP

        assert "web_search" in TOOL_ACTION_MAP
        assert "fingerprint_target" in TOOL_ACTION_MAP
        assert "credential_test" in TOOL_ACTION_MAP
        assert "run_custom_script" in TOOL_ACTION_MAP

    def test_tool_action_map_values(self):
        """Test that TOOL_ACTION_MAP has correct action labels."""
        from clawpwn.ai.nli.agent.prompt import TOOL_ACTION_MAP

        assert TOOL_ACTION_MAP["web_search"] == "research"
        assert TOOL_ACTION_MAP["fingerprint_target"] == "recon"
        assert TOOL_ACTION_MAP["credential_test"] == "exploit"
        assert TOOL_ACTION_MAP["run_custom_script"] == "exploit"


class TestPromptConstants:
    """Test updated prompt constants."""

    def test_max_tool_rounds_increased(self):
        """Test that MAX_TOOL_ROUNDS was increased."""
        from clawpwn.ai.nli.agent.prompt import MAX_TOOL_ROUNDS

        assert MAX_TOOL_ROUNDS == 8

    def test_analysis_max_tokens_increased(self):
        """Test that ANALYSIS_MAX_TOKENS was increased."""
        from clawpwn.ai.nli.agent.prompt import ANALYSIS_MAX_TOKENS

        assert ANALYSIS_MAX_TOKENS == 4096

    def test_system_prompt_has_methodology(self):
        """Test that system prompt includes pentest methodology."""
        from clawpwn.ai.nli.agent.prompt import SYSTEM_PROMPT_TEMPLATE

        assert "PENTEST METHODOLOGY" in SYSTEM_PROMPT_TEMPLATE
        assert "FINGERPRINT" in SYSTEM_PROMPT_TEMPLATE
        assert "RESEARCH" in SYSTEM_PROMPT_TEMPLATE
        assert "fingerprint_target" in SYSTEM_PROMPT_TEMPLATE
        assert "web_search" in SYSTEM_PROMPT_TEMPLATE
