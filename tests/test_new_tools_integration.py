"""Tests for new tool schemas and registration."""

from clawpwn.ai.nli.tool_executors import TOOL_EXECUTORS
from clawpwn.ai.nli.tools import (
    CREDENTIAL_TEST_TOOL,
    FETCH_URL_TOOL,
    FINGERPRINT_TARGET_TOOL,
    RUN_COMMAND_TOOL,
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
        assert "tool" in CREDENTIAL_TEST_TOOL["input_schema"]["properties"]
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
        assert "user_approved" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["properties"]
        assert "script" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["required"]
        assert "user_approved" in RUN_CUSTOM_SCRIPT_TOOL["input_schema"]["required"]

    def test_fetch_url_tool_schema(self):
        """Test FETCH_URL_TOOL schema structure."""
        assert FETCH_URL_TOOL["name"] == "fetch_url"
        assert "description" in FETCH_URL_TOOL
        props = FETCH_URL_TOOL["input_schema"]["properties"]
        assert "url" in props
        assert "method" in props
        assert "headers" in props
        assert "body" in props
        assert "url" in FETCH_URL_TOOL["input_schema"]["required"]

    def test_run_command_tool_schema(self):
        """Test RUN_COMMAND_TOOL schema structure."""
        assert RUN_COMMAND_TOOL["name"] == "run_command"
        assert "description" in RUN_COMMAND_TOOL
        props = RUN_COMMAND_TOOL["input_schema"]["properties"]
        assert "command" in props
        assert "description" in props
        assert "timeout" in props
        assert "user_approved" in props
        assert "command" in RUN_COMMAND_TOOL["input_schema"]["required"]
        assert "user_approved" in RUN_COMMAND_TOOL["input_schema"]["required"]


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
        assert "fetch_url" in tool_names
        assert "run_command" in tool_names

    def test_all_new_tools_have_executors(self):
        """Test that all new tools have executor functions."""
        assert "web_search" in TOOL_EXECUTORS
        assert "fingerprint_target" in TOOL_EXECUTORS
        assert "credential_test" in TOOL_EXECUTORS
        assert "run_custom_script" in TOOL_EXECUTORS
        assert "fetch_url" in TOOL_EXECUTORS
        assert "run_command" in TOOL_EXECUTORS

    def test_executor_functions_are_callable(self):
        """Test that all executor functions are callable."""
        assert callable(TOOL_EXECUTORS["web_search"])
        assert callable(TOOL_EXECUTORS["fingerprint_target"])
        assert callable(TOOL_EXECUTORS["credential_test"])
        assert callable(TOOL_EXECUTORS["run_custom_script"])
        assert callable(TOOL_EXECUTORS["fetch_url"])
        assert callable(TOOL_EXECUTORS["run_command"])

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
        assert TOOL_ACTION_MAP["fetch_url"] == "recon"
        assert TOOL_ACTION_MAP["run_command"] == "exploit"


class TestPromptConstants:
    """Test updated prompt constants."""

    def test_max_tool_rounds_increased(self):
        """Test that MAX_TOOL_ROUNDS supports exhaustive scanning."""
        from clawpwn.ai.nli.agent.prompt import MAX_TOOL_ROUNDS

        assert MAX_TOOL_ROUNDS == 16

    def test_analysis_max_tokens_increased(self):
        """Test that ANALYSIS_MAX_TOKENS was increased."""
        from clawpwn.ai.nli.agent.prompt import ANALYSIS_MAX_TOKENS

        assert ANALYSIS_MAX_TOKENS == 4096

    def test_system_prompt_has_methodology(self):
        """Test that system prompt includes pentest methodology."""
        from clawpwn.ai.nli.agent.prompt import SYSTEM_PROMPT_TEMPLATE

        assert "PENTEST METHODOLOGY" in SYSTEM_PROMPT_TEMPLATE
        assert "VALIDATION GUARDRAILS" in SYSTEM_PROMPT_TEMPLATE
        assert "FINGERPRINT" in SYSTEM_PROMPT_TEMPLATE
        assert "RESEARCH" in SYSTEM_PROMPT_TEMPLATE
        assert "fingerprint_target" in SYSTEM_PROMPT_TEMPLATE
        assert "web_search" in SYSTEM_PROMPT_TEMPLATE
        assert "fetch_url" in SYSTEM_PROMPT_TEMPLATE
        assert "run_command" in SYSTEM_PROMPT_TEMPLATE


class TestToolMetadataProfiles:
    """Test speed tier profiles for new tools."""

    def test_fetch_url_profile(self):
        from clawpwn.ai.nli.tools.tool_metadata import get_profile

        p = get_profile("fetch_url")
        assert p.speed_tier == 1
        assert p.label == "fast"

    def test_run_command_profile(self):
        from clawpwn.ai.nli.tools.tool_metadata import get_profile

        p = get_profile("run_command")
        assert p.speed_tier == 3
        assert p.label == "slow"

    def test_speed_table_mentions_new_tools(self):
        from clawpwn.ai.nli.tools.tool_metadata import format_speed_table

        table = format_speed_table()
        assert "fetch_url" in table
        assert "run_command" in table

    def test_plan_tool_enum_includes_new_tools(self):
        """save_plan enum accepts fetch_url and run_command."""
        from clawpwn.ai.nli.tools import SAVE_PLAN_TOOL  # noqa: F811

        enum_vals = SAVE_PLAN_TOOL["input_schema"]["properties"]["steps"]["items"]["properties"][
            "tool"
        ]["enum"]
        assert "fetch_url" in enum_vals
        assert "run_command" in enum_vals


class TestAvailabilityRegistry:
    """Test aws CLI registration in availability."""

    def test_aws_in_external_tools(self):
        from clawpwn.ai.nli.tool_executors.availability import EXTERNAL_TOOLS

        assert "aws" in EXTERNAL_TOOLS
        assert EXTERNAL_TOOLS["aws"]["binary"] == "aws"

    def test_aws_in_doctor_optional_tools(self):
        from clawpwn.cli_commands.doctor_checks import OPTIONAL_TOOLS

        assert "aws" in OPTIONAL_TOOLS
