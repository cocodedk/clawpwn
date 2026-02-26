"""Tests for the autopilot (autonomous recon) module."""

from pathlib import Path
from unittest.mock import Mock, patch

from clawpwn.ai.nli.agent.autopilot import AutopilotReport, run_autopilot
from clawpwn.ai.nli.agent.autopilot_helpers import (
    _parse_follow_up,
    attach_context,
    build_final_summary,
    build_system_prompt,
    clear_plan,
    cycle_message,
    filter_recon_tools,
    fmt_duration,
    should_continue,
)
from clawpwn.ai.nli.agent.autopilot_prompt import (
    AUTOPILOT_SYSTEM_PROMPT,
    FOLLOW_UP_DECISION_PROMPT,
)

# ---------------------------------------------------------------------------
# AutopilotReport dataclass
# ---------------------------------------------------------------------------


class TestAutopilotReport:
    def test_defaults(self):
        r = AutopilotReport()
        assert r.cycles == 0
        assert r.duration_seconds == 0.0
        assert r.cycle_summaries == []
        assert r.final_summary == ""

    def test_mutable_summaries(self):
        r = AutopilotReport()
        r.cycle_summaries.append("cycle 1 done")
        r.cycles = 1
        assert len(r.cycle_summaries) == 1


# ---------------------------------------------------------------------------
# filter_recon_tools
# ---------------------------------------------------------------------------


class TestFilterReconTools:
    def test_removes_credential_test(self):
        tools = [
            {"name": "fingerprint_target"},
            {"name": "credential_test"},
            {"name": "web_scan"},
        ]
        result = filter_recon_tools(tools)
        names = [t["name"] for t in result]
        assert "credential_test" not in names
        assert "fingerprint_target" in names
        assert "web_scan" in names

    def test_removes_run_custom_script(self):
        tools = [
            {"name": "run_custom_script"},
            {"name": "network_scan"},
        ]
        result = filter_recon_tools(tools)
        names = [t["name"] for t in result]
        assert "run_custom_script" not in names
        assert "network_scan" in names

    def test_keeps_all_recon_tools(self):
        tools = [
            {"name": "fingerprint_target"},
            {"name": "web_scan"},
            {"name": "network_scan"},
            {"name": "discover_hosts"},
            {"name": "web_search"},
            {"name": "research_vulnerabilities"},
            {"name": "save_plan"},
            {"name": "update_plan_step"},
        ]
        result = filter_recon_tools(tools)
        assert len(result) == len(tools)

    def test_uses_get_all_tools_when_none(self):
        with patch(
            "clawpwn.ai.nli.agent.autopilot_helpers.get_all_tools",
            return_value=[{"name": "web_scan"}, {"name": "credential_test"}],
        ):
            result = filter_recon_tools()
            assert len(result) == 1
            assert result[0]["name"] == "web_scan"

    def test_empty_list(self):
        assert filter_recon_tools([]) == []


# ---------------------------------------------------------------------------
# fmt_duration
# ---------------------------------------------------------------------------


class TestFmtDuration:
    def test_seconds_only(self):
        assert fmt_duration(45) == "0m 45s"

    def test_minutes_and_seconds(self):
        assert fmt_duration(125) == "2m 5s"

    def test_hours(self):
        assert fmt_duration(3661) == "1h 1m 1s"

    def test_zero(self):
        assert fmt_duration(0) == "0m 0s"


# ---------------------------------------------------------------------------
# _parse_follow_up
# ---------------------------------------------------------------------------


class TestParseFollowUp:
    def test_valid_json_continue_true(self):
        text = '{"continue": true, "focus": "test port 8080"}'
        cont, focus = _parse_follow_up(text)
        assert cont is True
        assert focus == "test port 8080"

    def test_valid_json_continue_false(self):
        text = '{"continue": false, "focus": ""}'
        cont, focus = _parse_follow_up(text)
        assert cont is False

    def test_json_embedded_in_text(self):
        text = 'Based on the results, {"continue": true, "focus": "SSH on port 22"} is my answer.'
        cont, focus = _parse_follow_up(text)
        assert cont is True
        assert focus == "SSH on port 22"

    def test_garbage_returns_false(self):
        cont, focus = _parse_follow_up("I don't know what to say")
        assert cont is False
        assert focus == ""

    def test_empty_string(self):
        cont, focus = _parse_follow_up("")
        assert cont is False

    def test_missing_continue_key(self):
        text = '{"focus": "something"}'
        cont, focus = _parse_follow_up(text)
        assert cont is False

    def test_mock_returns_mock_not_string(self):
        """Mock() is not a string — _parse_follow_up converts via str()."""
        cont, focus = _parse_follow_up(str(Mock()))
        assert cont is False


# ---------------------------------------------------------------------------
# cycle_message
# ---------------------------------------------------------------------------


class TestCycleMessage:
    def test_cycle_zero(self):
        report = AutopilotReport()
        msg = cycle_message(0, report)
        assert "comprehensive reconnaissance" in msg
        assert "fingerprint" in msg

    def test_subsequent_cycle_includes_focus(self):
        report = AutopilotReport(cycle_summaries=["Found open port 22"])
        report._next_focus = "SSH service on port 22"  # type: ignore[attr-defined]
        msg = cycle_message(1, report)
        assert "SSH service on port 22" in msg
        assert "Found open port 22" in msg

    def test_subsequent_cycle_no_focus(self):
        report = AutopilotReport(cycle_summaries=["summary"])
        msg = cycle_message(1, report)
        assert "Continue recon" in msg


# ---------------------------------------------------------------------------
# build_system_prompt
# ---------------------------------------------------------------------------


class TestBuildSystemPrompt:
    def test_contains_recon_framing(self):
        with (
            patch(
                "clawpwn.ai.nli.agent.autopilot_helpers.format_availability_report",
                return_value="all ok",
            ),
            patch(
                "clawpwn.ai.nli.agent.autopilot_helpers.format_speed_table",
                return_value="speed info",
            ),
        ):
            prompt = build_system_prompt()
        assert "AUTOPILOT recon mode" in prompt
        assert "No exploitation" in prompt
        assert "speed info" in prompt

    def test_no_exploitation_references(self):
        with (
            patch(
                "clawpwn.ai.nli.agent.autopilot_helpers.format_availability_report", return_value=""
            ),
            patch("clawpwn.ai.nli.agent.autopilot_helpers.format_speed_table", return_value=""),
        ):
            prompt = build_system_prompt()
        assert "credential_test" not in prompt.lower()
        assert "run_custom_script" not in prompt.lower()
        assert "brute-force" not in prompt.lower() or "no credential brute-force" in prompt.lower()


# ---------------------------------------------------------------------------
# attach_context
# ---------------------------------------------------------------------------


class TestAttachContext:
    def test_appends_context(self):
        with patch(
            "clawpwn.ai.nli.agent.autopilot_helpers.get_project_context",
            return_value="Target: http://example.com",
        ):
            result = attach_context("base prompt", Path("/fake"))
        assert result.startswith("base prompt")
        assert "Target: http://example.com" in result

    def test_no_context(self):
        with patch(
            "clawpwn.ai.nli.agent.autopilot_helpers.get_project_context",
            return_value="",
        ):
            result = attach_context("base prompt", Path("/fake"))
        assert result == "base prompt"


# ---------------------------------------------------------------------------
# build_final_summary
# ---------------------------------------------------------------------------


class TestBuildFinalSummary:
    def test_single_cycle(self):
        report = AutopilotReport(cycles=1, duration_seconds=60, cycle_summaries=["Found XSS"])
        summary = build_final_summary(report)
        assert "1 cycle(s)" in summary
        assert "--- Cycle 1 ---" in summary
        assert "Found XSS" in summary

    def test_multiple_cycles(self):
        report = AutopilotReport(
            cycles=3,
            duration_seconds=600,
            cycle_summaries=["c1", "c2", "c3"],
        )
        summary = build_final_summary(report)
        assert "3 cycle(s)" in summary
        assert "--- Cycle 3 ---" in summary


# ---------------------------------------------------------------------------
# clear_plan
# ---------------------------------------------------------------------------


class TestClearPlan:
    def test_clears_when_db_exists(self, project_dir, initialized_db):
        from clawpwn.modules.session import SessionManager

        session = SessionManager(initialized_db)
        session.create_project(str(project_dir))
        session.save_plan(["Step 1: fingerprint"])
        assert session.get_plan()

        # Lazy import inside clear_plan — patch at the source module.
        with patch("clawpwn.config.get_project_db_path", return_value=initialized_db):
            clear_plan(project_dir)

        session2 = SessionManager(initialized_db)
        assert not session2.get_plan()

    def test_no_error_on_missing_db(self, tmp_path):
        clear_plan(tmp_path / "nonexistent")


# ---------------------------------------------------------------------------
# should_continue
# ---------------------------------------------------------------------------


class TestShouldContinue:
    def test_returns_true_when_llm_says_continue(self, project_dir, initialized_db):
        from clawpwn.modules.session import SessionManager

        session = SessionManager(initialized_db)
        session.create_project(str(project_dir))
        session.set_target("http://example.com")

        llm = Mock()
        llm.routing_model = "haiku"
        llm.chat = Mock(return_value='{"continue": true, "focus": "port 443"}')

        # Lazy import — patch at the source module, not the calling module.
        with patch("clawpwn.config.get_project_db_path", return_value=initialized_db):
            cont, focus = should_continue(llm, "Found open ports", project_dir)

        assert cont is True
        assert focus == "port 443"
        llm.chat.assert_called_once()

    def test_returns_false_when_llm_says_stop(self, project_dir, initialized_db):
        llm = Mock()
        llm.routing_model = "haiku"
        llm.chat = Mock(return_value='{"continue": false, "focus": ""}')

        with patch("clawpwn.config.get_project_db_path", return_value=initialized_db):
            cont, _ = should_continue(llm, "All surfaces tested", project_dir)

        assert cont is False

    def test_mock_response_defaults_to_false(self, project_dir, initialized_db):
        """Mock() is not a string — should_continue safely returns False."""
        llm = Mock()
        llm.routing_model = None
        # llm.chat returns Mock() (not a string)

        with patch("clawpwn.config.get_project_db_path", return_value=initialized_db):
            cont, _ = should_continue(llm, "summary", project_dir)

        assert cont is False


# ---------------------------------------------------------------------------
# Prompt constants
# ---------------------------------------------------------------------------


class TestPromptConstants:
    def test_system_prompt_has_placeholders(self):
        assert "{speed_table}" in AUTOPILOT_SYSTEM_PROMPT
        assert "{tool_status}" in AUTOPILOT_SYSTEM_PROMPT

    def test_follow_up_prompt_has_placeholders(self):
        assert "{target}" in FOLLOW_UP_DECISION_PROMPT
        assert "{summary}" in FOLLOW_UP_DECISION_PROMPT

    def test_system_prompt_recon_only(self):
        assert "reconnaissance" in AUTOPILOT_SYSTEM_PROMPT.lower()
        assert "no exploitation" in AUTOPILOT_SYSTEM_PROMPT.lower()


# ---------------------------------------------------------------------------
# run_autopilot (integration-level with mocks)
# ---------------------------------------------------------------------------


class TestRunAutopilot:
    def _make_plan_result(self, text="Scan complete. Found 2 vulns."):
        return {"success": True, "text": text, "action": "scan"}

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.should_continue", return_value=(False, ""))
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_single_cycle_stops_on_no_continue(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_cont,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        report = run_autopilot(llm, project_dir, max_cycles=3, console=console)

        assert report.cycles == 1
        assert len(report.cycle_summaries) == 1
        assert "Scan complete" in report.cycle_summaries[0]
        mock_exec.assert_called_once()

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.should_continue")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_multiple_cycles(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_cont,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        # Continue after cycle 1, stop after cycle 2.
        mock_cont.side_effect = [(True, "test port 8080"), (False, "")]
        llm = Mock()
        console = Mock()

        report = run_autopilot(llm, project_dir, max_cycles=5, console=console)

        assert report.cycles == 2
        assert mock_exec.call_count == 2

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_max_cycles_enforced(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        report = run_autopilot(llm, project_dir, max_cycles=1, console=console)

        assert report.cycles == 1
        # Should NOT call should_continue when max_cycles reached.
        mock_exec.assert_called_once()

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    @patch("time.monotonic")
    def test_duration_limit(
        self,
        mock_time,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        # First call returns 0 (start), second returns past the limit.
        mock_time.side_effect = [0.0, 7201.0, 7201.0]
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        report = run_autopilot(
            llm,
            project_dir,
            max_cycles=5,
            max_duration_hours=2.0,
            console=console,
        )

        assert report.cycles == 0
        mock_exec.assert_not_called()

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_replace_plan_always_true(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        run_autopilot(llm, project_dir, max_cycles=1, console=console)

        call_kwargs = mock_exec.call_args[1]
        assert call_kwargs["replace_plan"] is True

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_verbose_passes_progress_cb(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        run_autopilot(llm, project_dir, max_cycles=1, verbose=True, console=console)

        call_kwargs = mock_exec.call_args[1]
        assert call_kwargs["on_progress"] is not None
        assert call_kwargs["debug"] is True

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_non_verbose_no_progress_cb(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result()
        llm = Mock()
        console = Mock()

        run_autopilot(llm, project_dir, max_cycles=1, verbose=False, console=console)

        call_kwargs = mock_exec.call_args[1]
        assert call_kwargs["on_progress"] is None
        assert call_kwargs["debug"] is False

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.should_continue", return_value=(False, ""))
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_final_summary_populated(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        _cont,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = self._make_plan_result("Vuln report")
        llm = Mock()
        console = Mock()

        report = run_autopilot(llm, project_dir, max_cycles=3, console=console)

        assert report.final_summary
        assert "1 cycle(s)" in report.final_summary
        assert "Vuln report" in report.final_summary
        assert report.duration_seconds > 0 or report.duration_seconds == 0

    @patch("clawpwn.ai.nli.agent.autopilot.run_plan_executor")
    @patch("clawpwn.ai.nli.agent.autopilot.clear_plan")
    @patch("clawpwn.ai.nli.agent.autopilot.build_system_prompt", return_value="prompt")
    @patch("clawpwn.ai.nli.agent.autopilot.filter_recon_tools", return_value=[])
    @patch("clawpwn.ai.nli.agent.autopilot.attach_context", return_value="prompt+ctx")
    def test_missing_text_key_uses_fallback(
        self,
        _ctx,
        _tools,
        _prompt,
        _clear,
        mock_exec,
        project_dir,
    ):
        mock_exec.return_value = {"success": True}
        llm = Mock()
        console = Mock()

        report = run_autopilot(llm, project_dir, max_cycles=1, console=console)

        assert report.cycle_summaries[0] == "No summary available."
