"""Tests for plan execution optimizations: pruning, early-exit, and concise summaries."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

from clawpwn.ai.nli.agent.plan_optimizers import (
    all_results_empty,
    is_empty_research,
    prune_empty_research,
    should_skip_remaining,
    tier_found_nothing,
)

# ---------------------------------------------------------------------------
# Context filtering by current target
# ---------------------------------------------------------------------------


class TestContextFiltersByTarget:
    """get_project_context only includes scan logs matching the current target."""

    def test_filters_out_logs_from_different_target(self, temp_dir: Path):
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        sm = SessionManager(db_path)
        sm.create_project(str(temp_dir))
        sm.set_target("10.0.0.2")

        # Log from old target
        sm.add_log(
            message="scan old",
            level="INFO",
            phase="scan",
            details=json.dumps(
                {"tool": "network_scan", "target": "10.0.0.1", "open_ports_count": 3}
            ),
        )
        # Log from current target
        sm.add_log(
            message="scan current",
            level="INFO",
            phase="scan",
            details=json.dumps(
                {"tool": "network_scan", "target": "10.0.0.2", "open_ports_count": 5}
            ),
        )

        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        assert "10.0.0.2" in context
        assert "5 ports" in context
        # Old target's log should be filtered out
        assert "10.0.0.1" not in context
        assert "3 ports" not in context


# ---------------------------------------------------------------------------
# Empty research pruning
# ---------------------------------------------------------------------------


class TestPruneEmptyResearch:
    """research_vulnerabilities steps are pruned when no service info exists."""

    def test_removes_research_with_empty_context(self):
        steps = [
            {"tool": "network_scan", "description": "Scan ports"},
            {"tool": "research_vulnerabilities", "description": "Research vulns"},
        ]
        ctx = {"app_hint": "", "techs": [], "vuln_categories": []}
        result = prune_empty_research(steps, ctx)
        assert len(result) == 1
        assert result[0]["tool"] == "network_scan"

    def test_keeps_research_when_context_has_techs(self):
        steps = [
            {"tool": "research_vulnerabilities", "description": "Research vulns"},
        ]
        ctx = {"app_hint": "", "techs": ["Apache/2.4"], "vuln_categories": []}
        result = prune_empty_research(steps, ctx)
        assert len(result) == 1

    def test_keeps_research_when_context_has_app_hint(self):
        steps = [
            {"tool": "research_vulnerabilities", "description": "Research vulns"},
        ]
        ctx = {"app_hint": "WordPress", "techs": [], "vuln_categories": []}
        result = prune_empty_research(steps, ctx)
        assert len(result) == 1

    def test_keeps_non_research_steps(self):
        steps = [
            {"tool": "network_scan", "description": "Scan"},
            {"tool": "web_scan:nikto", "description": "Web scan"},
        ]
        ctx = {"app_hint": "", "techs": [], "vuln_categories": []}
        result = prune_empty_research(steps, ctx)
        assert len(result) == 2

    def test_is_empty_research_false_for_other_tools(self):
        assert not is_empty_research(
            {"tool": "network_scan"}, {"app_hint": "", "techs": [], "vuln_categories": []}
        )


# ---------------------------------------------------------------------------
# Tier early-exit
# ---------------------------------------------------------------------------


class TestTierEarlyExit:
    """Early-exit triggers when scans find nothing and remaining tiers repeat tools."""

    def test_tier_found_nothing_all_empty(self):
        results = [
            {"result_text": "Scan complete: 0 open ports found", "failed": False},
            {"result_text": "Research failed: no data", "failed": False},
        ]
        assert tier_found_nothing(results) is True

    def test_tier_found_nothing_with_findings(self):
        results = [
            {"result_text": "Found 3 open ports: 22, 80, 443", "failed": False},
        ]
        assert tier_found_nothing(results) is False

    def test_tier_found_nothing_with_failure(self):
        results = [
            {"result_text": "0 open ports", "failed": True},
        ]
        assert tier_found_nothing(results) is False

    def test_tier_found_nothing_empty_list(self):
        assert tier_found_nothing([]) is False

    def test_should_skip_when_same_tools(self):
        completed = {"network_scan", "web_scan"}
        remaining = {3: [{"tool": "network_scan:deep"}, {"tool": "web_scan:nikto"}]}
        assert should_skip_remaining(completed, remaining) is True

    def test_should_not_skip_when_new_tool(self):
        completed = {"network_scan"}
        remaining = {3: [{"tool": "network_scan:deep"}, {"tool": "credential_test"}]}
        assert should_skip_remaining(completed, remaining) is False

    def test_empty_remaining_is_vacuously_true(self):
        # No remaining tiers → vacuously true (caller guards with `if remaining`)
        assert should_skip_remaining({"network_scan"}, {}) is True


# ---------------------------------------------------------------------------
# Concise summary for empty results
# ---------------------------------------------------------------------------


class TestAllResultsEmpty:
    """all_results_empty detects when every result indicates nothing found."""

    def test_all_empty(self):
        results = [
            {"result_summary": "Scan complete: 0 open ports found"},
            {"result_summary": "Research failed: no data available"},
        ]
        assert all_results_empty(results) is True

    def test_not_empty_when_findings(self):
        results = [
            {"result_summary": "Found SQL injection in login form"},
        ]
        assert all_results_empty(results) is False

    def test_empty_list(self):
        assert all_results_empty([]) is True

    def test_mixed_results(self):
        results = [
            {"result_summary": "0 open ports"},
            {"result_summary": "Found XSS vulnerability"},
        ]
        assert all_results_empty(results) is False


class TestConciseSummaryPrompt:
    """summarize_results uses a shorter prompt when all results are empty."""

    def test_condensed_prompt_for_empty_results(self):
        from clawpwn.ai.nli.agent.plan_llm_calls import summarize_results

        llm = Mock()
        llm.chat = Mock(return_value="Brief: nothing found, host may be down.")

        results = [
            {
                "step_number": 1,
                "description": "Quick scan",
                "status": "done",
                "result_summary": "0 open ports found",
            },
        ]
        summary = summarize_results(llm, "system", results, "10.0.0.1")

        # Verify the condensed prompt was used (no "manual follow-up steps")
        call_args = llm.chat.call_args[0][0]
        assert "Do NOT list manual commands" in call_args
        assert "manual follow-up" not in call_args
        assert summary == "Brief: nothing found, host may be down."

    def test_full_prompt_when_findings_exist(self):
        from clawpwn.ai.nli.agent.plan_llm_calls import summarize_results

        llm = Mock()
        llm.chat = Mock(return_value="Full report with findings.")

        results = [
            {
                "step_number": 1,
                "description": "SQLi scan",
                "status": "done",
                "result_summary": "Found SQL injection in login form",
            },
        ]
        summarize_results(llm, "system", results, "http://target/")

        call_args = llm.chat.call_args[0][0]
        assert "manual follow-up steps" in call_args
        assert "Do NOT list manual commands" not in call_args
