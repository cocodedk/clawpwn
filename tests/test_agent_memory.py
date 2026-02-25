"""Tests for agent action memory features."""

import json
from pathlib import Path

from clawpwn.db.init import init_db
from clawpwn.modules.session import SessionManager


class TestScanLogging:
    """Test structured logging of scan actions."""

    def test_get_scan_logs_empty(self, session_manager: SessionManager):
        """Test get_scan_logs returns empty list when no logs."""
        session_manager.create_project("/tmp/test_project")

        scan_logs = session_manager.get_scan_logs(limit=10)

        assert scan_logs == []

    def test_get_scan_logs_filters_by_phase(self, session_manager: SessionManager):
        """Test get_scan_logs only returns scan phase logs."""
        session_manager.create_project("/tmp/test_project")

        # Add a scan log
        session_manager.add_log(
            message="web_scan: sqlmap [sqli] depth=deep -> 0 findings",
            level="INFO",
            phase="scan",
            details=json.dumps({"tool": "web_scan", "target": "http://example.com"}),
        )

        # Add a non-scan log
        session_manager.add_log(
            message="Some other action",
            level="INFO",
            phase="exploit",
            details="",
        )

        scan_logs = session_manager.get_scan_logs(limit=10)

        assert len(scan_logs) == 1
        assert scan_logs[0].phase == "scan"
        assert "web_scan" in scan_logs[0].message

    def test_get_scan_logs_filters_by_details(self, session_manager: SessionManager):
        """Test get_scan_logs only returns logs with non-empty details."""
        session_manager.create_project("/tmp/test_project")

        # Add log with details
        session_manager.add_log(
            message="web_scan: sqlmap [sqli] depth=deep -> 0 findings",
            level="INFO",
            phase="scan",
            details=json.dumps({"tool": "web_scan"}),
        )

        # Add log without details
        session_manager.add_log(
            message="Some scan message",
            level="INFO",
            phase="scan",
            details="",
        )

        scan_logs = session_manager.get_scan_logs(limit=10)

        assert len(scan_logs) == 1
        assert scan_logs[0].details != ""

    def test_get_scan_logs_respects_limit(self, session_manager: SessionManager):
        """Test get_scan_logs respects the limit parameter."""
        session_manager.create_project("/tmp/test_project")

        # Add 15 scan logs
        for i in range(15):
            session_manager.add_log(
                message=f"scan_{i}",
                level="INFO",
                phase="scan",
                details=json.dumps({"tool": "web_scan", "index": i}),
            )

        scan_logs = session_manager.get_scan_logs(limit=5)

        assert len(scan_logs) == 5

    def test_get_scan_logs_returns_recent_first(self, session_manager: SessionManager):
        """Test get_scan_logs returns most recent logs first."""
        session_manager.create_project("/tmp/test_project")

        # Add logs in order
        for i in range(3):
            session_manager.add_log(
                message=f"scan_{i}",
                level="INFO",
                phase="scan",
                details=json.dumps({"tool": "web_scan", "index": i}),
            )

        scan_logs = session_manager.get_scan_logs(limit=10)

        # Parse details to check order
        indices = [json.loads(log.details)["index"] for log in scan_logs]
        assert indices == [2, 1, 0]  # Most recent first

    def test_scan_log_structure(self, session_manager: SessionManager):
        """Test scan log contains expected structure."""
        session_manager.create_project("/tmp/test_project")

        details_data = {
            "tool": "web_scan",
            "tools_used": ["sqlmap", "nuclei"],
            "categories": ["sqli", "xss"],
            "depth": "deep",
            "target": "http://example.com",
            "findings_count": 5,
        }

        session_manager.add_log(
            message="web_scan: sqlmap,nuclei [sqli,xss] depth=deep -> 5 findings",
            level="INFO",
            phase="scan",
            details=json.dumps(details_data),
        )

        scan_logs = session_manager.get_scan_logs(limit=1)

        assert len(scan_logs) == 1
        log = scan_logs[0]
        assert log.message.startswith("web_scan")
        assert log.level == "INFO"
        assert log.phase == "scan"

        parsed_details = json.loads(log.details)
        assert parsed_details["tool"] == "web_scan"
        assert parsed_details["tools_used"] == ["sqlmap", "nuclei"]
        assert parsed_details["target"] == "http://example.com"
        assert parsed_details["findings_count"] == 5


class TestFindingsByAttackType:
    """Test grouping findings by attack type."""

    def test_get_findings_by_attack_type_empty(self, session_manager: SessionManager):
        """Test get_findings_by_attack_type returns empty dict when no findings."""
        session_manager.create_project("/tmp/test_project")

        findings_by_type = session_manager.get_findings_by_attack_type()

        assert findings_by_type == {}

    def test_get_findings_by_attack_type_single_type(self, session_manager: SessionManager):
        """Test grouping findings of a single attack type."""
        session_manager.create_project("/tmp/test_project")

        # Add two SQLi findings
        session_manager.add_finding(
            title="SQL Injection in login",
            severity="high",
            attack_type="sqli",
        )
        session_manager.add_finding(
            title="SQL Injection in search",
            severity="medium",
            attack_type="sqli",
        )

        findings_by_type = session_manager.get_findings_by_attack_type()

        assert "sqli" in findings_by_type
        assert len(findings_by_type["sqli"]) == 2
        assert findings_by_type["sqli"][0].title == "SQL Injection in search"  # Most recent first
        assert findings_by_type["sqli"][1].title == "SQL Injection in login"

    def test_get_findings_by_attack_type_multiple_types(self, session_manager: SessionManager):
        """Test grouping findings of multiple attack types."""
        session_manager.create_project("/tmp/test_project")

        # Add various finding types
        session_manager.add_finding(
            title="SQL Injection",
            severity="high",
            attack_type="sqli",
        )
        session_manager.add_finding(
            title="XSS Vulnerability",
            severity="medium",
            attack_type="xss",
        )
        session_manager.add_finding(
            title="Missing Security Headers",
            severity="low",
            attack_type="misconfig",
        )
        session_manager.add_finding(
            title="Another XSS",
            severity="high",
            attack_type="xss",
        )

        findings_by_type = session_manager.get_findings_by_attack_type()

        assert len(findings_by_type) == 3
        assert "sqli" in findings_by_type
        assert "xss" in findings_by_type
        assert "misconfig" in findings_by_type
        assert len(findings_by_type["sqli"]) == 1
        assert len(findings_by_type["xss"]) == 2
        assert len(findings_by_type["misconfig"]) == 1

    def test_get_findings_by_attack_type_with_null_attack_type(
        self, session_manager: SessionManager
    ):
        """Test findings with no attack_type are grouped under 'other'."""
        session_manager.create_project("/tmp/test_project")

        session_manager.add_finding(
            title="Unknown Issue",
            severity="low",
            attack_type="",  # Empty string
        )

        findings_by_type = session_manager.get_findings_by_attack_type()

        assert "other" in findings_by_type
        assert len(findings_by_type["other"]) == 1
        assert findings_by_type["other"][0].title == "Unknown Issue"

    def test_findings_ordered_by_recency(self, session_manager: SessionManager):
        """Test findings within each type are ordered by recency."""
        session_manager.create_project("/tmp/test_project")

        # Add findings in a specific order
        session_manager.add_finding(title="First XSS", severity="high", attack_type="xss")
        session_manager.add_finding(title="Second XSS", severity="medium", attack_type="xss")
        session_manager.add_finding(title="Third XSS", severity="low", attack_type="xss")

        findings_by_type = session_manager.get_findings_by_attack_type()

        xss_findings = findings_by_type["xss"]
        assert xss_findings[0].title == "Third XSS"  # Most recent
        assert xss_findings[1].title == "Second XSS"
        assert xss_findings[2].title == "First XSS"  # Oldest


class TestProjectContextEnrichment:
    """Test enriched project context for agent prompts."""

    def test_context_includes_scan_history(self, temp_dir: Path):
        """Test that _get_project_context includes scan history."""
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        # Set up project and add scan logs
        session_manager = SessionManager(db_path)
        session_manager.create_project(str(temp_dir))
        session_manager.set_target("http://example.com")

        session_manager.add_log(
            message="web_scan: sqlmap [sqli] depth=deep -> 0 findings",
            level="INFO",
            phase="scan",
            details=json.dumps(
                {
                    "tool": "web_scan",
                    "tools_used": ["sqlmap"],
                    "categories": ["sqli"],
                    "depth": "deep",
                    "target": "http://example.com",
                    "findings_count": 0,
                }
            ),
        )

        # Create agent and get context
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        # Verify context includes scan history
        assert "Past actions" in context
        assert "web_scan(sqlmap" in context
        assert "http://example.com" in context
        assert "0 findings" in context

    def test_context_includes_findings_summary(self, temp_dir: Path):
        """Test that _get_project_context includes findings grouped by type."""
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        # Set up project and add findings
        session_manager = SessionManager(db_path)
        session_manager.create_project(str(temp_dir))
        session_manager.set_target("http://example.com")

        session_manager.add_finding(
            title="SQL Injection",
            severity="high",
            attack_type="sqli",
        )
        session_manager.add_finding(
            title="Missing Headers",
            severity="medium",
            attack_type="misconfig",
        )

        # Create agent and get context
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        # Verify context includes findings summary
        assert "Existing findings by type" in context
        assert "sqli:" in context
        assert "misconfig:" in context
        assert "SQL Injection" in context or "Missing Headers" in context

    def test_context_without_history_still_works(self, temp_dir: Path):
        """Test that context works even without scan history."""
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        # Set up project with just target
        session_manager = SessionManager(db_path)
        session_manager.create_project(str(temp_dir))
        session_manager.set_target("http://example.com")

        # Create agent and get context
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        # Verify basic context still present
        assert "Active target: http://example.com" in context
        assert "Past actions" not in context  # No history yet

    def test_context_time_formatting(self, temp_dir: Path):
        """Test that scan log timestamps are formatted as human-readable time ago."""
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        # Set up project
        session_manager = SessionManager(db_path)
        session_manager.create_project(str(temp_dir))
        session_manager.set_target("http://example.com")

        # Add a recent scan log
        session_manager.add_log(
            message="web_scan: builtin [all] depth=normal -> 1 findings",
            level="INFO",
            phase="scan",
            details=json.dumps(
                {
                    "tool": "web_scan",
                    "tools_used": ["builtin"],
                    "categories": ["all"],
                    "depth": "normal",
                    "target": "http://example.com",
                    "findings_count": 1,
                }
            ),
        )

        # Create agent and get context
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        # Verify time ago appears (should be "0m ago" or similar for just-added log)
        assert "[0m ago]" in context or "[1m ago]" in context


class TestSystemPromptHistoryAwareness:
    """Test that system prompt includes history awareness instructions."""

    def test_system_prompt_has_history_section(self):
        """Test that SYSTEM_PROMPT_TEMPLATE includes HISTORY AWARENESS section."""
        from clawpwn.ai.nli.agent.prompt import SYSTEM_PROMPT_TEMPLATE

        assert "HISTORY AWARENESS" in SYSTEM_PROMPT_TEMPLATE
        assert "Do NOT repeat the same tool" in SYSTEM_PROMPT_TEMPLATE
        assert "DIFFERENT tool" in SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_instructs_no_repetition(self):
        """Test that prompt specifically instructs against repeating scans."""
        from clawpwn.ai.nli.agent.prompt import SYSTEM_PROMPT_TEMPLATE

        assert "Past actions" in SYSTEM_PROMPT_TEMPLATE
        assert "same tool + category + depth" in SYSTEM_PROMPT_TEMPLATE

    def test_system_prompt_suggests_alternatives(self):
        """Test that prompt suggests trying different approaches."""
        from clawpwn.ai.nli.agent.prompt import SYSTEM_PROMPT_TEMPLATE

        assert "different tool" in SYSTEM_PROMPT_TEMPLATE
        assert "alternative tools/parameters" in SYSTEM_PROMPT_TEMPLATE
        assert "manual" in SYSTEM_PROMPT_TEMPLATE


class TestEndToEndMemory:
    """End-to-end tests for agent memory integration."""

    def test_scan_executor_logs_action(self, temp_dir: Path):
        """Test that scan executors actually log their actions."""
        from unittest.mock import patch

        from clawpwn.ai.nli.tool_executors.scan_executors import execute_web_scan
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        session = SessionManager(db_path)
        session.create_project(str(temp_dir))

        # Mock the scan orchestrator to avoid actual scanning
        with patch("clawpwn.utils.async_utils.safe_async_run") as mock_run:
            mock_run.return_value = ([], [])  # No findings, no errors

            # Execute a scan
            execute_web_scan(
                {
                    "target": "http://example.com",
                    "depth": "deep",
                    "vuln_categories": ["sqli"],
                    "tools": ["sqlmap"],
                },
                temp_dir,
            )

        # Verify log was created
        scan_logs = session.get_scan_logs(limit=10)
        assert len(scan_logs) == 1

        log = scan_logs[0]
        assert log.phase == "scan"
        assert "web_scan" in log.message

        details = json.loads(log.details)
        assert details["tool"] == "web_scan"
        assert details["target"] == "http://example.com"
        assert details["depth"] == "deep"
        assert "sqli" in details["categories"]

    def test_multiple_scans_build_history(self, temp_dir: Path):
        """Test that multiple scans create a history that agent can see."""
        from unittest.mock import patch

        from clawpwn.ai.nli.tool_executors.scan_executors import execute_web_scan
        from clawpwn.db.init import init_db
        from clawpwn.modules.session import SessionManager

        # Initialize database
        db_path = temp_dir / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_db(db_path)

        session = SessionManager(db_path)
        session.create_project(str(temp_dir))
        session.set_target("http://example.com")

        # Mock scanning
        with patch("clawpwn.utils.async_utils.safe_async_run") as mock_run:
            mock_run.return_value = ([], [])

            # Execute multiple scans
            execute_web_scan(
                {"target": "http://example.com", "depth": "normal", "tools": ["builtin"]},
                temp_dir,
            )
            execute_web_scan(
                {
                    "target": "http://example.com",
                    "depth": "deep",
                    "tools": ["sqlmap"],
                    "vuln_categories": ["sqli"],
                },
                temp_dir,
            )

        # Check agent sees the history
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)

        assert "Past actions" in context
        assert context.count("web_scan") >= 2  # Both scans should appear
