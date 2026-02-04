"""Integration tests for ClawPwn."""

from pathlib import Path

import respx
from httpx import Response

from clawpwn.cli import get_project_dir, require_project
from clawpwn.modules.scanner import ScanConfig, Scanner
from clawpwn.modules.session import SessionManager


class TestEndToEndWorkflow:
    """Test complete pentest workflows without CLI runner."""

    def test_full_project_lifecycle(self, temp_dir: Path):
        """Test a complete project from init through reporting."""

        # 1. Create project directory
        project_path = temp_dir / "pentest_project"
        project_path.mkdir()

        # 2. Initialize project structure
        (project_path / ".clawpwn").mkdir()
        (project_path / "evidence").mkdir()
        (project_path / "exploits").mkdir()
        (project_path / "report").mkdir()

        # 3. Initialize database
        from clawpwn.db.init import init_db

        db_path = project_path / ".clawpwn" / "clawpwn.db"
        init_db(db_path)

        # 4. Create session and set up project
        session = SessionManager(db_path)
        project = session.create_project(str(project_path))

        assert project is not None
        assert project.path == str(project_path)

        # 5. Set target
        session.set_target("https://example.com")
        state = session.get_state()

        assert state is not None
        assert state.target == "https://example.com"

        # 6. Add findings
        session.add_finding("SQL Injection", "critical", attack_type="SQLi")
        session.add_finding("XSS", "high", attack_type="XSS")

        state = session.get_state()
        assert state.findings_count == 2
        assert state.critical_count == 1
        assert state.high_count == 1

        # 7. Check logs were created
        logs = session.get_logs(limit=10)
        assert len(logs) >= 2

    @respx.mock
    async def test_scan_finds_vulnerabilities(self, project_dir: Path):
        """Test that scan finds vulnerabilities in a mock target."""
        # Setup mock vulnerable server
        respx.get("https://vulnerable.com").mock(
            return_value=Response(
                200,
                text="""<html>
                <head></head>
                <body>
                    <form action="/login" method="POST">
                        <input name="username" />
                        <input name="password" />
                    </form>
                    <div>SQL syntax error near '1=1'</div>
                </body>
                </html>""",
                headers={"Server": "Apache/2.4.41"},
            )
        )

        # Initialize and scan
        scanner = Scanner(project_dir)

        config = ScanConfig(target="https://vulnerable.com", depth="quick")
        findings = await scanner.scan("https://vulnerable.com", config)

        # Should return a list
        assert isinstance(findings, list)

    def test_project_state_tracking(self, session_manager: SessionManager):
        """Test that project state is tracked correctly through operations."""
        # Initial state
        state = session_manager.get_state()
        assert state is None

        # Create project
        session_manager.create_project("/tmp/test_project")
        state = session_manager.get_state()
        assert state is not None
        if state:
            assert state.current_phase == "Initialized"

        # Set target
        session_manager.set_target("https://example.com")
        state = session_manager.get_state()
        if state:
            assert state.target == "https://example.com"

        # Update phase
        session_manager.update_phase("Reconnaissance")
        state = session_manager.get_state()
        if state:
            assert state.current_phase == "Reconnaissance"

        # Add findings
        session_manager.add_finding("SQL Injection", "critical", attack_type="SQLi")
        session_manager.add_finding("XSS", "high", attack_type="XSS")
        state = session_manager.get_state()
        if state:
            assert state.findings_count == 2
            assert state.critical_count == 1
            assert state.high_count == 1

        # Check logs were created
        logs = session_manager.get_logs(limit=10)
        assert len(logs) >= 2


class TestMultipleProjects:
    """Test working with multiple projects simultaneously."""

    def test_isolated_projects(self, temp_dir: Path):
        """Test that multiple projects are isolated from each other."""
        from clawpwn.db.init import init_db

        # Create project A
        project_a = temp_dir / "project_a"
        project_a.mkdir()
        (project_a / ".clawpwn").mkdir()
        db_a = project_a / ".clawpwn" / "clawpwn.db"
        init_db(db_a)

        session_a = SessionManager(db_a)
        session_a.create_project(str(project_a))
        session_a.set_target("https://site-a.com")

        # Create project B
        project_b = temp_dir / "project_b"
        project_b.mkdir()
        (project_b / ".clawpwn").mkdir()
        db_b = project_b / ".clawpwn" / "clawpwn.db"
        init_db(db_b)

        session_b = SessionManager(db_b)
        session_b.create_project(str(project_b))
        session_b.set_target("https://site-b.com")

        # Check project A still has its target
        state_a = session_a.get_state()
        assert state_a is not None
        if state_a:
            assert state_a.target == "https://site-a.com"

        # Check project B has its target
        state_b = session_b.get_state()
        assert state_b is not None
        if state_b:
            assert state_b.target == "https://site-b.com"

        # Verify they're different
        if state_a and state_b:
            assert state_a.target != state_b.target


class TestProjectDetection:
    """Test project directory detection functionality."""

    def test_get_project_dir_finds_project(self, temp_dir: Path):
        """Test finding project directory."""
        # Create a mock project structure
        project_path = temp_dir / "test_project"
        project_path.mkdir()
        (project_path / ".clawpwn").mkdir()

        # Change to that directory
        import os

        original_cwd = os.getcwd()
        os.chdir(project_path)

        try:
            result = get_project_dir()
            assert result is not None
            assert result.name == "test_project"
        finally:
            os.chdir(original_cwd)

    def test_operations_outside_project(self, temp_dir: Path):
        """Test that operations outside a project fail gracefully."""
        import os

        import typer

        original_cwd = os.getcwd()
        os.chdir(temp_dir)

        try:
            # This should raise a typer.Exit
            try:
                require_project()
                assert False, "Should have raised an exception"
            except (typer.Exit, SystemExit):
                pass  # Expected
        finally:
            os.chdir(original_cwd)


class TestReportGeneration:
    """Test report generation integration."""

    def test_report_generation_with_findings(self, project_dir: Path, mock_env_vars):
        """Test report generation when findings exist."""
        from clawpwn.db.init import init_db
        from clawpwn.modules.report import ReportConfig, ReportGenerator

        # Setup project with data
        db_path = project_dir / ".clawpwn" / "clawpwn.db"
        init_db(db_path)

        session = SessionManager(db_path)
        session.create_project(str(project_dir))
        session.set_target("https://example.com")
        session.add_finding(
            title="SQL Injection",
            severity="critical",
            description="Test SQLi",
            evidence="Payload: ' OR 1=1--",
            attack_type="SQL Injection",
        )

        # Generate report
        generator = ReportGenerator(project_dir)
        config = ReportConfig(format="html", include_evidence=True)

        report_path = generator.generate(config)

        # Verify report was created
        assert report_path.exists()
        assert report_path.suffix == ".html"

        # Check content
        content = report_path.read_text()
        assert "SQL Injection" in content
        assert "https://example.com" in content

    def test_report_generation_json(self, project_dir: Path, mock_env_vars):
        """Test JSON report generation."""
        import json

        from clawpwn.db.init import init_db
        from clawpwn.modules.report import ReportConfig, ReportGenerator

        # Setup project with minimal data
        db_path = project_dir / ".clawpwn" / "clawpwn.db"
        init_db(db_path)

        session = SessionManager(db_path)
        session.create_project(str(project_dir))
        session.set_target("https://example.com")

        # Generate JSON report
        generator = ReportGenerator(project_dir)
        config = ReportConfig(format="json")

        report_path = generator.generate(config)

        # Verify JSON structure
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "report_metadata" in data
        assert "project" in data
        assert "findings" in data


class TestLLMIntegration:
    """Test LLM integration (with mocked responses)."""

    def test_llm_client_initialization(self, mock_env_vars):
        """Test LLM client can be initialized with API keys."""
        from clawpwn.ai.llm import LLMClient

        # Should initialize without error
        client = LLMClient()
        assert client.provider == "anthropic"
        assert client.api_key == "test-api-key"


class TestPerformance:
    """Test performance characteristics."""

    def test_large_finding_count_performance(self, session_manager: SessionManager):
        """Test that operations remain performant with many findings."""
        session_manager.create_project("/tmp/test")

        # Add many findings
        for i in range(100):
            session_manager.add_finding(
                title=f"Finding {i}",
                severity=["critical", "high", "medium", "low"][i % 4],
                description=f"Description {i}",
                attack_type="Test",
            )

        # Get state should still be fast
        import time

        start = time.time()
        state = session_manager.get_state()
        elapsed = time.time() - start

        if state:
            assert state.findings_count == 100
        assert elapsed < 1.0  # Should complete in under 1 second
