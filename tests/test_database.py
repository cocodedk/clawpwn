"""Tests for database models and operations."""

from pathlib import Path

from clawpwn.db.init import init_db
from clawpwn.db.models import Finding
from clawpwn.modules.session import SessionManager


class TestDatabaseInitialization:
    """Test database initialization."""

    def test_init_db_creates_tables(self, db_path: Path):
        """Test that init_db creates all required tables."""
        init_db(db_path)

        # Verify database file exists
        assert db_path.exists()
        assert db_path.stat().st_size > 0

    def test_init_db_creates_parent_directories(self, temp_dir: Path):
        """Test that init_db creates parent directories if needed."""
        nested_db = temp_dir / "nested" / "path" / "clawpwn.db"
        init_db(nested_db)

        assert nested_db.exists()


class TestProjectModel:
    """Test Project database model."""

    def test_create_project(self, session_manager: SessionManager):
        """Test creating a project."""
        project = session_manager.create_project("/tmp/test_project")

        assert project.id is not None
        assert project.path == "/tmp/test_project"
        assert project.current_phase == "Initialized"
        assert project.target is None

    def test_get_project(self, session_manager: SessionManager):
        """Test retrieving a project."""
        # First create a project
        created = session_manager.create_project("/tmp/test_project")

        # Then retrieve it
        retrieved = session_manager.get_project()

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.path == created.path

    def test_set_target(self, session_manager: SessionManager):
        """Test setting a target."""
        session_manager.create_project("/tmp/test_project")
        session_manager.set_target("https://example.com")

        project = session_manager.get_project()
        assert project.target == "https://example.com"

    def test_update_phase(self, session_manager: SessionManager):
        """Test updating the current phase."""
        session_manager.create_project("/tmp/test_project")
        session_manager.update_phase("Reconnaissance")

        project = session_manager.get_project()
        assert project.current_phase == "Reconnaissance"


class TestFindingModel:
    """Test Finding database model."""

    def test_add_finding(self, session_manager: SessionManager, sample_project):
        """Test adding a finding."""
        finding = session_manager.add_finding(
            title="SQL Injection",
            severity="critical",
            description="SQL injection in login form",
            evidence="Payload: ' OR 1=1--",
            attack_type="SQL Injection",
        )

        assert finding.id is not None
        assert finding.title == "SQL Injection"
        assert finding.severity == "critical"
        assert finding.project_id == sample_project.id

    def test_add_multiple_findings(self, session_manager: SessionManager):
        """Test adding multiple findings."""
        session_manager.create_project("/tmp/test_project")

        # Add multiple findings
        session_manager.add_finding("Finding 1", "critical", "Desc 1", attack_type="SQLi")
        session_manager.add_finding("Finding 2", "high", "Desc 2", attack_type="XSS")
        session_manager.add_finding("Finding 3", "medium", "Desc 3", attack_type="Info")

        state = session_manager.get_state()
        assert state.findings_count == 3
        assert state.critical_count == 1
        assert state.high_count == 1

    def test_finding_severity_levels(self, session_manager: SessionManager):
        """Test findings with different severity levels."""
        session_manager.create_project("/tmp/test_project")

        severities = ["critical", "high", "medium", "low", "info"]
        for sev in severities:
            session_manager.add_finding(
                title=f"{sev.title()} Finding",
                severity=sev,
                description=f"A {sev} severity finding",
                attack_type="Test",
            )

        state = session_manager.get_state()
        assert state.findings_count == 5
        assert state.critical_count == 1
        assert state.high_count == 1


class TestLogModel:
    """Test Log database model."""

    def test_add_log(self, session_manager: SessionManager, sample_project):
        """Test adding a log entry."""
        log = session_manager.add_log(
            message="Started scanning", level="INFO", phase="Reconnaissance"
        )

        assert log.id is not None
        assert log.message == "Started scanning"
        assert log.level == "INFO"
        assert log.phase == "Reconnaissance"
        assert log.project_id == sample_project.id

    def test_add_log_default_level(self, session_manager: SessionManager):
        """Test that default log level is INFO."""
        session_manager.create_project("/tmp/test_project")

        log = session_manager.add_log("Test message")

        assert log.level == "INFO"

    def test_get_logs(self, session_manager: SessionManager):
        """Test retrieving logs."""
        session_manager.create_project("/tmp/test_project")

        # Add several logs
        session_manager.add_log("Message 1", "INFO")
        session_manager.add_log("Message 2", "WARNING")
        session_manager.add_log("Message 3", "ERROR")

        logs = session_manager.get_logs(limit=10)

        assert len(logs) == 3
        # Should be in reverse chronological order
        assert logs[0].message == "Message 3"

    def test_get_logs_with_limit(self, session_manager: SessionManager):
        """Test log retrieval with limit."""
        session_manager.create_project("/tmp/test_project")

        # Add 5 logs
        for i in range(5):
            session_manager.add_log(f"Message {i}")

        logs = session_manager.get_logs(limit=3)

        assert len(logs) == 3


class TestSessionManager:
    """Test SessionManager functionality."""

    def test_get_state_no_project(self, session_manager: SessionManager):
        """Test getting state when no project exists."""
        state = session_manager.get_state()
        assert state is None

    def test_get_state_with_project(self, session_manager: SessionManager):
        """Test getting state with project data."""
        session_manager.create_project("/tmp/test_project")
        session_manager.set_target("https://example.com")
        session_manager.update_phase("Reconnaissance")

        state = session_manager.get_state()

        assert state is not None
        assert state.project_path == "/tmp/test_project"
        assert state.target == "https://example.com"
        assert state.current_phase == "Reconnaissance"

    def test_get_state_with_findings(self, session_manager: SessionManager):
        """Test getting state counts findings correctly."""
        session_manager.create_project("/tmp/test_project")

        # Add findings
        session_manager.add_finding("Critical Finding", "critical", attack_type="SQLi")
        session_manager.add_finding("High Finding", "high", attack_type="XSS")
        session_manager.add_finding("Medium Finding", "medium", attack_type="Info")

        state = session_manager.get_state()

        assert state.findings_count == 3
        assert state.critical_count == 1
        assert state.high_count == 1

    def test_project_memory_round_trip(self, session_manager: SessionManager):
        """Test setting and clearing project memory."""
        session_manager.create_project("/tmp/test_project")
        memory = session_manager.get_memory()
        assert memory is not None
        assert memory.objective == ""
        assert memory.summary == ""

        session_manager.set_objective("Test objective")
        session_manager.update_summary("Test summary")
        memory = session_manager.get_memory()
        assert memory.objective == "Test objective"
        assert memory.summary == "Test summary"

        session_manager.clear_memory()
        memory = session_manager.get_memory()
        assert memory.objective == ""
        assert memory.summary == ""

    def test_message_storage(self, session_manager: SessionManager):
        """Test storing and retrieving conversation messages."""
        session_manager.create_project("/tmp/test_project")
        session_manager.add_message("user", "hello")
        session_manager.add_message("assistant", "hi")

        assert session_manager.get_message_count() == 2
        recent = session_manager.get_recent_messages(limit=2)
        roles = [m.role for m in recent]
        assert "user" in roles and "assistant" in roles


class TestDatabaseRelationships:
    """Test database relationships."""

    def test_project_finding_relationship(self, session_manager: SessionManager):
        """Test that findings are related to projects."""
        project = session_manager.create_project("/tmp/test_project")
        finding = session_manager.add_finding("Test", "high", attack_type="Test")

        assert finding.project_id == project.id

    def test_cascade_delete(self, session_manager: SessionManager):
        """Test that deleting a project cascades to findings."""
        project = session_manager.create_project("/tmp/test_project")
        session_manager.add_finding("Test Finding", "critical", attack_type="Test")

        # Delete project
        session_manager.session.delete(project)
        session_manager.session.commit()

        # Verify finding is also deleted

        findings = session_manager.session.query(Finding).all()
        assert len(findings) == 0
