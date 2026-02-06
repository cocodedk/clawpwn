"""Test configuration and fixtures for ClawPwn."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from clawpwn.db.init import init_db
from clawpwn.db.models import Finding, Project
from clawpwn.modules.session import SessionManager


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def project_dir(temp_dir: Path) -> Path:
    """Create a mock project directory structure."""
    project_path = temp_dir / "test_project"
    project_path.mkdir()

    # Create standard directories
    (project_path / ".clawpwn").mkdir()
    (project_path / "evidence").mkdir()
    (project_path / "exploits").mkdir()
    (project_path / "report").mkdir()

    return project_path


@pytest.fixture
def db_path(project_dir: Path) -> Path:
    """Return the database path for a project."""
    return project_dir / ".clawpwn" / "clawpwn.db"


@pytest.fixture
def initialized_db(db_path: Path) -> Path:
    """Initialize the database and return its path."""
    init_db(db_path)
    return db_path


@pytest.fixture
def session_manager(initialized_db: Path) -> SessionManager:
    """Create a session manager with an initialized database."""
    return SessionManager(initialized_db)


@pytest.fixture
def sample_project(session_manager: SessionManager) -> Project:
    """Create a sample project in the database."""
    project = session_manager.create_project("/tmp/test_project")
    return project


@pytest.fixture
def sample_finding(session_manager: SessionManager, sample_project: Project) -> Finding:
    """Create a sample finding in the database."""
    finding = session_manager.add_finding(
        title="Test SQL Injection",
        severity="critical",
        description="A test SQL injection vulnerability",
        evidence="Payload: ' OR 1=1--",
        attack_type="SQL Injection",
    )
    return finding


@pytest.fixture
def mock_env_vars(monkeypatch) -> None:
    """Set up mock environment variables for testing.

    Forces the legacy (text-parse) NLI path so tests that mock ``llm.chat``
    continue to work.  Tests that exercise the tool-use agent should set
    ``CLAWPWN_LLM_PROVIDER=anthropic`` explicitly.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-api-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    # Default to openai so NLI uses the text-parse path (not tool-use agent)
    monkeypatch.setenv("CLAWPWN_LLM_PROVIDER", "openai")


@pytest.fixture
def mock_http_response() -> dict:
    """Return a mock HTTP response for testing."""
    return {
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx/1.18.0",
        },
        "body": "<html><body>Test page</body></html>",
    }


@pytest.fixture
def mock_vulnerable_response() -> dict:
    """Return a mock vulnerable HTTP response for testing."""
    return {
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41",
        },
        "body": """<html>
        <body>
            <h1>Login</h1>
            <form action="/login" method="POST">
                <input name="username" />
                <input name="password" />
                <button>Submit</button>
            </form>
            <div>SQL syntax error near '1=1'</div>
        </body>
        </html>""",
    }
