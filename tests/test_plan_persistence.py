"""Tests for attack plan persistence (save, load, update, resume)."""

from pathlib import Path

import pytest


@pytest.fixture()
def temp_dir(tmp_path: Path) -> Path:
    """Create a temporary project directory with an initialized DB."""
    from clawpwn.db.init import init_db
    from clawpwn.modules.session import SessionManager

    marker = tmp_path / ".clawpwn"
    marker.mkdir(parents=True, exist_ok=True)
    db_path = marker / "clawpwn.db"
    init_db(db_path)
    session = SessionManager(db_path)
    session.create_project(str(tmp_path))
    session.set_target("http://example.com")
    return tmp_path


@pytest.fixture()
def db_path(temp_dir: Path) -> Path:
    return temp_dir / ".clawpwn" / "clawpwn.db"


class TestPlanModel:
    """Test that the PlanStep table is created and usable."""

    def test_plan_step_table_exists(self, db_path: Path):
        from sqlalchemy import create_engine, inspect

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        assert "plan_steps" in tables

    def test_plan_step_columns(self, db_path: Path):
        from sqlalchemy import create_engine, inspect

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("plan_steps")}
        assert cols >= {
            "id",
            "project_id",
            "step_number",
            "tool",
            "description",
            "status",
            "result_summary",
            "created_at",
            "updated_at",
        }


class TestPlanMigration:
    """Test that old databases without the tool column get migrated."""

    def test_migrate_adds_tool_column(self, tmp_path: Path):
        """Simulate an old DB that has plan_steps without the tool column."""
        from sqlalchemy import create_engine, inspect, text

        from clawpwn.db.init import init_db

        db_path = tmp_path / ".clawpwn" / "clawpwn.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create a DB with the OLD schema (no tool column)
        engine = create_engine(f"sqlite:///{db_path}")
        with engine.begin() as conn:
            conn.execute(
                text("""
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL,
                    target TEXT DEFAULT '',
                    current_phase TEXT DEFAULT 'reconnaissance',
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """)
            )
            conn.execute(
                text("""
                CREATE TABLE plan_steps (
                    id INTEGER PRIMARY KEY,
                    project_id INTEGER NOT NULL,
                    step_number INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    result_summary TEXT DEFAULT '',
                    created_at DATETIME,
                    updated_at DATETIME,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                )
            """)
            )
            # Insert a row to prove data survives migration
            conn.execute(text("INSERT INTO projects (id, path) VALUES (1, '/tmp/test')"))
            conn.execute(
                text(
                    "INSERT INTO plan_steps (project_id, step_number, description) "
                    "VALUES (1, 1, 'Old step without tool')"
                )
            )

        # Verify tool column is missing
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("plan_steps")}
        assert "tool" not in cols

        # Run init_db — should add the tool column
        init_db(db_path)

        engine2 = create_engine(f"sqlite:///{db_path}")
        inspector2 = inspect(engine2)
        cols2 = {c["name"] for c in inspector2.get_columns("plan_steps")}
        assert "tool" in cols2

        # Verify existing data survived
        with engine2.connect() as conn:
            row = conn.execute(text("SELECT description, tool FROM plan_steps")).fetchone()
            assert row[0] == "Old step without tool"
            assert row[1] == "" or row[1] is None  # default value


class TestPlanMixin:
    """Test SessionManager plan operations."""

    def test_save_plan_creates_steps(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        steps = sm.save_plan(["Fingerprint target", "SQLi scan", "XSS scan"])
        assert len(steps) == 3
        assert steps[0].step_number == 1
        assert steps[0].description == "Fingerprint target"
        assert steps[0].status == "pending"

    def test_save_plan_replaces_existing(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Old step 1", "Old step 2"])
        sm.save_plan(["New step 1"])
        plan = sm.get_plan()
        assert len(plan) == 1
        assert plan[0].description == "New step 1"

    def test_get_plan_ordered(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Step A", "Step B", "Step C"])
        plan = sm.get_plan()
        assert [s.step_number for s in plan] == [1, 2, 3]

    def test_update_step_status(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Fingerprint", "SQLi scan"])
        step = sm.update_step_status(1, "done", "Apache 2.4 detected")
        assert step is not None
        assert step.status == "done"
        assert step.result_summary == "Apache 2.4 detected"

    def test_update_nonexistent_step_returns_none(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Only step"])
        assert sm.update_step_status(99, "done") is None

    def test_get_next_pending_step(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Step 1", "Step 2", "Step 3"])
        sm.update_step_status(1, "done")
        nxt = sm.get_next_pending_step()
        assert nxt is not None
        assert nxt.step_number == 2

    def test_get_next_pending_returns_none_when_complete(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Only step"])
        sm.update_step_status(1, "done")
        assert sm.get_next_pending_step() is None

    def test_clear_plan(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Step 1", "Step 2"])
        sm.clear_plan()
        assert sm.get_plan() == []

    def test_format_plan_status_empty(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        assert sm.format_plan_status() == ""

    def test_format_plan_status_with_progress(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Fingerprint", "SQLi scan", "XSS scan"])
        sm.update_step_status(1, "done", "Apache 2.4")
        sm.update_step_status(2, "in_progress")
        output = sm.format_plan_status()
        assert "1/3 complete" in output
        assert "[x] 1. Fingerprint -> Apache 2.4" in output
        assert "[~] 2. SQLi scan" in output
        assert "[ ] 3. XSS scan" in output


class TestPlanExecutors:
    """Test the tool executor functions for plan management."""

    def test_execute_save_plan(self, temp_dir: Path):
        from clawpwn.ai.nli.tool_executors.plan_executors import execute_save_plan

        result = execute_save_plan({"steps": ["Fingerprint", "SQLi scan"]}, temp_dir)
        assert "Plan saved (2 steps, ordered fastest-first)" in result
        assert "Fingerprint" in result
        assert "fast" in result or "medium" in result  # speed labels present

    def test_execute_save_plan_empty(self, temp_dir: Path):
        from clawpwn.ai.nli.tool_executors.plan_executors import execute_save_plan

        result = execute_save_plan({"steps": []}, temp_dir)
        assert "Error" in result

    def test_execute_update_plan_step(self, temp_dir: Path):
        from clawpwn.ai.nli.tool_executors.plan_executors import (
            execute_save_plan,
            execute_update_plan_step,
        )

        execute_save_plan({"steps": ["Fingerprint", "SQLi scan"]}, temp_dir)
        result = execute_update_plan_step(
            {"step_number": 1, "status": "done", "result_summary": "Apache 2.4"},
            temp_dir,
        )
        assert "1/2 complete" in result
        assert "[x] 1. Fingerprint -> Apache 2.4" in result

    def test_execute_update_missing_step(self, temp_dir: Path):
        from clawpwn.ai.nli.tool_executors.plan_executors import execute_update_plan_step

        result = execute_update_plan_step({"step_number": 99, "status": "done"}, temp_dir)
        assert "Error" in result


class TestPlanInContext:
    """Test that the plan appears in the agent's context enrichment."""

    def test_context_includes_plan(self, temp_dir: Path, db_path: Path):
        from clawpwn.ai.nli.agent.context import get_project_context
        from clawpwn.modules.session import SessionManager

        sm = SessionManager(db_path)
        sm.save_plan(["Fingerprint target", "Run SQLi scan"])
        sm.update_step_status(1, "done", "WordPress 5.9")

        context = get_project_context(temp_dir)
        assert "Attack plan" in context
        assert "[x] 1. Fingerprint target -> WordPress 5.9" in context
        assert "[ ] 2. Run SQLi scan" in context

    def test_context_without_plan(self, temp_dir: Path):
        from clawpwn.ai.nli.agent.context import get_project_context

        context = get_project_context(temp_dir)
        assert "Attack plan" not in context


class TestPlanToolRegistration:
    """Test that plan tools are properly registered."""

    def test_plan_tools_in_get_all_tools(self):
        from clawpwn.ai.nli.tools import get_all_tools

        tools = get_all_tools()
        names = {t["name"] for t in tools}
        assert "save_plan" in names
        assert "update_plan_step" in names

    def test_plan_tools_have_executors(self):
        from clawpwn.ai.nli.tool_executors import TOOL_EXECUTORS

        assert "save_plan" in TOOL_EXECUTORS
        assert "update_plan_step" in TOOL_EXECUTORS

    def test_plan_tools_in_action_map(self):
        from clawpwn.ai.nli.agent.prompt import TOOL_ACTION_MAP

        assert TOOL_ACTION_MAP["save_plan"] == "plan"
        assert TOOL_ACTION_MAP["update_plan_step"] == "plan"


class TestPlanSurvivesRestart:
    """Test that a plan persists across SessionManager instances (simulating restart)."""

    def test_plan_survives_new_session_manager(self, db_path: Path):
        from clawpwn.modules.session import SessionManager

        # First "session" — create and partially execute plan
        sm1 = SessionManager(db_path)
        sm1.save_plan(["Fingerprint", "SQLi scan", "XSS scan", "Cred test"])
        sm1.update_step_status(1, "done", "Nginx 1.18")
        sm1.update_step_status(2, "in_progress")

        # Simulate restart — new SessionManager instance
        sm2 = SessionManager(db_path)
        plan = sm2.get_plan()
        assert len(plan) == 4
        assert plan[0].status == "done"
        assert plan[0].result_summary == "Nginx 1.18"
        assert plan[1].status == "in_progress"
        assert plan[2].status == "pending"
        assert plan[3].status == "pending"

        nxt = sm2.get_next_pending_step()
        assert nxt is not None
        assert nxt.step_number == 3


class TestSpeedOrdering:
    """Test that plan steps are sorted fastest-first using tool profile lookup."""

    def test_sort_structured_steps_fast_before_slow(self):
        from clawpwn.ai.nli.tool_executors.plan_executors import _sort_steps_by_speed

        steps = [
            {"description": "SQLi deep scan", "tool": "web_scan:sqlmap"},
            {"description": "Fingerprint target", "tool": "fingerprint_target"},
            {"description": "Nikto server check", "tool": "web_scan:nikto"},
            {"description": "Research CVEs", "tool": "research_vulnerabilities"},
        ]
        sorted_steps = _sort_steps_by_speed(steps)
        tools = [s["tool"] for s in sorted_steps]
        # Fast first, medium second, slow last
        assert tools[0] == "fingerprint_target"
        assert tools[1] == "research_vulnerabilities"
        assert tools[2] == "web_scan:nikto"
        assert tools[3] == "web_scan:sqlmap"

    def test_credential_test_sorts_before_scanners(self):
        from clawpwn.ai.nli.tool_executors.plan_executors import _sort_steps_by_speed

        steps = [
            {"description": "SQLi scan", "tool": "web_scan:sqlmap"},
            {"description": "Builtin scan", "tool": "web_scan:builtin"},
            {"description": "Wordlist attack with hydra", "tool": "credential_test:hydra"},
            {"description": "Default creds test", "tool": "credential_test"},
        ]
        sorted_steps = _sort_steps_by_speed(steps)
        tools = [s["tool"] for s in sorted_steps]
        # Credential tests (tier 1) before scanners (tier 2, 3)
        assert tools[0] in ("credential_test", "credential_test:hydra")
        assert tools[1] in ("credential_test", "credential_test:hydra")
        assert tools[2] == "web_scan:builtin"
        assert tools[3] == "web_scan:sqlmap"

    def test_format_speed_table(self):
        from clawpwn.ai.nli.tools.tool_metadata import format_speed_table

        table = format_speed_table()
        assert "FAST" in table
        assert "MEDIUM" in table
        assert "SLOW" in table
        assert "fingerprint_target" in table
        assert "sqlmap" in table

    def test_save_plan_executor_sorts_structured_steps(self, temp_dir: Path):
        from clawpwn.ai.nli.tool_executors.plan_executors import execute_save_plan
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        # Provide steps in wrong order (slow first)
        execute_save_plan(
            {
                "steps": [
                    {"description": "SQLmap deep scan", "tool": "web_scan:sqlmap"},
                    {"description": "Fingerprint target", "tool": "fingerprint_target"},
                    {"description": "Nikto server check", "tool": "web_scan:nikto"},
                    {"description": "Hydra wordlist attack", "tool": "credential_test:hydra"},
                ]
            },
            temp_dir,
        )

        db_path = get_project_db_path(temp_dir)
        sm = SessionManager(db_path)
        plan = sm.get_plan()
        tools = [s.tool for s in plan]
        # Fast first (fingerprint, hydra), then medium (nikto), then slow (sqlmap)
        assert tools[0] == "fingerprint_target"
        assert tools[1] == "credential_test:hydra"
        assert tools[2] == "web_scan:nikto"
        assert tools[3] == "web_scan:sqlmap"

    def test_get_profile_with_config(self):
        from clawpwn.ai.nli.tools.tool_metadata import get_profile

        # Specific config
        p = get_profile("web_scan", "sqlmap")
        assert p.speed_tier == 3
        assert p.label == "slow"

        # Base profile
        p = get_profile("fingerprint_target")
        assert p.speed_tier == 1
        assert p.label == "fast"

        # Credential test is fast (tier 1)
        p = get_profile("credential_test")
        assert p.speed_tier == 1

        # Unknown tool falls back to default
        p = get_profile("unknown_tool")
        assert p.speed_tier == 2  # default
