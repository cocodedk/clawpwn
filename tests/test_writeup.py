"""Tests for writeup generation, persistence, and tool execution."""

from unittest.mock import MagicMock, patch

from clawpwn.db.models import Writeup


class TestWriteupModel:
    """Test Writeup DB model creation and field defaults."""

    def test_writeup_model(self, session_manager, sample_project):
        writeup = Writeup(
            project_id=sample_project.id,
            title="Test Writeup",
            content="# Hello\nSome content.",
        )
        session_manager.session.add(writeup)
        session_manager.session.commit()

        assert writeup.id is not None
        assert writeup.title == "Test Writeup"
        assert writeup.format == "markdown"
        assert writeup.created_at is not None


class TestWriteupMixin:
    """Test WriteupMixin round-trip through SessionManager."""

    def test_save_and_retrieve(self, session_manager, sample_project):
        w = session_manager.save_writeup(
            title="Scan Writeup",
            content="## Objective\nTest the target.",
        )
        assert w.id is not None
        assert w.content.startswith("## Objective")

        writeups = session_manager.get_writeups()
        assert len(writeups) == 1
        assert writeups[0].title == "Scan Writeup"

    def test_get_latest_writeup(self, session_manager, sample_project):
        session_manager.save_writeup(title="First", content="one")
        session_manager.save_writeup(title="Second", content="two")

        latest = session_manager.get_latest_writeup()
        assert latest is not None
        assert latest.title == "Second"

    def test_get_latest_writeup_empty(self, session_manager, sample_project):
        assert session_manager.get_latest_writeup() is None


class TestGenerateWriteupLLM:
    """Test LLM-based writeup generation."""

    def test_generate_writeup_llm(self, project_dir):
        mock_llm = MagicMock()
        mock_llm.chat.return_value = "## Objective\nTest writeup content."

        from clawpwn.ai.nli.agent.writeup_llm import generate_writeup

        result = generate_writeup(
            llm=mock_llm,
            target="http://example.com",
            all_results=[
                {"tool": "web_scan", "description": "XSS scan", "result": "No vulns found"},
            ],
            project_dir=project_dir,
        )

        assert "Objective" in result
        mock_llm.chat.assert_called_once()
        prompt = mock_llm.chat.call_args[0][0]
        assert "http://example.com" in prompt
        assert "web_scan" in prompt

    def test_generate_writeup_fallback(self, project_dir):
        mock_llm = MagicMock()
        mock_llm.chat.side_effect = RuntimeError("LLM down")

        from clawpwn.ai.nli.agent.writeup_llm import generate_writeup

        result = generate_writeup(
            llm=mock_llm,
            target="10.0.0.1",
            all_results=[{"tool": "nmap", "description": "scan", "result": "open ports"}],
            project_dir=project_dir,
        )

        assert "10.0.0.1" in result
        assert "nmap" in result


class TestSaveWriteupToDisk:
    """Test writeup file I/O."""

    def test_save_writeup_to_disk(self, session_manager, sample_project, project_dir):
        from clawpwn.ai.nli.agent.writeup_io import save_writeup

        path = save_writeup(
            session=session_manager,
            content="# My Writeup\nDetails here.",
            target="http://example.com",
            project_dir=project_dir,
        )

        assert path.exists()
        assert path.suffix == ".md"
        assert "writeup_" in path.name
        assert path.read_text().startswith("# My Writeup")

        # Verify DB persistence too
        latest = session_manager.get_latest_writeup()
        assert latest is not None
        assert "My Writeup" in latest.content


class TestExecuteGenerateWriteupTool:
    """Test the generate_writeup tool executor end-to-end."""

    def test_execute_generate_writeup(self, session_manager, sample_project, project_dir):
        session_manager.set_target("http://victim.local")
        session_manager.save_plan(
            [
                {"description": "Fingerprint target", "tool": "fingerprint_target"},
            ]
        )
        session_manager.update_step_status(1, "done", "Apache 2.4 detected")

        mock_llm_instance = MagicMock()
        mock_llm_instance.chat.return_value = "## Objective\nGenerated writeup."

        with (
            patch(
                "clawpwn.config.get_project_db_path",
                return_value=session_manager.db_path,
            ),
            patch(
                "clawpwn.modules.session.SessionManager",
                return_value=session_manager,
            ),
            patch(
                "clawpwn.ai.llm.LLMClient",
                return_value=mock_llm_instance,
            ),
        ):
            from clawpwn.ai.nli.tool_executors.writeup_executor import execute_generate_writeup

            result = execute_generate_writeup({}, project_dir)

        assert "Writeup saved to" in result
        assert (project_dir / "writeups").exists()
