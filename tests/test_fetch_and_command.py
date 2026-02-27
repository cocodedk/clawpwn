"""Tests for fetch_url and run_command tool executors."""

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from clawpwn.ai.nli.tool_executors import dispatch_tool
from clawpwn.ai.nli.tool_executors.command_executor import execute_run_command
from clawpwn.ai.nli.tool_executors.recon_executors import execute_fetch_url

# ---------------------------------------------------------------------------
# Helper: build a mock HTTPClient with a canned response
# ---------------------------------------------------------------------------


def _mock_client(status=200, content_type="text/html", body="ok"):
    """Return (mock_client, mock_resp) pair ready for patching HTTPClient."""
    resp = MagicMock()
    resp.status_code = status
    resp.content_type = content_type
    resp.body = body

    client = AsyncMock()
    client.request = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client, resp


# ---------------------------------------------------------------------------
# fetch_url tests
# ---------------------------------------------------------------------------

_PATCH_HTTP = "clawpwn.tools.http.client.HTTPClient"


class TestFetchUrlExecutor:
    """Tests for the fetch_url executor."""

    def test_missing_url_returns_error(self, tmp_path: Path):
        result = execute_fetch_url({}, tmp_path)
        assert "Error" in result
        assert "url" in result

    def test_get_success(self, tmp_path: Path):
        client, _ = _mock_client(200, "text/html", "<html><body>hello</body></html>")
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com"}, tmp_path)
        assert "HTTP 200" in result
        assert "hello" in result
        assert "text/html" in result

    def test_http_error_status(self, tmp_path: Path):
        client, _ = _mock_client(404, "text/html", "Not Found")
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com/nope"}, tmp_path)
        assert "HTTP 404" in result
        assert "Not Found" in result

    def test_server_error_status(self, tmp_path: Path):
        client, _ = _mock_client(500, "text/html", "Internal Server Error")
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com/fail"}, tmp_path)
        assert "HTTP 500" in result

    def test_empty_response_body(self, tmp_path: Path):
        client, _ = _mock_client(204, "text/plain", "")
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com/empty"}, tmp_path)
        assert "HTTP 204" in result

    def test_missing_content_type_fallback(self, tmp_path: Path):
        client, resp = _mock_client(200, None, "data")
        resp.content_type = None
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com"}, tmp_path)
        assert "unknown" in result

    def test_custom_headers_passed_through(self, tmp_path: Path):
        client, _ = _mock_client()
        headers = {"Authorization": "Bearer tok123"}
        with patch(_PATCH_HTTP, return_value=client):
            execute_fetch_url({"url": "http://example.com", "headers": headers}, tmp_path)
        call_kw = client.request.call_args[1]
        assert call_kw["headers"] == headers

    def test_post_with_json_body(self, tmp_path: Path):
        client, _ = _mock_client(200, "application/json", '{"ok": true}')
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url(
                {"url": "http://example.com/api", "method": "POST", "body": '{"key": "val"}'},
                tmp_path,
            )
        assert "HTTP 200" in result
        call_kw = client.request.call_args[1]
        assert call_kw["data"] == {"key": "val"}

    def test_post_with_raw_body(self, tmp_path: Path):
        client, _ = _mock_client()
        with patch(_PATCH_HTTP, return_value=client):
            execute_fetch_url(
                {"url": "http://example.com", "method": "POST", "body": "not-json"},
                tmp_path,
            )
        call_kw = client.request.call_args[1]
        assert call_kw["data"] == {"_raw": "not-json"}

    def test_delete_method(self, tmp_path: Path):
        client, _ = _mock_client(200, "text/plain", "deleted")
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url(
                {"url": "http://example.com/resource", "method": "DELETE"},
                tmp_path,
            )
        assert "HTTP 200" in result
        assert client.request.call_args[0] == ("DELETE", "http://example.com/resource")

    def test_method_uppercased(self, tmp_path: Path):
        client, _ = _mock_client()
        with patch(_PATCH_HTTP, return_value=client):
            execute_fetch_url({"url": "http://example.com", "method": "get"}, tmp_path)
        assert client.request.call_args[0][0] == "GET"

    def test_large_response_truncation(self, tmp_path: Path):
        client, _ = _mock_client(200, "text/html", "x" * 60_000)
        with patch(_PATCH_HTTP, return_value=client):
            result = execute_fetch_url({"url": "http://example.com"}, tmp_path)
        assert "Truncated" in result
        assert len(result) < 55_000

    def test_network_error_propagates(self, tmp_path: Path):
        client = AsyncMock()
        client.request = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch(_PATCH_HTTP, return_value=client):
            try:
                result = execute_fetch_url({"url": "http://192.168.1.99"}, tmp_path)
                # If the executor wraps the error, check for error text
                assert "error" in result.lower() or "refused" in result.lower()
            except httpx.ConnectError:
                pass  # Also acceptable — error bubbles up to dispatch_tool


# ---------------------------------------------------------------------------
# run_command tests
# ---------------------------------------------------------------------------


class TestRunCommandExecutor:
    """Tests for the run_command executor."""

    def test_missing_command_returns_error(self, tmp_path: Path):
        result = execute_run_command({}, tmp_path)
        assert "Error" in result
        assert "command" in result

    def test_approval_gate_blocks(self, tmp_path: Path):
        result = execute_run_command(
            {"command": "echo hello", "description": "test", "user_approved": False},
            tmp_path,
        )
        assert "Approval required" in result

    def test_success_echo(self, tmp_path: Path):
        result = execute_run_command(
            {"command": "echo hello", "description": "echo test", "user_approved": True},
            tmp_path,
        )
        assert "Exit code: 0" in result
        assert "hello" in result
        assert "echo test" in result
        # Verify script was saved
        exploits = list((tmp_path / "exploits").glob("command_*.sh"))
        assert len(exploits) == 1

    def test_script_file_contains_command(self, tmp_path: Path):
        execute_run_command(
            {"command": "echo saved", "description": "save test", "user_approved": True},
            tmp_path,
        )
        scripts = list((tmp_path / "exploits").glob("command_*.sh"))
        content = scripts[0].read_text()
        assert "echo saved" in content
        assert "#!/usr/bin/env bash" in content

    def test_failure_exit_code(self, tmp_path: Path):
        result = execute_run_command(
            {"command": "exit 42", "description": "fail test", "user_approved": True},
            tmp_path,
        )
        assert "Exit code: 42" in result

    def test_stderr_output(self, tmp_path: Path):
        result = execute_run_command(
            {"command": "echo err >&2", "description": "stderr test", "user_approved": True},
            tmp_path,
        )
        assert "STDERR" in result
        assert "err" in result

    def test_stdout_and_stderr(self, tmp_path: Path):
        result = execute_run_command(
            {
                "command": "echo out && echo err >&2",
                "description": "both test",
                "user_approved": True,
            },
            tmp_path,
        )
        assert "STDOUT" in result
        assert "STDERR" in result
        assert "out" in result
        assert "err" in result

    def test_timeout(self, tmp_path: Path):
        result = execute_run_command(
            {
                "command": "sleep 60",
                "description": "timeout test",
                "user_approved": True,
                "timeout": 1,
            },
            tmp_path,
        )
        assert "Timed out" in result

    def test_default_timeout_is_30(self, tmp_path: Path):
        """Verify default timeout is used when not specified."""
        with patch(
            "clawpwn.ai.nli.tool_executors.command_executor._run_shell_command",
            new_callable=AsyncMock,
        ) as mock_run:
            from clawpwn.ai.nli.tool_executors.command_executor import CommandResult

            mock_run.return_value = CommandResult(0, "ok", "", "/tmp/cmd.sh")
            execute_run_command(
                {"command": "echo hi", "description": "test", "user_approved": True},
                tmp_path,
            )
            assert mock_run.call_args[0][1] == 30  # timeout arg

    def test_cwd_is_project_dir(self, tmp_path: Path):
        """Command runs in the project directory."""
        result = execute_run_command(
            {"command": "pwd", "description": "cwd test", "user_approved": True},
            tmp_path,
        )
        assert str(tmp_path) in result


# ---------------------------------------------------------------------------
# dispatch_tool thread-safety tests
# ---------------------------------------------------------------------------


class TestDispatchToolThreadSafety:
    """Verify dispatch_tool doesn't corrupt sys.stdout under concurrency."""

    def test_stdout_survives_concurrent_dispatch(self, tmp_path: Path):
        """Multiple concurrent dispatch_tool calls must not close sys.stdout."""
        # Use a lightweight executor that sleeps to force overlap
        import time

        def _slow_executor(params, project_dir):
            time.sleep(0.05)
            return "done"

        with patch.dict("clawpwn.ai.nli.tool_executors.TOOL_EXECUTORS", {"_test": _slow_executor}):
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(dispatch_tool, "_test", {}, tmp_path) for _ in range(8)]
                for f in as_completed(futures):
                    assert f.result() == "done"

        # The critical check: sys.stdout must still be writable
        assert not sys.stdout.closed
        sys.stdout.write("")  # should not raise
        sys.stdout.flush()
