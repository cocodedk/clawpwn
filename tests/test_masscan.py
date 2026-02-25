"""Tests for masscan parsing."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clawpwn.tools.masscan import MasscanScanner, _parse_float_env


def test_parse_float_env_unset_returns_default(monkeypatch):
    monkeypatch.delenv("CLAWPWN_MASSCAN_TIMEOUT", raising=False)
    assert _parse_float_env("CLAWPWN_MASSCAN_TIMEOUT") == 3600.0


def test_parse_float_env_set_returns_float(monkeypatch):
    monkeypatch.setenv("CLAWPWN_MASSCAN_TIMEOUT", "120.5")
    assert _parse_float_env("CLAWPWN_MASSCAN_TIMEOUT") == 120.5


def test_parse_float_env_invalid_returns_default(monkeypatch):
    monkeypatch.setenv("CLAWPWN_MASSCAN_TIMEOUT", "not-a-number")
    assert _parse_float_env("CLAWPWN_MASSCAN_TIMEOUT") == 3600.0


@pytest.mark.asyncio
async def test_masscan_scan_host_timeout_raises():
    """When communicate() does not complete within timeout, RuntimeError is raised."""

    async def never_complete():
        await asyncio.Future()

    mock_process = Mock()
    mock_process.communicate = lambda: never_complete()
    mock_process.terminate = Mock()
    mock_process.kill = Mock()
    mock_process.wait = AsyncMock(return_value=None)
    mock_process.stdout = None
    mock_process.stderr = None
    mock_process.returncode = None

    with (
        patch.object(MasscanScanner, "_check_masscan", return_value="/usr/bin/masscan"),
        patch(
            "clawpwn.tools.masscan.asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec,
    ):
        mock_exec.return_value = mock_process
        scanner = MasscanScanner()
        with pytest.raises(RuntimeError, match="timed out"):
            await scanner.scan_host("127.0.0.1", "80", timeout=0.01)
    mock_process.terminate.assert_called_once()


def test_masscan_parse_multiple_hosts():
    output = """[
      {"ip":"192.168.1.10","ports":[{"port":80,"proto":"tcp","status":"open"}]},
      {"ip":"192.168.1.10","ports":[{"port":443,"proto":"tcp","status":"open"}]},
      {"ip":"192.168.1.20","ports":[{"port":22,"proto":"tcp","status":"open"}]}
    ]"""

    results = MasscanScanner._parse_masscan_json(output)
    assert len(results) == 2

    host10 = next(r for r in results if r.ip == "192.168.1.10")
    ports10 = sorted(p.port for p in host10.ports)
    assert ports10 == [80, 443]

    host20 = next(r for r in results if r.ip == "192.168.1.20")
    assert [p.port for p in host20.ports] == [22]


def test_masscan_parse_empty():
    assert MasscanScanner._parse_masscan_json("") == []
