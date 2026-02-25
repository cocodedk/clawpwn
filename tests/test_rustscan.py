"""Tests for RustScan parsing and scanner."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clawpwn.tools.rustscan import RustScanScanner, _parse_float_env


def test_parse_float_env_unset_returns_default(monkeypatch):
    monkeypatch.delenv("RUSTSCAN_TIMEOUT", raising=False)
    assert _parse_float_env("RUSTSCAN_TIMEOUT") == 3600.0


def test_parse_float_env_set_returns_float(monkeypatch):
    monkeypatch.setenv("RUSTSCAN_TIMEOUT", "60.0")
    assert _parse_float_env("RUSTSCAN_TIMEOUT") == 60.0


def test_parse_float_env_invalid_returns_default(monkeypatch):
    monkeypatch.setenv("RUSTSCAN_TIMEOUT", "invalid")
    assert _parse_float_env("RUSTSCAN_TIMEOUT") == 3600.0


@pytest.mark.asyncio
async def test_rustscan_scan_host_timeout_raises():
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
        patch.object(RustScanScanner, "_check_rustscan", return_value="/usr/bin/rustscan"),
        patch(
            "clawpwn.tools.rustscan.asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec,
    ):
        mock_exec.return_value = mock_process
        scanner = RustScanScanner()
        with pytest.raises(RuntimeError, match="timed out"):
            await scanner.scan_host("127.0.0.1", timeout=0.01)
    mock_process.terminate.assert_called_once()


def test_rustscan_parse_empty():
    """Empty output returns single host with no ports."""
    results = RustScanScanner._parse_output("192.168.1.1", "")
    assert len(results) == 1
    assert results[0].ip == "192.168.1.1"
    assert results[0].ports == []


def test_rustscan_parse_whitespace_only():
    """Whitespace-only output returns single host with no ports."""
    results = RustScanScanner._parse_output("10.0.0.1", "   \n  ")
    assert len(results) == 1
    assert results[0].ports == []


def test_rustscan_parse_one_per_line():
    """One port per line (typical --quiet output)."""
    output = "22\n80\n443\n"
    results = RustScanScanner._parse_output("192.168.1.10", output)
    assert len(results) == 1
    assert results[0].ip == "192.168.1.10"
    ports = sorted(p.port for p in results[0].ports)
    assert ports == [22, 80, 443]
    for p in results[0].ports:
        assert p.protocol == "tcp"
        assert p.state == "open"


def test_rustscan_parse_comma_separated():
    """Comma-separated port list."""
    output = "22,80,443,8080"
    results = RustScanScanner._parse_output("10.0.0.1", output)
    assert len(results) == 1
    ports = sorted(p.port for p in results[0].ports)
    assert ports == [22, 80, 443, 8080]


def test_rustscan_parse_with_proto_suffix():
    """Ports with /tcp suffix."""
    output = "22/tcp 80/tcp 443/tcp"
    results = RustScanScanner._parse_output("127.0.0.1", output)
    assert len(results) == 1
    ports = sorted(p.port for p in results[0].ports)
    assert ports == [22, 80, 443]


def test_rustscan_parse_deduplicates_ports():
    """Repeated ports are deduplicated."""
    output = "80\n80\n443\n80"
    results = RustScanScanner._parse_output("1.2.3.4", output)
    assert len(results[0].ports) == 2
    ports = sorted(p.port for p in results[0].ports)
    assert ports == [80, 443]


def test_rustscan_parse_ignores_invalid():
    """Non-port tokens are ignored."""
    output = "80\nabc\n443\n0\n99999\n"
    results = RustScanScanner._parse_output("1.1.1.1", output)
    ports = sorted(p.port for p in results[0].ports)
    assert ports == [80, 443]


@pytest.mark.asyncio
async def test_rustscan_scan_host_requires_binary(monkeypatch):
    """RustScanScanner raises when rustscan is not installed."""
    monkeypatch.setattr(
        "shutil.which",
        lambda _: None,
    )
    # Also mock cargo path check (Path.is_file returns False)
    monkeypatch.setattr("pathlib.Path.is_file", lambda self: False)
    with pytest.raises(RuntimeError, match="rustscan is not installed"):
        RustScanScanner()
