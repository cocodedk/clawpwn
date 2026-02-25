"""Tests for the Naabu port scanner wrapper."""

from unittest.mock import AsyncMock, patch

import pytest

from clawpwn.tools.naabu.scanner import NaabuScanner


class TestParseOutput:
    """Test JSONL output parsing."""

    def test_single_host(self):
        output = '{"ip":"10.0.0.1","port":22}\n{"ip":"10.0.0.1","port":80}\n'
        results = NaabuScanner._parse_output(output)
        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"
        assert len(results[0].ports) == 2
        assert results[0].ports[0].port == 22
        assert results[0].ports[1].port == 80

    def test_multi_host(self):
        output = (
            '{"ip":"10.0.0.1","port":22}\n'
            '{"ip":"10.0.0.2","port":443}\n'
            '{"ip":"10.0.0.1","port":80}\n'
        )
        results = NaabuScanner._parse_output(output)
        assert len(results) == 2
        ips = {r.ip for r in results}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_empty_output(self):
        assert NaabuScanner._parse_output("") == []
        assert NaabuScanner._parse_output("   \n  ") == []

    def test_invalid_lines_skipped(self):
        output = 'not json\n{"ip":"10.0.0.1","port":80}\n{broken\n'
        results = NaabuScanner._parse_output(output)
        assert len(results) == 1
        assert results[0].ports[0].port == 80

    def test_duplicate_ports_deduplicated(self):
        output = '{"ip":"10.0.0.1","port":80}\n{"ip":"10.0.0.1","port":80}\n'
        results = NaabuScanner._parse_output(output)
        assert len(results[0].ports) == 1

    def test_host_key_alias(self):
        output = '{"host":"10.0.0.1","port":22}\n'
        results = NaabuScanner._parse_output(output)
        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"

    def test_port_out_of_range_skipped(self):
        output = '{"ip":"10.0.0.1","port":0}\n{"ip":"10.0.0.1","port":99999}\n'
        assert NaabuScanner._parse_output(output) == []


class TestBinaryCheck:
    """Test binary detection."""

    def test_missing_binary_raises(self, tmp_path):
        with patch("clawpwn.tools.naabu.scanner.shutil.which", return_value=None):
            with patch("clawpwn.tools.naabu.scanner.Path.home", return_value=tmp_path):
                with pytest.raises(RuntimeError, match="naabu is not installed"):
                    NaabuScanner()


class TestScanTimeout:
    """Test scan timeout handling."""

    @pytest.mark.asyncio
    async def test_timeout_raises_runtime_error(self):
        with patch.object(NaabuScanner, "_check_naabu", return_value="/usr/bin/naabu"):
            scanner = NaabuScanner()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError)
        mock_proc.terminate = AsyncMock()
        mock_proc.wait = AsyncMock()
        mock_proc.kill = AsyncMock()

        with patch(
            "clawpwn.tools.naabu.scanner.asyncio.create_subprocess_exec", return_value=mock_proc
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                await scanner.scan_host("10.0.0.1", timeout=0.001)
