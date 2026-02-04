"""Tests for nmap wrapper (unit tests, no nmap binary required)."""

import os
import sys
import types
from unittest.mock import patch

import pytest

from clawpwn.tools import nmap as nmap_module
from clawpwn.tools.nmap import NmapScanner


class TestIsRoot:
    """Tests for _is_root helper."""

    def test_is_root_unix_when_euid_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        assert nmap_module._is_root() is True

    def test_is_root_unix_when_not_root(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        assert nmap_module._is_root() is False

    def test_is_root_unix_exception_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(os, "geteuid", lambda: (_ for _ in ()).throw(OSError()))
        assert nmap_module._is_root() is False

    def test_is_root_windows_admin_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        mock_shell32 = types.SimpleNamespace(IsUserAnAdmin=lambda: 1)
        ctypes_mock = types.ModuleType("ctypes")
        ctypes_mock.windll = types.SimpleNamespace(shell32=mock_shell32)
        monkeypatch.setitem(sys.modules, "ctypes", ctypes_mock)
        try:
            assert nmap_module._is_root() is True
        finally:
            monkeypatch.delitem(sys.modules, "ctypes", raising=False)

    def test_is_root_windows_not_admin_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        mock_shell32 = types.SimpleNamespace(IsUserAnAdmin=lambda: 0)
        ctypes_mock = types.ModuleType("ctypes")
        ctypes_mock.windll = types.SimpleNamespace(shell32=mock_shell32)
        monkeypatch.setitem(sys.modules, "ctypes", ctypes_mock)
        try:
            assert nmap_module._is_root() is False
        finally:
            monkeypatch.delitem(sys.modules, "ctypes", raising=False)

    def test_is_root_windows_exception_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        ctypes_mock = types.ModuleType("ctypes")
        ctypes_mock.windll = None  # accessing .shell32 will raise AttributeError
        monkeypatch.setitem(sys.modules, "ctypes", ctypes_mock)
        try:
            assert nmap_module._is_root() is False
        finally:
            monkeypatch.delitem(sys.modules, "ctypes", raising=False)


# Minimal valid nmap XML (one host, one port) for parsing tests
MINIMAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="foo.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
    <os><osmatch name="Linux 3.x" accuracy="95"/></os>
  </host>
</nmaprun>
"""


class TestNmapXmlParsing:
    """Tests for XML parsing (no subprocess)."""

    @patch.object(NmapScanner, "_check_nmap", lambda self: None)
    def test_parse_nmap_xml_one_host_one_port(self) -> None:
        scanner = NmapScanner()
        results = scanner._parse_nmap_xml(MINIMAL_NMAP_XML)
        assert len(results) == 1
        host = results[0]
        assert host.ip == "192.168.1.1"
        assert host.hostname == "foo.local"
        assert host.status == "up"
        assert len(host.ports) == 1
        port = host.ports[0]
        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service == "http"
        assert port.product == "nginx"
        assert port.version == "1.18"
        assert host.os_info == {"name": "Linux 3.x", "accuracy": "95"}

    @patch.object(NmapScanner, "_check_nmap", lambda self: None)
    def test_parse_nmap_xml_empty_returns_empty_list(self) -> None:
        scanner = NmapScanner()
        assert scanner._parse_nmap_xml("") == []
        assert scanner._parse_nmap_xml("<nmaprun></nmaprun>") == []

    @patch.object(NmapScanner, "_check_nmap", lambda self: None)
    def test_parse_nmap_xml_invalid_returns_empty_list(self) -> None:
        scanner = NmapScanner()
        assert scanner._parse_nmap_xml("not xml <<<") == []
