"""Tests for network discovery behavior."""

import pytest

from clawpwn.modules import network as network_module
from clawpwn.tools.masscan import HostResult as MasscanHostResult
from clawpwn.tools.masscan import PortScanResult as MasscanPortScanResult
from clawpwn.tools.nmap import HostResult as NmapHostResult
from clawpwn.tools.nmap import PortScanResult as NmapPortScanResult


def test_split_port_range_single():
    """Single range when n<=1 or high<=low."""
    assert network_module._split_port_range(1, 100, 1) == ["1-100"]
    assert network_module._split_port_range(1, 1, 4) == ["1-1"]


def test_split_port_range_four_groups():
    """Port range split into four roughly equal parts."""
    ranges = network_module._split_port_range(1, 100, 4)
    assert len(ranges) == 4
    assert ranges[0] == "1-25"
    assert ranges[1] == "26-50"
    assert ranges[2] == "51-75"
    assert ranges[3] == "76-100"


def test_parse_port_spec_range():
    """Parse a-b style range."""
    assert network_module._parse_port_spec("1-65535") == (1, 65535)
    assert network_module._parse_port_spec("80-443") == (80, 443)
    assert network_module._parse_port_spec("  100-200  ") == (100, 200)


def test_parse_port_spec_comma_returns_none():
    """Comma-separated or list returns None (no parallel split)."""
    assert network_module._parse_port_spec("80,443,8080") is None
    assert network_module._parse_port_spec("1-100,200-300") is None


def test_merge_host_results():
    """Merge multiple scan results into one host with deduplicated ports."""
    results_list = [
        [MasscanHostResult(ip="10.0.0.1", ports=[MasscanPortScanResult(22, "tcp", "open")])],
        [MasscanHostResult(ip="10.0.0.1", ports=[MasscanPortScanResult(80, "tcp", "open")])],
        [
            MasscanHostResult(
                ip="10.0.0.1",
                ports=[
                    MasscanPortScanResult(22, "tcp", "open"),
                    MasscanPortScanResult(443, "tcp", "open"),
                ],
            )
        ],
    ]
    discovery = network_module.NetworkDiscovery(project_dir=None)
    merged = discovery._merge_host_results(results_list, "10.0.0.1")
    assert len(merged) == 1
    assert merged[0].ip == "10.0.0.1"
    ports = sorted(p.port for p in merged[0].ports)
    assert ports == [22, 80, 443]


@pytest.mark.asyncio
async def test_tcp_connect_fallback_when_masscan_empty(monkeypatch):
    """Ensure TCP connect scan runs when masscan returns no results."""

    class FakeMasscan:
        async def scan_host(self, *args, **kwargs):
            return []

    class FakeNmap:
        def __init__(self):
            self.called_ports = None

        async def scan_host_tcp_connect(
            self, target: str, ports: str, version_detection: bool = True, verbose: bool = False
        ):
            self.called_ports = ports
            return [
                NmapHostResult(
                    ip=target,
                    ports=[
                        NmapPortScanResult(port=22, protocol="tcp", state="open", service="ssh")
                    ],
                )
            ]

        async def scan_host_udp(self, *args, **kwargs):
            return []

    fake_nmap = FakeNmap()

    monkeypatch.setattr(network_module, "MasscanScanner", lambda: FakeMasscan())
    monkeypatch.setattr(network_module, "NmapScanner", lambda: fake_nmap)
    monkeypatch.setattr(network_module, "can_raw_scan", lambda _: True)

    discovery = network_module.NetworkDiscovery(project_dir=None)
    info = await discovery.scan_host(
        "1.2.3.4",
        verify_tcp=True,
        include_udp=False,
        ports_tcp="1-100",
        scanner_type="masscan",
    )

    assert fake_nmap.called_ports == "1-100"
    assert 22 in info.open_ports
    assert any(service.name == "ssh" for service in info.services)
    assert "fallback" in (info.notes or "").lower()
