"""Tests for network discovery behavior."""

import pytest

from clawpwn.modules import network as network_module
from clawpwn.tools.nmap import HostResult as NmapHostResult
from clawpwn.tools.nmap import PortScanResult as NmapPortScanResult


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
                        NmapPortScanResult(
                            port=22, protocol="tcp", state="open", service="ssh"
                        )
                    ],
                )
            ]

        async def scan_host_udp(self, *args, **kwargs):
            return []

    fake_nmap = FakeNmap()

    monkeypatch.setattr(network_module, "MasscanScanner", lambda: FakeMasscan())
    monkeypatch.setattr(network_module, "NmapScanner", lambda: fake_nmap)

    discovery = network_module.NetworkDiscovery(project_dir=None)
    info = await discovery.scan_host(
        "1.2.3.4",
        verify_tcp=True,
        include_udp=False,
        ports_tcp="1-100",
    )

    assert fake_nmap.called_ports == "1-100"
    assert 22 in info.open_ports
    assert any(service.name == "ssh" for service in info.services)
    assert "fallback" in (info.notes or "").lower()
