"""High-level NetworkDiscovery operations."""

from typing import Any

from clawpwn.modules.network_helpers.host_scan import scan_host as scan_host_impl
from clawpwn.modules.network_helpers.operations import (
    discover_hosts as discover_hosts_impl,
)
from clawpwn.modules.network_helpers.operations import (
    enumerate_target as enumerate_target_impl,
)
from clawpwn.modules.network_helpers.operations import (
    print_summary as print_summary_impl,
)

from .deps import network_module


class OperationsMixin:
    """Provide scan/discover/enumeration workflows."""

    async def discover_hosts(self, network: str) -> list[str]:
        module = network_module()
        return await discover_hosts_impl(
            self,
            network,
            console=module.console,
            nmap_factory=module.NmapScanner,
        )

    async def scan_host(
        self,
        target: str,
        scan_type: str = "quick",
        full_scan: bool = False,
        verbose: bool = False,
        include_udp: bool = False,
        verify_tcp: bool = False,
        ports_tcp: str | None = None,
        ports_udp: str | None = None,
        scanner_type: str = "rustscan",
        parallel_groups: int = 40,
    ) -> Any:
        module = network_module()
        return await scan_host_impl(
            self,
            target,
            scan_type,
            full_scan,
            verbose,
            include_udp,
            verify_tcp,
            ports_tcp,
            ports_udp,
            scanner_type,
            parallel_groups,
            console=module.console,
            env=module.os_environ,
            nmap_factory=module.NmapScanner,
            host_info_cls=module.HostInfo,
            service_info_cls=module.ServiceInfo,
            parse_port_spec=module._parse_port_spec,
            split_port_range=module._split_port_range,
        )

    async def enumerate_target(self, target: str) -> dict[str, Any]:
        return await enumerate_target_impl(self, target)

    def print_summary(self, results: dict[str, Any]) -> None:
        print_summary_impl(results)
