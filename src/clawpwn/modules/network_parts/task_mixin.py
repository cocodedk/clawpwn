"""Parallel and vulnerability task methods."""

from typing import Any

from clawpwn.modules.network_helpers.parallel_scan import run_parallel_scan_with_progress
from clawpwn.modules.network_helpers.vuln_tasks import run_udp_and_vuln_parallel, run_vuln_lookup
from clawpwn.tools.masscan import HostResult, PortScanResult

from .deps import network_module


class TaskMixin:
    """Provide parallel scan and vulnerability helpers."""

    async def _run_parallel_scan_with_progress(
        self,
        scanner: Any,
        scanner_type: str,
        target: str,
        port_ranges: list[str],
        verbose: bool,
    ) -> list[HostResult]:
        module = network_module()
        return await run_parallel_scan_with_progress(
            self,
            scanner,
            scanner_type,
            target,
            port_ranges,
            verbose,
            console=module.console,
        )

    async def _run_vuln_lookup(
        self,
        services: list[Any],
        max_results: int = 3,
        state: dict[str, Any] | None = None,
    ) -> list[str]:
        module = network_module()
        return await run_vuln_lookup(
            services,
            module.VulnDBClient,
            max_results=max_results,
            state=state,
        )

    async def _run_udp_and_vuln_parallel(
        self,
        target: str,
        ports_udp: str,
        host_info: Any,
        verbose: bool,
        max_vuln_results: int,
    ) -> tuple[list[HostResult], list[str]]:
        module = network_module()
        return await run_udp_and_vuln_parallel(
            self,
            target,
            ports_udp,
            host_info,
            verbose,
            max_vuln_results,
            console=module.console,
        )

    def _merge_host_results(
        self,
        results_list: list[list[HostResult]],
        target: str,
    ) -> list[HostResult]:
        all_ports: dict[int, PortScanResult] = {}
        for results in results_list:
            for host in results:
                for port in host.ports:
                    if port.state == "open" and port.port not in all_ports:
                        all_ports[port.port] = port
        ports_sorted = [all_ports[port] for port in sorted(all_ports)]
        return [HostResult(ip=target, ports=ports_sorted)]
