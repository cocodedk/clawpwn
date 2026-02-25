"""Parallel port scanning helpers."""

import asyncio
from typing import Any

from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from clawpwn.tools.masscan import HostResult


async def run_parallel_scan_with_progress(
    discovery: Any,
    scanner: Any,
    scanner_type: str,
    target: str,
    port_ranges: list[str],
    verbose: bool,
    *,
    console: Any,
) -> list[HostResult]:
    """Run parallel port scans with live progress UI."""
    results_list: list[list[HostResult]] = [[] for _ in port_ranges]
    found_ports: dict[int, list[int]] = {idx: [] for idx in range(len(port_ranges))}
    range_errors: dict[int, str] = {}

    def create_progress_table() -> Table:
        table = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
        table.add_column("Status", style="cyan", width=3)
        table.add_column("Range", style="bold white", width=16)
        table.add_column("Progress", width=12)
        table.add_column("Found", style="green", width=20)

        for idx, port_range in enumerate(port_ranges):
            status = "[green]✓[/]" if results_list[idx] else "[cyan]●[/]"
            progress = "[dim]done[/]" if results_list[idx] else "[cyan]scanning[/]"

            ports_found = found_ports[idx]
            if ports_found:
                if len(ports_found) <= 3:
                    found_str = f"[green]{', '.join(map(str, ports_found))}[/]"
                else:
                    found_str = f"[green]{len(ports_found)} ports[/]"
            else:
                found_str = "[dim]—[/]"

            table.add_row(status, f"[bold]{port_range}[/]", progress, found_str)

        return table

    def create_display() -> Panel:
        return Panel(
            create_progress_table(),
            title=f"[bold cyan]Port Scan[/] [dim]({scanner_type})[/]",
            subtitle=f"[dim]{target}[/]",
            border_style="cyan",
            padding=(0, 1),
        )

    async def scan_range(idx: int, port_range: str) -> None:
        try:
            result = await discovery._run_port_scan(
                scanner,
                scanner_type,
                target,
                port_range,
                verbose,
            )
            results_list[idx] = result
            for host in result:
                for port in host.ports:
                    if port.state == "open":
                        found_ports[idx].append(port.port)
        except Exception as exc:
            range_errors[idx] = str(exc)
            if verbose:
                console.print(f"[red]Error scanning {port_range}: {exc}[/]")
            results_list[idx] = []

    with Live(create_display(), console=console, refresh_per_second=4) as live:
        tasks = [scan_range(idx, port_range) for idx, port_range in enumerate(port_ranges)]
        pending = {asyncio.ensure_future(task) for task in tasks}
        while pending:
            _, pending = await asyncio.wait(
                pending,
                timeout=0.25,
                return_when=asyncio.FIRST_COMPLETED,
            )
            live.update(create_display())

    if range_errors:
        ordered_errors = [
            f"{port_ranges[idx]} ({error})"
            for idx, error in sorted(range_errors.items(), key=lambda item: item[0])
        ]
        sample = "; ".join(ordered_errors[:3])
        if len(ordered_errors) > 3:
            sample += "; ..."
        raise RuntimeError(
            f"Port scan failed for {len(range_errors)}/{len(port_ranges)} ranges: {sample}"
        )

    total_ports = sum(len(ports) for ports in found_ports.values())
    if total_ports > 0:
        console.print(f"[green]✓[/] Found [bold green]{total_ports}[/] open ports")
    else:
        console.print("[yellow]○[/] No open ports found")

    return discovery._merge_host_results(results_list, target)
