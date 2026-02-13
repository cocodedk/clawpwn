"""Vulnerability lookup and UDP parallel task helpers."""

import asyncio
from typing import Any

from rich.live import Live
from rich.panel import Panel
from rich.table import Table


async def run_vuln_lookup(
    services: list[Any],
    vulndb_factory: Any,
    max_results: int = 3,
    state: dict[str, Any] | None = None,
) -> list[str]:
    """Run vulnerability lookup for unique services."""
    unique: dict[str, tuple[str, str]] = {}
    for service in services:
        # Prefer product (e.g. "vsftpd") over generic name (e.g. "ftp")
        label = getattr(service, "product", "") or service.name
        if not label:
            continue
        key = f"{label}:{service.version}"
        if key not in unique:
            unique[key] = (label, service.version)
    if not unique:
        return []

    vulndb = vulndb_factory()
    results: list[str] = []
    for idx, (name, version) in enumerate(unique.values()):
        if state is not None:
            state["vuln_current"] = f"{name} {version}"
            state["vuln_index"] = idx + 1
            state["vuln_total"] = len(unique)
        try:
            exploits = await vulndb.find_exploits(name, version)
            if not exploits:
                line = f"- {name} {version}: no known exploits found"
            else:
                top = exploits[:max_results]
                titles = "; ".join(exploit.title for exploit in top)
                line = f"- {name} {version}: {titles}"
        except Exception as exc:
            line = f"- {name} {version}: lookup failed ({exc})"

        results.append(line)
        if state is not None:
            state["vuln_results"] = list(results)

    if state is not None:
        state["vuln_done"] = True
    return results


async def run_udp_and_vuln_parallel(
    discovery: Any,
    target: str,
    ports_udp: str,
    host_info: Any,
    verbose: bool,
    max_vuln_results: int,
    *,
    console: Any,
) -> tuple[list[Any], list[str]]:
    """Run UDP scan and vulnerability lookup concurrently with live status."""
    state: dict[str, Any] = {
        "udp_done": False,
        "udp_result": None,
        "vuln_done": False,
        "vuln_results": [],
        "vuln_current": "",
        "vuln_index": 0,
        "vuln_total": 0,
    }

    async def do_udp() -> None:
        result = await discovery.nmap.scan_host_udp(target, ports=ports_udp, verbose=verbose)
        state["udp_done"] = True
        state["udp_result"] = result

    async def do_vuln() -> None:
        await discovery._run_vuln_lookup(
            host_info.services,
            max_results=max_vuln_results,
            state=state,
        )

    def make_table() -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
        table.add_column("Status", style="cyan", width=3)
        table.add_column("Task", style="bold white", width=14)
        table.add_column("Detail", width=44)

        if state["udp_done"]:
            udp_result = state["udp_result"]
            count = 0
            if udp_result and udp_result[0].ports:
                count = sum(1 for port in udp_result[0].ports if port.state == "open")
            table.add_row("[green]✓[/]", "UDP scan", f"[dim]done[/] ({count} open)")
        else:
            table.add_row("[cyan]●[/]", "UDP scan", "[cyan]scanning...[/]")

        if state["vuln_total"]:
            if state["vuln_done"]:
                table.add_row(
                    "[green]✓[/]",
                    "Vuln lookup",
                    f"[dim]{state['vuln_index']}/{state['vuln_total']} done[/]",
                )
            else:
                table.add_row(
                    "[cyan]●[/]",
                    "Vuln lookup",
                    f"[dim]{state['vuln_current'] or '...'}[/]",
                )

        return Panel(
            table,
            title="[bold cyan]Parallel Tasks[/]",
            subtitle=f"[dim]{target}[/]",
            border_style="cyan",
            padding=(0, 1),
        )

    asyncio.create_task(do_udp())
    asyncio.create_task(do_vuln())

    with Live(make_table(), console=console, refresh_per_second=4) as live:
        while not (state["udp_done"] and state["vuln_done"]):
            live.update(make_table())
            await asyncio.sleep(0.25)

    return state["udp_result"] or [], state["vuln_results"]
