"""LAN discovery CLI command."""

import asyncio

import typer

from clawpwn.modules.network import HostInfo

from .deps import cli_module
from .scan_helpers import (
    coerce_nonnegative_int,
    coerce_positive_int,
    normalize_depth,
    normalize_scanner,
    normalize_verbose,
)
from .shared import UDP_TOP_PORTS, app, console


@app.command("discover")
@app.command("lan")
def discover(
    network: str = typer.Option(
        ...,
        "--range",
        "-r",
        help="Network range in CIDR notation (e.g., 192.168.1.0/24)",
    ),
    scan_hosts: bool = typer.Option(
        False,
        "--scan-hosts",
        help="Port-scan discovered hosts after ping sweep",
    ),
    depth: str = typer.Option("quick", "--depth", help="Host scan depth: quick, normal, deep"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose scan output"),
    scanner: str = typer.Option(
        "rustscan",
        "--scanner",
        "-s",
        help="Port scanner: rustscan, masscan, nmap, naabu",
    ),
    parallel: int = typer.Option(
        4,
        "--parallel",
        "-p",
        help="Number of parallel port groups for range scans",
    ),
    verify_tcp: bool = typer.Option(
        False,
        "--verify-tcp",
        help="Run TCP connect service detection on open ports",
    ),
    udp: bool = typer.Option(False, "--udp", help="Include UDP scan (top ports only)"),
    udp_full: bool = typer.Option(
        False,
        "--udp-full",
        help="Scan full UDP range (1-65535); implies --udp",
    ),
    max_hosts: int = typer.Option(0, "--max-hosts", help="Limit hosts to scan (0 = no limit)"),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        help="Concurrent host scans when --scan-hosts is enabled",
    ),
) -> None:
    """Discover live hosts on a LAN and optionally scan them."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    effective_verbose = normalize_verbose(verbose)
    scanner_name = normalize_scanner(scanner)
    depth_value = normalize_depth(depth)
    parallel_groups = coerce_positive_int(parallel, default=4)
    max_hosts_value = coerce_nonnegative_int(max_hosts, default=0)
    concurrency_value = coerce_positive_int(concurrency, default=5)
    verify_tcp_value = verify_tcp if isinstance(verify_tcp, bool) else False
    udp_value = udp if isinstance(udp, bool) else False
    udp_full_value = udp_full if isinstance(udp_full, bool) else False
    if udp_full_value:
        udp_value = True
    udp_ports = "1-65535" if udp_full_value else UDP_TOP_PORTS

    session = cli.SessionManager(db_path)
    project = session.get_project()

    console.print(f"[blue]Starting LAN discovery for {network}...[/blue]")

    async def run_discovery():
        discovery = cli.NetworkDiscovery(project_dir)
        hosts = await discovery.discover_hosts(network)
        return hosts, discovery

    try:
        hosts, discovery = cli.safe_async_run(run_discovery())
    except Exception as exc:
        console.print(f"[red]LAN discovery failed: {exc}[/red]")
        raise typer.Exit(1) from exc

    if not hosts:
        console.print("[yellow]No live hosts found.[/yellow]")
        if project:
            session.add_log(f"LAN discovery {network}: 0 hosts", phase="Reconnaissance")
        return

    host_count = len(hosts)
    console.print(f"[green]Discovery complete: {host_count} live hosts[/green]")
    if host_count <= 20:
        for host in hosts:
            console.print(f"  [cyan]{host}[/cyan]")
    else:
        preview = ", ".join(hosts[:10])
        console.print(f"[dim]Preview:[/dim] {preview} [dim]...[/dim]")

    if project:
        session.add_log(f"LAN discovery {network}: {host_count} hosts", phase="Reconnaissance")

    scan_hosts_value = scan_hosts if isinstance(scan_hosts, bool) else False
    if not scan_hosts_value:
        return

    if max_hosts_value and host_count > max_hosts_value:
        console.print(f"[yellow]Limiting host scans to first {max_hosts_value} hosts[/yellow]")
        hosts = hosts[:max_hosts_value]

    console.print(f"[blue]Scanning {len(hosts)} discovered hosts (depth={depth_value})...[/blue]")

    async def run_host_scans() -> list[HostInfo]:
        semaphore = asyncio.Semaphore(concurrency_value)

        async def scan_one(host: str) -> HostInfo | None:
            async with semaphore:
                try:
                    return await discovery.scan_host(
                        host,
                        scan_type=depth_value,
                        full_scan=False,
                        verbose=effective_verbose,
                        include_udp=udp_value,
                        verify_tcp=verify_tcp_value,
                        ports_udp=udp_ports if udp_value else None,
                        scanner_type=scanner_name,
                        parallel_groups=parallel_groups,
                    )
                except Exception as exc:
                    console.print(f"[red]Scan failed for {host}: {exc}[/red]")
                    return None

        results = await asyncio.gather(*(scan_one(host) for host in hosts))
        return [result for result in results if result is not None]

    try:
        host_results = cli.safe_async_run(run_host_scans())
    except Exception as exc:
        console.print(f"[red]Host scanning failed: {exc}[/red]")
        raise typer.Exit(1) from exc

    console.print(f"[green]Host scans complete: {len(host_results)} hosts scanned[/green]")
    if project:
        session.add_log(
            f"LAN host scans complete: {len(host_results)} hosts",
            phase="Reconnaissance",
        )
