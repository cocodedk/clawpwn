"""Scan CLI command entrypoint."""

import typer

from ..deps import cli_module
from ..scan_helpers import (
    coerce_positive_float,
    coerce_positive_int,
    normalize_depth,
    normalize_scanner,
    normalize_verbose,
    parse_web_tools,
)
from ..shared import app, console
from .network_runner import ai_recommendations, run_network_scan
from .web_runner import run_web_scan_for_services, run_web_scan_for_url


@app.command()
def scan(
    auto: bool = typer.Option(False, "--auto", help="Run AI-guided scan automatically"),
    depth: str = typer.Option("normal", "--depth", help="Scan depth: quick, normal, deep"),
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
    udp_full: bool = typer.Option(
        False,
        "--udp-full",
        help="Scan full UDP range (1-65535); default is top common ports only",
    ),
    web_tools: str = typer.Option(
        "builtin",
        "--web-tools",
        help=(
            "Web scanners: builtin,nuclei,feroxbuster,ffuf,nikto,searchsploit,zap "
            "or all (comma-separated)"
        ),
    ),
    web_timeout: float = typer.Option(
        45.0,
        "--web-timeout",
        help="Per-tool web scanner timeout in seconds",
    ),
    web_concurrency: int = typer.Option(
        10,
        "--web-concurrency",
        help="Web scanner worker threads where supported",
    ),
) -> None:
    """Start the scanning phase."""
    cli = cli_module()
    effective_verbose = normalize_verbose(verbose)

    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    state = session.get_state()
    if not (state and state.target):
        console.print("[red]No target set. Run 'clawpwn target <url>' first.[/red]")
        raise typer.Exit(1)

    target_url = state.target
    has_scheme = "://" in target_url
    console.print(f"[blue]Starting scan phase for {target_url}...[/blue]")
    console.print("[*] Phase 1: Network Discovery")

    async def run_scan():
        port_scanner_name = normalize_scanner(scanner)
        effective_depth = normalize_depth(depth, default="normal")
        parallel_groups = coerce_positive_int(parallel, default=4)
        selected_web_tools = parse_web_tools(web_tools)
        effective_web_timeout = coerce_positive_float(web_timeout, default=45.0)
        effective_web_concurrency = coerce_positive_int(web_concurrency, default=10)

        host_info, host_target = await run_network_scan(
            cli,
            project_dir,
            target_url,
            has_scheme,
            effective_depth,
            port_scanner_name,
            parallel_groups,
            udp_full,
            effective_verbose,
        )

        if has_scheme:
            findings = await run_web_scan_for_url(
                cli,
                project_dir,
                target_url,
                effective_depth,
                selected_web_tools,
                effective_web_timeout,
                effective_web_concurrency,
                effective_verbose,
            )
            await ai_recommendations(cli, project_dir, host_info, host_target)
            return findings

        all_findings, web_services = await run_web_scan_for_services(
            cli,
            project_dir,
            host_info,
            host_target,
            effective_depth,
            selected_web_tools,
            effective_web_timeout,
            effective_web_concurrency,
            effective_verbose,
        )
        await ai_recommendations(cli, project_dir, host_info, host_target)
        return all_findings

    try:
        findings = cli.safe_async_run(run_scan())
        if findings:
            console.print(
                f"\n[green]Scan complete! Found {len(findings)} potential issues.[/green]"
            )
            console.print("\n[dim]Use 'clawpwn status' to see detailed findings.[/dim]")
        else:
            console.print("\n[green]Scan complete! No obvious vulnerabilities found.[/green]")
        session.update_phase("Vulnerability Research")
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")
        raise typer.Exit(1) from exc
