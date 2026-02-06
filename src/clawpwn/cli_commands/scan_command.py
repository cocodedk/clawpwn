"""Scan CLI command."""

import os
import time

import typer

from .deps import cli_module
from .scan_helpers import (
    coerce_positive_int,
    normalize_scanner,
    normalize_verbose,
    resolve_host_target,
    service_summary,
    web_services_payload,
)
from .shared import UDP_TOP_PORTS, app, console, detect_scheme


@app.command()
def scan(
    auto: bool = typer.Option(False, "--auto", help="Run AI-guided scan automatically"),
    depth: str = typer.Option("normal", "--depth", help="Scan depth: quick, normal, deep"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose scan output"),
    scanner: str = typer.Option(
        "rustscan",
        "--scanner",
        "-s",
        help="Port scanner: rustscan, masscan, nmap",
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
        parallel_groups = coerce_positive_int(parallel, default=4)

        web_scanner = cli.Scanner(project_dir)
        network = cli.NetworkDiscovery(project_dir)

        scan_started = time.perf_counter()
        host_target = resolve_host_target(target_url)

        scan_type = "quick" if depth == "quick" else "normal"
        full_scan = depth == "deep"

        if not has_scheme:
            ports_tcp = os.environ.get("CLAWPWN_MASSCAN_PORTS_TCP", "1-65535")
            ports_udp = os.environ.get(
                "CLAWPWN_MASSCAN_PORTS_UDP",
                "1-65535" if udp_full else UDP_TOP_PORTS,
            )
            host_info = await network.scan_host(
                host_target,
                scan_type="deep",
                full_scan=True,
                verbose=effective_verbose,
                include_udp=True,
                verify_tcp=True,
                ports_tcp=ports_tcp,
                ports_udp=ports_udp,
                scanner_type=port_scanner_name,
                parallel_groups=parallel_groups,
            )
        else:
            host_info = await network.scan_host(
                host_target,
                scan_type=scan_type,
                full_scan=full_scan,
                verbose=effective_verbose,
                scanner_type=port_scanner_name,
                parallel_groups=parallel_groups,
            )

        if effective_verbose:
            elapsed = time.perf_counter() - scan_started
            console.print(f"[dim]Network discovery completed in {elapsed:.2f}s[/dim]")

        network.print_summary(
            {
                "hosts": [host_info],
                "services": [
                    {
                        "port": service.port,
                        "name": service.name,
                        "version": service.version,
                        "product": service.product,
                    }
                    for service in host_info.services
                ],
                "web_services": web_services_payload(host_target, host_info.services),
            }
        )

        if has_scheme:
            config = cli.ScanConfig(target=target_url, depth=depth)
            console.print(f"[*] Phase 2: Web Application Scanning ({depth} mode)")
            web_started = time.perf_counter()
            findings = await web_scanner.scan(target_url, config)
            if effective_verbose:
                elapsed = time.perf_counter() - web_started
                console.print(f"[dim]Web scan completed in {elapsed:.2f}s[/dim]")
            return findings

        all_findings = []
        web_services = [
            service
            for service in host_info.services
            if service.name in ["http", "https", "http-proxy"]
        ]
        if web_services:
            config = cli.ScanConfig(target=host_target, depth=depth)
            console.print(f"[*] Phase 2: Web Application Scanning ({len(web_services)} service(s))")
            for service in web_services:
                url = f"{detect_scheme(host_target, service.port, service)}://{host_target}:{service.port}"
                console.print(f"[*] Scanning {url}...")
                web_started = time.perf_counter()
                findings = await web_scanner.scan(url, config)
                all_findings.extend(findings)
                if effective_verbose:
                    elapsed = time.perf_counter() - web_started
                    console.print(f"[dim]  Completed in {elapsed:.2f}s[/dim]")
            if all_findings:
                console.print(
                    f"[green]Web scans found {len(all_findings)} potential issue(s).[/green]"
                )

        console.print("[*] Phase 3: AI Recommendations")
        try:
            from clawpwn.ai.llm import LLMClient

            prompt = f"""Target: {host_target}
Open ports: {host_info.open_ports or []}
Services: {service_summary(host_info)}

Provide the next safe, authorized, low-risk enumeration steps. Do not exploit. Focus on validation, version checks, and service-specific recon. Return a short numbered list."""
            with LLMClient(project_dir=project_dir) as client:
                response = client.chat(
                    prompt,
                    system_prompt=(
                        "You are a penetration testing assistant. "
                        "Provide only safe, authorized, non-destructive next steps."
                    ),
                )
            console.print("\\n[bold]AI Next Steps:[/bold]")
            console.print(response.strip())
        except Exception as exc:
            console.print(
                "[yellow]AI guidance unavailable: "
                f"{exc}. Configure CLAWPWN_LLM_PROVIDER and CLAWPWN_LLM_API_KEY "
                "to enable recommendations.[/yellow]"
            )

        if not web_services:
            console.print(
                "[yellow]No URL scheme detected and no web services found; "
                "network discovery and enumeration completed.[/yellow]"
            )
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
