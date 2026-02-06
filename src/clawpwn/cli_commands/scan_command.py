"""Scan CLI command."""

import os
import time

import typer

from clawpwn.modules.webscan import (
    WebScanConfig,
    WebScanOrchestrator,
    create_default_webscan_plugins,
)

from .deps import cli_module
from .scan_helpers import (
    coerce_positive_float,
    coerce_positive_int,
    normalize_depth,
    normalize_scanner,
    normalize_verbose,
    parse_web_tools,
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
    web_tools: str = typer.Option(
        "builtin",
        "--web-tools",
        help="Web scanners: builtin,nuclei,feroxbuster,ffuf,nikto,zap or all (comma-separated)",
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

        network = cli.NetworkDiscovery(project_dir)
        web_orchestrator = WebScanOrchestrator(
            plugins=create_default_webscan_plugins(project_dir, scanner_factory=cli.Scanner)
        )
        web_config = WebScanConfig(
            depth=effective_depth,
            timeout=effective_web_timeout,
            concurrency=effective_web_concurrency,
            verbose=effective_verbose,
        )

        scan_started = time.perf_counter()
        host_target = resolve_host_target(target_url)

        scan_type = "quick" if effective_depth == "quick" else "normal"
        full_scan = effective_depth == "deep"

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
            console.print(f"[*] Phase 2: Web Application Scanning ({effective_depth} mode)")
            console.print(f"[dim]Web tools: {', '.join(selected_web_tools)}[/dim]")
            web_started = time.perf_counter()
            web_findings, web_errors = await web_orchestrator.scan_target_with_diagnostics(
                target_url,
                config=web_config,
                tools=selected_web_tools,
                progress=lambda msg: console.print(f"[dim]{msg}[/dim]"),
            )
            findings = [finding.to_scan_result() for finding in web_findings]
            for error in web_errors:
                console.print(f"[yellow]! {error.tool}: {error.message}[/yellow]")
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
            console.print(f"[*] Phase 2: Web Application Scanning ({len(web_services)} service(s))")
            console.print(f"[dim]Web tools: {', '.join(selected_web_tools)}[/dim]")
            for service in web_services:
                url = f"{detect_scheme(host_target, service.port, service)}://{host_target}:{service.port}"
                console.print(f"[*] Scanning {url}...")
                web_started = time.perf_counter()
                web_findings, web_errors = await web_orchestrator.scan_target_with_diagnostics(
                    url,
                    config=web_config,
                    tools=selected_web_tools,
                    progress=lambda msg: console.print(f"[dim]{msg}[/dim]"),
                )
                findings = [finding.to_scan_result() for finding in web_findings]
                all_findings.extend(findings)
                for error in web_errors:
                    console.print(f"[yellow]! {error.tool}: {error.message}[/yellow]")
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
