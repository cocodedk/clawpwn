"""Web scan runner for CLI scan command."""

import time

from clawpwn.modules.webscan import (
    WebScanConfig,
    WebScanOrchestrator,
    create_default_webscan_plugins,
)

from ..shared import console, detect_scheme


async def run_web_scan_for_url(
    cli,
    project_dir,
    target_url: str,
    effective_depth: str,
    selected_web_tools: list[str],
    effective_web_timeout: float,
    effective_web_concurrency: int,
    effective_verbose: bool,
):
    """Run web application scan for a direct URL."""
    web_orchestrator = WebScanOrchestrator(
        plugins=create_default_webscan_plugins(project_dir, scanner_factory=cli.Scanner)
    )
    web_config = WebScanConfig(
        depth=effective_depth,
        timeout=effective_web_timeout,
        concurrency=effective_web_concurrency,
        verbose=effective_verbose,
    )

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


async def run_web_scan_for_services(
    cli,
    project_dir,
    host_info,
    host_target: str,
    effective_depth: str,
    selected_web_tools: list[str],
    effective_web_timeout: float,
    effective_web_concurrency: int,
    effective_verbose: bool,
):
    """Run web application scans for discovered services."""
    web_orchestrator = WebScanOrchestrator(
        plugins=create_default_webscan_plugins(project_dir, scanner_factory=cli.Scanner)
    )
    web_config = WebScanConfig(
        depth=effective_depth,
        timeout=effective_web_timeout,
        concurrency=effective_web_concurrency,
        verbose=effective_verbose,
    )

    all_findings = []
    web_services = [
        service for service in host_info.services if service.name in ["http", "https", "http-proxy"]
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
            console.print(f"[green]Web scans found {len(all_findings)} potential issue(s).[/green]")
    else:
        console.print(
            "[yellow]No URL scheme detected and no web services found; "
            "network discovery and enumeration completed.[/yellow]"
        )
    return all_findings, web_services
