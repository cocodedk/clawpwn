"""Host scan workflow helper."""

from typing import Any

from .scan_display import run_scan_with_live_display


async def scan_host(
    discovery: Any,
    target: str,
    scan_type: str,
    full_scan: bool,
    verbose: bool,
    include_udp: bool,
    verify_tcp: bool,
    ports_tcp: str | None,
    ports_udp: str | None,
    scanner_type: str,
    parallel_groups: int,
    *,
    console: Any,
    env: Any,
    nmap_factory: Any,
    host_info_cls: Any,
    service_info_cls: Any,
    parse_port_spec: Any,
    split_port_range: Any,
) -> Any:
    """Scan one host and return HostInfo-like result."""
    console.print(f"[bold cyan]Scanning[/] [bold]{target}[/]")
    ports = ports_tcp or discovery._ports_for_scan(scan_type, full_scan)
    scanner = discovery._get_port_scanner(scanner_type)
    parsed = parse_port_spec(ports)
    if parsed and parallel_groups > 1:
        low, high = parsed
        port_ranges = split_port_range(low, high, parallel_groups)
    else:
        port_ranges = [ports]

    if len(port_ranges) > 1:
        results = await discovery._run_parallel_scan_with_progress(
            scanner,
            scanner_type,
            target,
            port_ranges,
            verbose,
        )
    else:
        results = await run_scan_with_live_display(
            scan_coro_factory=lambda **kw: discovery._run_port_scan(
                scanner, scanner_type, target, ports, verbose, **kw
            ),
            scanner_type=scanner_type,
            target=target,
            console=console,
        )

    host_info = host_info_cls(ip=target, hostname="", os="")
    host_result = results[0] if results else None
    if not host_result:
        host_info.notes = f"No response from {scanner_type}"

    if host_result:
        for port in host_result.ports:
            if port.state != "open":
                continue
            host_info.open_ports.append(port.port)
            service_name = discovery._guess_service(port.port)
            host_info.services.append(
                service_info_cls(
                    port=port.port,
                    protocol=port.protocol,
                    name=service_name,
                    version="",
                    product="",
                    banner=service_name,
                )
            )

    if verify_tcp:
        if discovery.nmap is None:
            discovery.nmap = nmap_factory()

        if host_info.open_ports:
            tcp_ports = ",".join(str(port) for port in sorted(set(host_info.open_ports)))
            port_count = len(host_info.open_ports)
            status_msg = f"[cyan]Service detection[/] [dim]({port_count} ports)[/]"
        else:
            tcp_ports = ports
            host_info.notes = (
                host_info.notes + "; TCP connect scan fallback"
                if host_info.notes
                else "TCP connect scan fallback"
            )
            status_msg = "[cyan]TCP connect scan[/] [dim](full range)[/]"

        with console.status(status_msg, spinner="dots"):
            tcp_results = await discovery.nmap.scan_host_tcp_connect(
                target,
                ports=tcp_ports,
                version_detection=True,
                verbose=verbose,
            )

        if tcp_results:
            tcp_host = tcp_results[0]
            host_info.services = []
            host_info.open_ports = []
            for port in tcp_host.ports:
                if port.state != "open":
                    continue
                host_info.services.append(
                    service_info_cls(
                        port=port.port,
                        protocol=port.protocol,
                        name=port.service,
                        version=port.version,
                        product=port.product,
                        banner=f"{port.product} {port.version}".strip(),
                    )
                )
                host_info.open_ports.append(port.port)
            console.print(
                f"[green]✓[/] Service detection: "
                f"[bold green]{len(host_info.services)}[/] services identified"
            )
        else:
            console.print("[yellow]○[/] Service detection: no results")
    lookup_on = env.get("CLAWPWN_VULN_LOOKUP", "true").lower() in {"1", "true", "yes", "on"}
    max_vulns = int(env.get("CLAWPWN_VULN_MAX_RESULTS", "3"))
    if include_udp:
        if discovery.nmap is None:
            discovery.nmap = nmap_factory()
        udp_ports = ports_udp or env.get("CLAWPWN_MASSCAN_PORTS_UDP", "1-65535")

        if lookup_on and host_info.services:
            udp_results, vuln_lines = await discovery._run_udp_and_vuln_parallel(
                target,
                udp_ports,
                host_info,
                verbose,
                max_vulns,
            )
            uf = _merge_udp_results(host_info, udp_results, service_info_cls)
            _print_udp(console, uf)
            if vuln_lines:
                console.print("\n[bold]Vulnerability lookup:[/bold]")
                console.print("\n".join(vuln_lines))
        else:
            with console.status(
                "[cyan]UDP scan[/] [dim](this may take a while)[/]", spinner="dots"
            ):
                udp_results = await discovery.nmap.scan_host_udp(
                    target, ports=udp_ports, verbose=verbose
                )
            _print_udp(console, _merge_udp_results(host_info, udp_results, service_info_cls))

    if lookup_on and host_info.services and not include_udp:
        vuln_lines = await discovery._run_vuln_lookup(host_info.services, max_results=max_vulns)
        if vuln_lines:
            console.print("\n[bold]Vulnerability lookup:[/bold]")
            console.print("\n".join(vuln_lines))

    host_info.open_ports = sorted(set(host_info.open_ports))
    if discovery.session:
        discovery.session.add_log(
            f"Discovered host {target}: {len(host_info.open_ports)} open ports",
            phase="Reconnaissance",
        )

    return host_info


def _merge_udp_results(host_info: Any, udp_results: list[Any], svc_cls: Any) -> int:
    if not udp_results:
        return 0
    count = 0
    for p in udp_results[0].ports:
        if p.state != "open":
            continue
        count += 1
        host_info.open_ports.append(p.port)
        host_info.services.append(
            svc_cls(
                port=p.port,
                protocol=p.protocol,
                name=p.service or "udp",
                version=p.version,
                product=p.product,
                banner=f"{p.product} {p.version}".strip(),
            )
        )
    return count


def _print_udp(console: Any, udp_found: int) -> None:
    if udp_found > 0:
        console.print(f"[green]✓[/] UDP scan: [bold green]{udp_found}[/] open ports")
    else:
        console.print("[yellow]○[/] UDP scan: no open ports")
