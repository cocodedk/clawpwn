"""Host scan workflow helper."""

from typing import Any


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
        console.print(f"[cyan]●[/] Port scan ([bold]{scanner_type}[/])")
        results = await discovery._run_port_scan(scanner, scanner_type, target, ports, verbose)

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

    lookup_enabled = env.get("CLAWPWN_VULN_LOOKUP", "true").lower() in {"1", "true", "yes", "on"}
    max_vuln_results = int(env.get("CLAWPWN_VULN_MAX_RESULTS", "3"))

    if include_udp:
        if discovery.nmap is None:
            discovery.nmap = nmap_factory()
        udp_ports = ports_udp or env.get("CLAWPWN_MASSCAN_PORTS_UDP", "1-65535")

        if lookup_enabled and host_info.services:
            udp_results, vuln_lines = await discovery._run_udp_and_vuln_parallel(
                target,
                udp_ports,
                host_info,
                verbose,
                max_vuln_results,
            )
            udp_found = _merge_udp_results(host_info, udp_results, service_info_cls)
            _print_udp_result(console, udp_found)
            if vuln_lines:
                console.print("\n[bold]Vulnerability lookup:[/bold]")
                console.print("\n".join(vuln_lines))
        else:
            with console.status(
                "[cyan]UDP scan[/] [dim](this may take a while)[/]", spinner="dots"
            ):
                udp_results = await discovery.nmap.scan_host_udp(
                    target,
                    ports=udp_ports,
                    verbose=verbose,
                )
            udp_found = _merge_udp_results(host_info, udp_results, service_info_cls)
            _print_udp_result(console, udp_found)

    if lookup_enabled and host_info.services and not include_udp:
        vuln_lines = await discovery._run_vuln_lookup(
            host_info.services, max_results=max_vuln_results
        )
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


def _merge_udp_results(host_info: Any, udp_results: list[Any], service_info_cls: Any) -> int:
    udp_found = 0
    if udp_results:
        udp_host = udp_results[0]
        for port in udp_host.ports:
            if port.state != "open":
                continue
            udp_found += 1
            host_info.open_ports.append(port.port)
            host_info.services.append(
                service_info_cls(
                    port=port.port,
                    protocol=port.protocol,
                    name=port.service or "udp",
                    version=port.version,
                    product=port.product,
                    banner=f"{port.product} {port.version}".strip(),
                )
            )
    return udp_found


def _print_udp_result(console: Any, udp_found: int) -> None:
    if udp_found > 0:
        console.print(f"[green]✓[/] UDP scan: [bold green]{udp_found}[/] open ports")
    else:
        console.print("[yellow]○[/] UDP scan: no open ports")
