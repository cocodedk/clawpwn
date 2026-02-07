"""Network scan runner for CLI scan command."""

import os
import time

from ..scan_helpers import resolve_host_target, service_summary, web_services_payload
from ..shared import UDP_TOP_PORTS, console


async def run_network_scan(
    cli,
    project_dir,
    target_url: str,
    has_scheme: bool,
    effective_depth: str,
    port_scanner_name: str,
    parallel_groups: int,
    udp_full: bool,
    effective_verbose: bool,
):
    """Run network discovery phase."""
    network = cli.NetworkDiscovery(project_dir)
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

    return host_info, host_target


async def ai_recommendations(cli, project_dir, host_info, host_target):
    """Generate AI recommendations based on scan results."""
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
