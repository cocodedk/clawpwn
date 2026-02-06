"""Discovery operations and output helpers."""

from typing import Any


async def discover_hosts(
    discovery: Any, network: str, *, console: Any, nmap_factory: Any
) -> list[str]:
    """Discover live hosts for a CIDR network."""
    console.print(f"[cyan]●[/] Discovering hosts on [bold]{network}[/]...")
    if discovery.nmap is None:
        discovery.nmap = nmap_factory()
    hosts = await discovery.nmap.ping_sweep(network)
    console.print(f"[green]✓[/] Found [bold green]{len(hosts)}[/] live hosts")
    return hosts


async def enumerate_target(discovery: Any, target: str) -> dict[str, Any]:
    """Run full target enumeration."""
    results: dict[str, Any] = {
        "target": target,
        "hosts": [],
        "services": [],
        "web_services": [],
    }

    host_info = await discovery.scan_host(target, scan_type="normal")
    results["hosts"].append(host_info)

    for service in host_info.services:
        results["services"].append(
            {
                "port": service.port,
                "name": service.name,
                "version": service.version,
                "product": service.product,
            }
        )
        if service.name in ["http", "https", "http-proxy"]:
            results["web_services"].append(
                {
                    "url": f"{'https' if service.port == 443 else 'http'}://{target}:{service.port}",
                    "port": service.port,
                    "service": service.name,
                }
            )

    return results


def print_summary(results: dict[str, Any]) -> None:
    """Print discovery summary output."""
    print("\n" + "=" * 60)
    print("NETWORK DISCOVERY SUMMARY")
    print("=" * 60)

    for host in results.get("hosts", []):
        print(f"\nHost: {host.ip} ({host.hostname or 'unknown'})")
        print(f"OS: {host.os or 'unknown'}")

        if host.services:
            print("\nOpen Ports:")
            for service in host.services:
                banner = f" - {service.banner}" if service.banner else ""
                print(f"  {service.port}/{service.protocol}: {service.name}{banner}")

    web_services = results.get("web_services", [])
    if web_services:
        print("\nWeb Services Found:")
        for web in web_services:
            print(f"  {web['url']}")

    print("=" * 60)
