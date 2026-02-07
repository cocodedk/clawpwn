"""Masscan JSON output parser."""

import json

from .scanner import HostResult, PortScanResult


def parse_masscan_json(output: str) -> list[HostResult]:
    """Parse masscan JSON output into HostResult objects."""
    data = output.strip()
    if not data:
        return []

    # Masscan sometimes emits trailing commas or extra whitespace
    cleaned = data.replace("\n", "").replace("\t", "").strip()
    if not cleaned.startswith("["):
        cleaned = f"[{cleaned}]"

    # Remove trailing commas before closing brackets
    cleaned = cleaned.replace(",]", "]").replace(",}", "}")

    try:
        items = json.loads(cleaned)
    except json.JSONDecodeError:
        return []

    hosts: dict[str, HostResult] = {}

    for item in items:
        ip = item.get("ip")
        if not ip:
            continue
        host = hosts.setdefault(ip, HostResult(ip=ip))
        for port_entry in item.get("ports", []):
            port = port_entry.get("port")
            proto = port_entry.get("proto", "tcp")
            status = port_entry.get("status", "open")
            if port is None:
                continue
            host.ports.append(
                PortScanResult(
                    port=int(port),
                    protocol=str(proto),
                    state=str(status),
                )
            )

    return list(hosts.values())
