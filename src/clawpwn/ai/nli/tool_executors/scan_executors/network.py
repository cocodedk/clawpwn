"""Network scan executor for NLI tool agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


def _format_services(host_info: Any) -> str:
    """Format discovered services with product/version info."""
    lines: list[str] = []
    for svc in getattr(host_info, "services", []):
        product = getattr(svc, "product", "") or ""
        version = getattr(svc, "version", "") or ""
        name = getattr(svc, "name", "") or ""
        label = f"{product} {version}".strip() or name
        lines.append(f"  {svc.port}/{svc.protocol}: {label}")
    return "\n".join(lines)


def execute_network_scan(params: dict[str, Any], project_dir: Path) -> str:
    """Run a host port scan."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.network import NetworkDiscovery
    from clawpwn.modules.session import SessionManager

    target = params["target"]
    depth = params.get("depth", "deep")
    scanner = params.get("scanner", "nmap")
    udp = params.get("udp", True)
    udp_full = params.get("udp_full", False)
    verify_tcp = params.get("verify_tcp", True)
    parallel = params.get("parallel", 4)
    ports_tcp = params.get("ports")
    if udp_full:
        udp = True
    udp_ports = "1-65535" if udp_full else "53,67,123,161,500,514,1434,1900,5353"

    discovery = NetworkDiscovery(project_dir)
    try:
        host_info = safe_async_run(
            discovery.scan_host(
                target,
                scan_type=depth,
                full_scan=depth == "deep",
                verbose=False,
                verify_tcp=verify_tcp,
                include_udp=udp,
                ports_udp=udp_ports if udp else None,
                ports_tcp=ports_tcp,
                scanner_type=scanner,
                parallel_groups=parallel,
            )
        )
        # Build rich output with service versions
        svc_lines = _format_services(host_info)
        open_ports = ", ".join(str(p) for p in host_info.open_ports) or "none"

        # Log the scan action
        try:
            db_path = get_project_db_path(project_dir)
            if db_path:
                session = SessionManager(db_path)
                session.add_log(
                    message=f"network_scan: {scanner} depth={depth} -> {len(host_info.open_ports)} ports",
                    level="INFO",
                    phase="scan",
                    details=json.dumps(
                        {
                            "tool": "network_scan",
                            "scanner": scanner,
                            "depth": depth,
                            "target": target,
                            "open_ports_count": len(host_info.open_ports),
                            "open_ports": list(host_info.open_ports)[:20],
                        }
                    ),
                )
        except Exception:
            pass

        if not host_info.open_ports:
            return (
                f"Host scan of {target}: NO OPEN PORTS FOUND. "
                "The host may be down, unreachable, or firewalled. "
                "Verify the target IP is correct before continuing."
            )
        if svc_lines:
            return f"Host scan of {target} complete.\nServices:\n{svc_lines}"
        return f"Host scan of {target} complete. Open ports: {open_ports}."
    except Exception as exc:
        return f"Network scan failed: {exc}"
