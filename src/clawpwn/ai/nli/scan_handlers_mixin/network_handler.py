"""Network scan handler for NLI."""

from clawpwn.ai.nli.constants import UDP_TOP_PORTS
from clawpwn.utils.async_utils import safe_async_run


def handle_network_scan(
    handler, scan_target: str, params: dict[str, str], command: str
) -> dict[str, object]:
    """Handle network (host) scanning."""
    from clawpwn.modules.network import NetworkDiscovery

    discovery = NetworkDiscovery(handler.project_dir)
    command_preview = "!scan"
    execution_note = "Running network scan"
    try:
        depth = handler._param_str(params, "depth", "deep")
        scanner = handler._param_str(params, "scanner", "nmap")
        parallel = handler._param_int(params, "parallel", 40)
        verify_tcp = handler._param_bool(params, "verify_tcp", True)
        udp = handler._param_bool(params, "udp", True)
        udp_full = handler._param_bool(params, "udp_full", False)
        verbose = handler._param_bool(params, "verbose", True)
        ports_spec = handler._ports_spec(params)
        if udp_full:
            udp = True
        udp_ports = "1-65535" if udp_full else UDP_TOP_PORTS
        command_preview = handler._build_scan_command_preview(
            scanner, depth, verbose, parallel, udp_full
        )
        execution_note = handler._build_scan_execution_note(
            scan_target, scanner, depth, verify_tcp, udp, udp_full, verbose
        )
        host_info = safe_async_run(
            discovery.scan_host(
                scan_target,
                scan_type=depth,
                full_scan=depth == "deep",
                verbose=verbose,
                verify_tcp=verify_tcp,
                include_udp=udp,
                ports_udp=udp_ports if udp else None,
                ports_tcp=ports_spec,
                scanner_type=scanner,
                parallel_groups=parallel,
            )
        )
        open_ports = ", ".join(str(p) for p in host_info.open_ports) or "none"
        return {
            "success": True,
            "response": f"Host scan complete. Open ports: {open_ports}.",
            "action": "scan",
            "executed_command": command_preview,
            "execution_note": execution_note,
        }
    except Exception as e:
        return {
            "success": False,
            "response": f"Scan failed: {e}",
            "action": "scan",
            "executed_command": command_preview,
            "execution_note": execution_note,
        }
