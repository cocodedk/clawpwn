"""Scan-focused intent handlers for NLI."""

from clawpwn.ai.nli.constants import UDP_TOP_PORTS


class ScanHandlersMixin:
    """Handlers for scan-related intents."""

    def _handle_scan(self, target: str, parsed: dict[str, str], command: str) -> dict[str, object]:
        from clawpwn.utils.async_utils import safe_async_run

        params = self._get_params(parsed)
        scan_target = target or self._extract_url(command) or self._get_current_target()
        command_preview = "!scan"
        execution_note = "Running scan"

        if not scan_target:
            lowered = command.lower()
            if any(
                word in lowered
                for word in ("port", "ports", "lan", "network", "subnet", "hosts", "cidr")
            ):
                return {
                    "success": False,
                    "response": "Please provide a target IP or CIDR range (e.g., 192.168.1.10 or 192.168.1.0/24).",
                    "action": "scan",
                    "needs_input": True,
                }
            return {
                "success": False,
                "response": "I need a target to scan. Please specify a URL or IP address.",
                "action": "scan",
                "needs_input": True,
            }

        if self._extract_network(scan_target):
            return self._handle_discover(scan_target, parsed, command)

        if "://" not in scan_target and not scan_target.lower().startswith("www."):
            from clawpwn.modules.network import NetworkDiscovery

            discovery = NetworkDiscovery(self.project_dir)
            command_preview = "!scan"
            execution_note = "Running network scan"
            try:
                depth = self._param_str(params, "depth", "deep")
                scanner = self._param_str(params, "scanner", "nmap")
                parallel = self._param_int(params, "parallel", 4)
                verify_tcp = self._param_bool(params, "verify_tcp", True)
                udp = self._param_bool(params, "udp", True)
                udp_full = self._param_bool(params, "udp_full", False)
                verbose = self._param_bool(params, "verbose", True)
                ports_spec = self._ports_spec(params)
                if udp_full:
                    udp = True
                udp_ports = "1-65535" if udp_full else UDP_TOP_PORTS
                command_preview = self._build_scan_command_preview(
                    scanner, depth, verbose, parallel, udp_full
                )
                execution_note = self._build_scan_execution_note(
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

        from clawpwn.modules.scanner import Scanner

        scanner = Scanner(self.project_dir)
        execution_note = f"Running web scan on {scan_target}."
        try:
            findings = safe_async_run(scanner.scan(scan_target))
            if findings:
                critical = len([f for f in findings if f.severity == "critical"])
                high = len([f for f in findings if f.severity == "high"])
                return {
                    "success": True,
                    "response": f"Scan complete! Found {len(findings)} issues ({critical} critical, {high} high). Check 'clawpwn status' for details.",
                    "action": "scan",
                    "findings_count": len(findings),
                    "executed_command": command_preview,
                    "execution_note": execution_note,
                }
            return {
                "success": True,
                "response": "Scan complete! No obvious vulnerabilities found.",
                "action": "scan",
                "findings_count": 0,
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

    def _handle_exploit(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        return {
            "success": False,
            "response": "To exploit a finding, use the killchain command or specify the finding ID. Use 'clawpwn killchain --auto' for AI-guided exploitation.",
            "action": "exploit",
            "needs_approval": True,
        }

    def _handle_find_vulns(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        return self._handle_scan(target, parsed, command)
