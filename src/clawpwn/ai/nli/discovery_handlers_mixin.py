"""Discovery and research handlers for NLI."""

from clawpwn.ai.nli.constants import UDP_TOP_PORTS


class DiscoveryHandlersMixin:
    """Handlers for network discovery and vuln research intents."""

    def _handle_discover(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        from clawpwn.utils.async_utils import safe_async_run

        params = self._get_params(parsed)
        network = target or self._extract_network(command)
        if not network:
            return {
                "success": False,
                "response": "Please specify a network range (e.g., '192.168.1.0/24')",
                "action": "discover",
                "needs_input": True,
            }

        from clawpwn.modules.network import NetworkDiscovery

        try:
            discovery = NetworkDiscovery(self.project_dir)
            hosts = safe_async_run(discovery.discover_hosts(network))

            scan_hosts = self._param_bool(params, "scan_hosts", False)
            if not scan_hosts and any(
                word in command.lower() for word in ("port", "ports", "service", "scan hosts")
            ):
                scan_hosts = True

            if not scan_hosts:
                preview = ", ".join(hosts[:5])
                suffix = "..." if len(hosts) > 5 else ""
                return {
                    "success": True,
                    "response": f"Found {len(hosts)} live hosts on {network}: {preview}{suffix}",
                    "action": "discover",
                    "hosts": hosts,
                }

            max_hosts = self._param_int(params, "max_hosts", 0)
            if max_hosts > 0:
                hosts = hosts[:max_hosts]

            depth = self._param_str(params, "depth", "quick")
            scanner = self._param_str(params, "scanner", "rustscan")
            parallel = self._param_int(params, "parallel", 4)
            verify_tcp = self._param_bool(params, "verify_tcp", True)
            udp = self._param_bool(params, "udp", False)
            udp_full = self._param_bool(params, "udp_full", False)
            ports_spec = self._ports_spec(params)
            concurrency = self._param_int(params, "concurrency", 5)
            if udp_full:
                udp = True
            udp_ports = "1-65535" if udp_full else UDP_TOP_PORTS

            async def run_scans():
                import asyncio

                semaphore = asyncio.Semaphore(max(1, concurrency))

                async def scan_one(host: str):
                    async with semaphore:
                        return await discovery.scan_host(
                            host,
                            scan_type=depth,
                            full_scan=depth == "deep",
                            verify_tcp=verify_tcp,
                            include_udp=udp,
                            ports_udp=udp_ports if udp else None,
                            ports_tcp=ports_spec,
                            scanner_type=scanner,
                            parallel_groups=parallel,
                        )

                return await asyncio.gather(*(scan_one(h) for h in hosts), return_exceptions=True)

            results = safe_async_run(run_scans())
            scanned = sum(1 for r in results if not isinstance(r, Exception))
            with_open = sum(
                1
                for r in results
                if not isinstance(r, Exception) and getattr(r, "open_ports", None)
            )
            return {
                "success": True,
                "response": f"Scanned {scanned} hosts. Hosts with open ports: {with_open}.",
                "action": "discover",
                "hosts": hosts,
            }
        except Exception as e:
            return {"success": False, "response": f"Discovery failed: {e}", "action": "discover"}

    def _handle_research(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        from clawpwn.utils.async_utils import safe_async_run

        service_info = self._extract_service_info(command)
        if not service_info.get("service"):
            return {
                "success": False,
                "response": "Please specify what to research (e.g., 'research apache 2.4')",
                "action": "research",
                "needs_input": True,
            }

        from clawpwn.modules.vulndb import VulnDB

        try:
            vulndb = VulnDB()
            results = safe_async_run(
                vulndb.research_service(service_info["service"], service_info.get("version", ""))
            )
            cves = results.get("cves", [])
            exploits = results.get("exploits", [])
            response = f"Research complete for {service_info['service']}:\n"
            response += f"  CVEs found: {len(cves)}\n"
            response += f"  Exploits available: {len(exploits)}\n"
            return {"success": True, "response": response, "action": "research"}
        except Exception as e:
            return {"success": False, "response": f"Research failed: {e}", "action": "research"}
