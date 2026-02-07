"""Base mixin class for scan handlers."""


class ScanHandlersMixin:
    """Handlers for scan-related intents."""

    def _handle_scan(self, target: str, parsed: dict[str, str], command: str) -> dict[str, object]:
        """Delegate to web or network handler based on target type."""

        params = self._get_params(parsed)
        scan_target = target or self._extract_url(command) or self._get_current_target()

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
            from .network_handler import handle_network_scan

            return handle_network_scan(self, scan_target, params, command)

        from .web_handler import handle_web_scan

        return handle_web_scan(self, scan_target, params, command)

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
