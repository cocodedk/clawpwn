"""Scanner selection and scanner-specific execution methods."""

import os
from typing import Any

from clawpwn.tools.masscan import HostResult

from .deps import network_module


class ScannerMixin:
    """Provide scanner resolution and scanner-specific configuration."""

    def _get_port_scanner(self, scanner_type: str = "rustscan"):
        """Return the port scanner instance for the given type."""
        if self._port_scanner is not None and self._scanner_type == scanner_type:
            return self._port_scanner

        module = network_module()
        self._scanner_type = scanner_type
        if scanner_type == "rustscan":
            self._port_scanner = module.RustScanScanner()
        elif scanner_type == "masscan":
            self._port_scanner = module.MasscanScanner()
        elif scanner_type == "nmap":
            self._port_scanner = module.NmapScanner()
        elif scanner_type == "naabu":
            self._port_scanner = module.NaabuScanner()
        else:
            raise ValueError(
                f"Unknown scanner type: {scanner_type}. Use rustscan, masscan, nmap, or naabu."
            )
        return self._port_scanner

    async def _run_port_scan(
        self,
        scanner: Any,
        scanner_type: str,
        target: str,
        ports: str,
        verbose: bool,
    ) -> list[HostResult]:
        """Run port scan with scanner-specific arguments."""
        module = network_module()
        if scanner_type in ("rustscan", "masscan") and not module.can_raw_scan(scanner_type):
            raise RuntimeError(module.get_privilege_help(scanner_type))

        if scanner_type == "rustscan":
            batch_size = int(os.environ.get("CLAWPWN_RUSTSCAN_BATCH_SIZE", "5000"))
            timeout_ms = int(os.environ.get("CLAWPWN_RUSTSCAN_TIMEOUT_MS", "1000"))
            return await scanner.scan_host(
                target,
                ports=ports,
                batch_size=batch_size,
                timeout_ms=timeout_ms,
                verbose=verbose,
            )

        if scanner_type == "masscan":
            return await scanner.scan_host(
                target,
                ports=ports,
                rate=self._rate_for_scan(),
                interface=os.environ.get("CLAWPWN_MASSCAN_INTERFACE"),
                sudo=False,
                verbose=verbose,
            )

        if scanner_type == "nmap":
            return await scanner.scan_host(target, ports=ports, verbose=verbose)

        if scanner_type == "naabu":
            rate = int(os.environ.get("CLAWPWN_NAABU_RATE", "1000"))
            return await scanner.scan_host(target, ports=ports, rate=rate, verbose=verbose)

        raise ValueError(f"Unknown scanner type: {scanner_type}")

    def _rate_for_scan(self) -> int:
        rate = os.environ.get("CLAWPWN_MASSCAN_RATE", "10000")
        try:
            return int(rate)
        except ValueError:
            return 10000

    def _ports_for_scan(self, scan_type: str, full_scan: bool) -> str:
        if full_scan or scan_type in {"full", "deep"}:
            default = "1-65535"
            env_key = "CLAWPWN_MASSCAN_PORTS_DEEP"
        elif scan_type == "quick":
            default = "1-1024"
            env_key = "CLAWPWN_MASSCAN_PORTS_QUICK"
        else:
            default = "1-10000"
            env_key = "CLAWPWN_MASSCAN_PORTS_NORMAL"
        return os.environ.get(env_key, default)

    def _guess_service(self, port: int) -> str:
        common = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            3389: "rdp",
            8080: "http",
            8443: "https",
        }
        return common.get(port, "unknown")
