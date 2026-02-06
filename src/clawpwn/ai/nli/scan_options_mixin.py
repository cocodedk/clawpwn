"""Scan option helpers for NLI."""

import re


class ScanOptionsMixin:
    """Helpers for rendering and validating scan options."""

    def _build_scan_command_preview(
        self,
        scanner: str,
        depth: str,
        verbose: bool,
        parallel: int,
        udp_full: bool,
    ) -> str:
        parts = ["!scan", "--scanner", scanner, "--depth", depth]
        if verbose:
            parts.append("--verbose")
        if parallel != 4:
            parts.extend(["--parallel", str(parallel)])
        if udp_full:
            parts.append("--udp-full")
        return " ".join(parts)

    def _build_scan_execution_note(
        self,
        target: str,
        scanner: str,
        depth: str,
        verify_tcp: bool,
        include_udp: bool,
        udp_full: bool,
        verbose: bool,
    ) -> str:
        details: list[str] = [scanner, depth]
        if verify_tcp:
            details.append("service detection")
        if include_udp:
            details.append("udp full" if udp_full else "udp top ports")
        if verbose:
            details.append("verbose")
        return f"Running host scan on {target} ({', '.join(details)})."

    def _ports_spec(self, params: dict[str, object]) -> str | None:
        ports = params.get("ports") or params.get("port")
        if not ports:
            return None
        if isinstance(ports, list):
            cleaned_list = [str(p).strip() for p in ports if str(p).strip()]
            if not cleaned_list:
                return None
            joined = ",".join(cleaned_list)
            return joined if re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", joined) else None
        if isinstance(ports, (int, float)):
            return str(int(ports))
        if isinstance(ports, str):
            cleaned = ports.strip().replace(" ", "").lower()
            if not cleaned:
                return None
            if cleaned in {"all", "allports", "full", "fullrange"}:
                return "1-65535"
            if re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", cleaned):
                return cleaned
        return None
