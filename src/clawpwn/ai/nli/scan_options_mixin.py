"""Scan option helpers for NLI."""

import re

from clawpwn.ai.nli.constants import VULN_CATEGORIES, VULN_CATEGORY_ALIASES

SUPPORTED_WEB_TOOLS = (
    "builtin",
    "nuclei",
    "feroxbuster",
    "ffuf",
    "nikto",
    "searchsploit",
    "zap",
)


class ScanOptionsMixin:
    """Helpers for rendering and validating scan options."""

    def _build_scan_command_preview(
        self,
        scanner: str,
        depth: str,
        verbose: bool,
        parallel: int,
        udp_full: bool,
        web_tools: list[str] | None = None,
        web_timeout: float | None = None,
        web_concurrency: int | None = None,
    ) -> str:
        parts = ["!scan", "--scanner", scanner, "--depth", depth]
        if verbose:
            parts.append("--verbose")
        if parallel != 4:
            parts.extend(["--parallel", str(parallel)])
        if udp_full:
            parts.append("--udp-full")
        if web_tools:
            joined = ",".join(web_tools)
            if joined != "builtin":
                parts.extend(["--web-tools", joined])
        if web_timeout is not None and web_timeout != 45.0:
            parts.extend(["--web-timeout", str(int(web_timeout))])
        if web_concurrency is not None and web_concurrency != 10:
            parts.extend(["--web-concurrency", str(web_concurrency)])
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

    def _parse_web_tools(self, params: dict[str, object]) -> list[str]:
        raw = params.get("web_tools") or params.get("web_tool")
        if raw is None:
            return ["builtin"]
        if isinstance(raw, list):
            tokens = [str(item).strip().lower() for item in raw if str(item).strip()]
        else:
            tokens = [part.strip().lower() for part in str(raw).split(",") if part.strip()]

        aliases = {
            "default": "builtin",
            "owasp-zap": "zap",
            "zap-baseline": "zap",
            "dirbuster": "feroxbuster",
            "dirb": "feroxbuster",
        }
        selected: list[str] = []
        for token in tokens:
            normalized = aliases.get(token, token)
            if normalized == "all":
                return list(SUPPORTED_WEB_TOOLS)
            if normalized in SUPPORTED_WEB_TOOLS and normalized not in selected:
                selected.append(normalized)
        return selected or ["builtin"]

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

    # ------------------------------------------------------------------
    # Vulnerability category helpers
    # ------------------------------------------------------------------

    def _parse_vuln_categories(self, params: dict[str, object]) -> list[str]:
        """Extract normalized vulnerability category keys from params."""
        raw = params.get("vuln_categories") or params.get("vuln_category")
        if raw is None:
            return []
        if isinstance(raw, list):
            tokens = [str(item).strip().lower() for item in raw if str(item).strip()]
        else:
            tokens = [part.strip().lower() for part in str(raw).split(",") if part.strip()]

        categories: list[str] = []
        for token in tokens:
            normalized = VULN_CATEGORY_ALIASES.get(token, token)
            if normalized in VULN_CATEGORIES and normalized not in categories:
                categories.append(normalized)
        return categories

    def _tools_for_categories(self, categories: list[str]) -> list[str]:
        """Return the union of recommended web tools for the given categories."""
        tools: list[str] = []
        for cat in categories:
            info = VULN_CATEGORIES.get(cat, {})
            for tool in info.get("tools", []):
                if tool not in tools:
                    tools.append(tool)
        return tools

    def _category_labels(self, categories: list[str]) -> list[str]:
        """Return human-readable labels for the given category keys."""
        return [VULN_CATEGORIES[cat]["label"] for cat in categories if cat in VULN_CATEGORIES]

    def _category_scan_types(self, categories: list[str]) -> list[str]:
        """Map category keys to the scan_types values used by the scanner."""
        return categories if categories else ["all"]
