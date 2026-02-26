"""Helpers for scan-related CLI commands."""

import os
from urllib.parse import urlparse

from clawpwn.modules.network import HostInfo, ServiceInfo

from .shared import detect_scheme

WEB_TOOLS = ("builtin", "nuclei", "feroxbuster", "ffuf", "nikto", "searchsploit", "zap")


def normalize_verbose(verbose: bool) -> bool:
    """Resolve effective verbose flag from CLI arg and env var."""
    effective = verbose if isinstance(verbose, bool) else False
    if effective:
        return True
    env_verbose = os.environ.get("CLAWPWN_VERBOSE", "").lower()
    return env_verbose in {"1", "true", "yes", "on"}


def normalize_scanner(scanner: str | None, default: str = "rustscan") -> str:
    """Normalize and validate scanner name."""
    scanner_name = scanner.strip().lower() if isinstance(scanner, str) else default
    return scanner_name if scanner_name in {"rustscan", "masscan", "nmap", "naabu"} else default


def normalize_depth(depth: str | None, default: str = "quick") -> str:
    """Normalize and validate scan depth."""
    depth_name = depth.strip().lower() if isinstance(depth, str) else default
    return depth_name if depth_name in {"quick", "normal", "deep"} else default


def coerce_positive_int(value: int, default: int) -> int:
    """Return value when positive int-like, otherwise fallback default."""
    return max(1, int(value)) if isinstance(value, int) else default


def coerce_nonnegative_int(value: int, default: int) -> int:
    """Return non-negative integer with fallback default."""
    return max(0, int(value)) if isinstance(value, int) else default


def coerce_positive_float(value: float, default: float) -> float:
    """Return value when positive float-like, otherwise fallback default."""
    if isinstance(value, (int, float)):
        return max(0.1, float(value))
    return default


def resolve_host_target(target_url: str) -> str:
    """Extract host/IP from URL-like targets for port scanning."""
    if "://" not in target_url:
        return target_url

    parsed = urlparse(target_url)
    return parsed.hostname or target_url


def parse_web_tools(raw: str | None) -> list[str]:
    """Normalize --web-tools option into ordered unique tool names."""
    if raw is None or not isinstance(raw, str):
        return ["builtin"]
    cleaned = raw.strip().lower()
    if not cleaned:
        return ["builtin"]

    aliases = {
        "owasp-zap": "zap",
        "zap-baseline": "zap",
        "default": "builtin",
        "dirbuster": "feroxbuster",
        "dirb": "feroxbuster",
    }
    selected: list[str] = []
    unknown: list[str] = []
    for item in cleaned.split(","):
        token = aliases.get(item.strip(), item.strip())
        if not token:
            continue
        if token == "all":
            selected = list(WEB_TOOLS)
            continue
        if token not in WEB_TOOLS:
            unknown.append(token)
            continue
        if token not in selected:
            selected.append(token)

    if unknown:
        supported = ", ".join(WEB_TOOLS)
        raise ValueError(
            f"Unknown web scanner tool(s): {', '.join(sorted(set(unknown)))}. "
            f"Supported values: {supported}, all."
        )
    return selected or ["builtin"]


def service_summary(host_info: HostInfo) -> str:
    """Build compact service summary for AI guidance."""
    summary = ", ".join(
        f"{service.port}/{service.protocol} {service.name} {service.banner}".strip()
        for service in host_info.services
    )
    return summary or "No open services detected"


def web_services_payload(
    host_target: str, services: list[ServiceInfo]
) -> list[dict[str, str | int]]:
    """Build Rich summary payload for discovered web services."""
    return [
        {
            "url": f"{detect_scheme(host_target, service.port, service)}://{host_target}:{service.port}",
            "port": service.port,
            "service": service.name,
        }
        for service in services
        if service.name in ["http", "https", "http-proxy"]
    ]
