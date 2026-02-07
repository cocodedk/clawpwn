"""Executors for scanning tools (web, network, discovery)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run

from .availability import enrich_missing_tool_error

MAX_FINDINGS_IN_RESULT = 20
MAX_EVIDENCE_CHARS = 200


def execute_web_scan(params: dict[str, Any], project_dir: Path) -> str:
    """Run web vulnerability scan and return compact result text."""
    from clawpwn.modules.scanner import Scanner
    from clawpwn.modules.webscan import (
        WebScanConfig,
        WebScanOrchestrator,
        create_default_webscan_plugins,
    )

    target = params["target"]
    depth = params.get("depth", "normal")
    vuln_cats = params.get("vuln_categories") or []
    scan_types = vuln_cats if vuln_cats else ["all"]
    tools_list = params.get("tools") or ["builtin"]
    timeout = params.get("timeout", 45.0)
    concurrency = max(1, params.get("concurrency", 10))

    orchestrator = WebScanOrchestrator(
        plugins=create_default_webscan_plugins(project_dir, scanner_factory=Scanner)
    )
    config = WebScanConfig(
        depth=depth,
        timeout=timeout,
        concurrency=concurrency,
        verbose=True,
        scan_types=scan_types,
    )

    # Print plugin progress live to stdout
    def _progress(msg: str) -> None:
        print(msg)

    findings, errors = safe_async_run(
        orchestrator.scan_target_with_diagnostics(
            target, config=config, tools=tools_list, progress=_progress
        )
    )

    return _format_scan_findings(findings, errors, target)


def execute_network_scan(params: dict[str, Any], project_dir: Path) -> str:
    """Run a host port scan."""
    from clawpwn.modules.network import NetworkDiscovery

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
        open_ports = ", ".join(str(p) for p in host_info.open_ports) or "none"
        return f"Host scan of {target} complete. Open ports: {open_ports}."
    except Exception as exc:
        return f"Network scan failed: {exc}"


def execute_discover_hosts(params: dict[str, Any], project_dir: Path) -> str:
    """Discover live hosts on a CIDR range."""
    from clawpwn.modules.network import NetworkDiscovery

    network = params["network"]
    discovery = NetworkDiscovery(project_dir)
    try:
        hosts = safe_async_run(discovery.discover_hosts(network))
        max_hosts = params.get("max_hosts", 256)
        if max_hosts and len(hosts) > max_hosts:
            hosts = hosts[:max_hosts]
        preview = ", ".join(hosts[:10])
        suffix = f" ... ({len(hosts)} total)" if len(hosts) > 10 else ""
        return f"Found {len(hosts)} live hosts on {network}: {preview}{suffix}"
    except Exception as exc:
        return f"Discovery failed: {exc}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_scan_findings(findings: list, errors: list, target: str) -> str:
    """Compact summary of web scan results for Claude (token-efficient)."""
    parts: list[str] = [f"Scan of {target} complete."]

    if errors:
        err_lines = [enrich_missing_tool_error(f"{e.tool}: {e.message}") for e in errors]
        parts.append("Tool issues: " + "; ".join(err_lines))

    if not findings:
        parts.append("No vulnerabilities found.")
        return "\n".join(parts)

    by_sev: dict[str, int] = {}
    for f in findings:
        sr = f.to_scan_result()
        by_sev[sr.severity] = by_sev.get(sr.severity, 0) + 1

    summary = ", ".join(f"{cnt} {sev}" for sev, cnt in sorted(by_sev.items()))
    parts.append(f"Total findings: {len(findings)} ({summary}).")

    # Top findings (capped for token efficiency)
    top = sorted(findings, key=lambda f: _sev_rank(f.severity))[:MAX_FINDINGS_IN_RESULT]
    parts.append("Top findings:")
    for f in top:
        evidence = (f.evidence or "")[:MAX_EVIDENCE_CHARS]
        parts.append(f"  - [{f.severity.upper()}] {f.title} @ {f.url} ({f.attack_type})")
        if evidence:
            parts.append(f"    evidence: {evidence}")

    return "\n".join(parts)


def _sev_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)
