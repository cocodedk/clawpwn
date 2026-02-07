"""Web scan handler for NLI."""

from clawpwn.utils.async_utils import safe_async_run


def handle_web_scan(
    handler, scan_target: str, params: dict[str, str], command: str
) -> dict[str, object]:
    """Handle web scanning."""
    from clawpwn.modules.scanner import Scanner
    from clawpwn.modules.webscan import (
        WebScanConfig,
        WebScanOrchestrator,
        create_default_webscan_plugins,
    )

    vuln_categories = handler._parse_vuln_categories(params)
    depth_default = "deep" if vuln_categories else "normal"
    depth = handler._param_str(params, "depth", depth_default)
    scanner_name = handler._param_str(params, "scanner", "nmap")
    parallel = handler._param_int(params, "parallel", 4)
    verbose = handler._param_bool(params, "verbose", True)
    udp_full = handler._param_bool(params, "udp_full", False)
    web_timeout = handler._param_float(params, "web_timeout", 45.0)
    web_concurrency = handler._param_int(params, "web_concurrency", 10)

    # Smart tool selection: if the user asked for specific vuln categories
    # and did not explicitly pick web_tools, choose the best tools.
    explicit_tools = params.get("web_tools") or params.get("web_tool")
    if vuln_categories and not explicit_tools:
        web_tools = handler._tools_for_categories(vuln_categories)
    else:
        web_tools = handler._parse_web_tools(params)

    scan_types = handler._category_scan_types(vuln_categories)

    stream_progress = verbose
    progress_updates: list[str] = []

    def _progress(msg: str) -> None:
        progress_updates.append(msg)
        if stream_progress:
            print(msg)

    command_preview = handler._build_scan_command_preview(
        scanner_name,
        depth,
        verbose,
        parallel,
        udp_full,
        web_tools=web_tools,
        web_timeout=web_timeout,
        web_concurrency=web_concurrency,
    )

    if vuln_categories:
        labels = ", ".join(handler._category_labels(vuln_categories))
        execution_note = (
            f"Running targeted {labels} scan on {scan_target} "
            f"using {', '.join(web_tools)} (depth={depth})."
        )
    else:
        execution_note = (
            f"Running web scan on {scan_target} using {', '.join(web_tools)} (depth={depth})."
        )

    try:
        orchestrator = WebScanOrchestrator(
            plugins=create_default_webscan_plugins(
                handler.project_dir,
                scanner_factory=Scanner,
            )
        )
        web_findings, errors = safe_async_run(
            orchestrator.scan_target_with_diagnostics(
                scan_target,
                config=WebScanConfig(
                    depth=depth,
                    timeout=web_timeout,
                    concurrency=max(1, web_concurrency),
                    verbose=verbose,
                    scan_types=scan_types,
                ),
                tools=web_tools,
                progress=_progress,
            )
        )
        findings = [finding.to_scan_result() for finding in web_findings]
        return _format_web_scan_result(
            handler,
            findings,
            errors,
            command_preview,
            execution_note,
            progress_updates,
            stream_progress,
            vuln_categories,
        )
    except Exception as e:
        return {
            "success": False,
            "response": f"Scan failed: {e}",
            "action": "scan",
            "executed_command": command_preview,
            "execution_note": execution_note,
            "progress_updates": progress_updates,
            "progress_streamed": stream_progress,
        }


def _format_web_scan_result(
    handler,
    findings: list,
    errors: list,
    command_preview: str,
    execution_note: str,
    progress_updates: list[str],
    stream_progress: bool,
    vuln_categories: list[str],
) -> dict[str, object]:
    """Build the response dict for a web scan, with category-aware summary."""
    from clawpwn.ai.nli.constants import VULN_CATEGORIES

    error_suffix = ""
    if errors:
        rendered = "; ".join(f"{err.tool}: {err.message}" for err in errors)
        error_suffix = f" Tool issues: {rendered}"

    if not findings:
        if vuln_categories:
            labels = ", ".join(handler._category_labels(vuln_categories))
            msg = f"Targeted scan complete. No {labels} vulnerabilities found.{error_suffix}"
        else:
            msg = f"Scan complete! No obvious vulnerabilities found.{error_suffix}"
        return {
            "success": True,
            "response": msg,
            "action": "scan",
            "findings_count": 0,
            "executed_command": command_preview,
            "execution_note": execution_note,
            "progress_updates": progress_updates,
            "progress_streamed": stream_progress,
        }

    # When categories are specified, highlight relevant findings.
    if vuln_categories:
        target_attack_types = {
            str(VULN_CATEGORIES[c]["attack_type"]).lower()
            for c in vuln_categories
            if c in VULN_CATEGORIES
        }
        relevant = [f for f in findings if f.attack_type.lower() in target_attack_types]
        other = len(findings) - len(relevant)
        labels = ", ".join(handler._category_labels(vuln_categories))
        if relevant:
            critical = len([f for f in relevant if f.severity == "critical"])
            high = len([f for f in relevant if f.severity == "high"])
            parts = [f"Found {len(relevant)} {labels} issue(s)"]
            parts.append(f"({critical} critical, {high} high)")
            if other:
                parts.append(f"+ {other} other finding(s)")
            msg = f"Targeted scan complete! {' '.join(parts)}.{error_suffix}"
        else:
            msg = (
                f"Targeted scan complete. No {labels} issues found, "
                f"but {other} other finding(s) detected.{error_suffix}"
            )
    else:
        critical = len([f for f in findings if f.severity == "critical"])
        high = len([f for f in findings if f.severity == "high"])
        msg = (
            f"Scan complete! Found {len(findings)} issues "
            f"({critical} critical, {high} high). "
            f"Check 'clawpwn status' for details.{error_suffix}"
        )

    return {
        "success": True,
        "response": msg,
        "action": "scan",
        "findings_count": len(findings),
        "executed_command": command_preview,
        "execution_note": execution_note,
        "progress_updates": progress_updates,
        "progress_streamed": stream_progress,
    }
