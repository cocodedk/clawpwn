"""Project context enrichment for agent prompts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def get_project_context(project_dir: Path) -> str:
    """Fetch active target, phase, action history, and findings from session."""
    try:
        from clawpwn.config import get_project_db_path
        from clawpwn.modules.session import SessionManager

        db_path = get_project_db_path(project_dir)
        if not db_path:
            return ""
        session = SessionManager(db_path)
        state = session.get_state()
        if not state:
            return ""

        parts: list[str] = []

        # Current target and phase
        if state.target:
            parts.append(f"Active target: {state.target}")
        if state.current_phase:
            parts.append(f"Phase: {state.current_phase}")
        if state.findings_count:
            parts.append(
                f"Findings so far: {state.findings_count} "
                f"({state.critical_count} critical, {state.high_count} high)"
            )

        # Recent scan action history
        scan_logs = session.get_scan_logs(limit=10)
        if scan_logs:
            parts.append("\nPast actions (recent first):")
            for log in scan_logs:
                try:
                    # Parse the JSON details
                    details = json.loads(log.details) if log.details else {}
                    tool_type = details.get("tool", "unknown")
                    target = details.get("target", details.get("network", ""))

                    # Format based on tool type
                    if tool_type == "web_scan":
                        tools_used = ",".join(details.get("tools_used", []))
                        cats = ",".join(details.get("categories", []))
                        depth = details.get("depth", "normal")
                        findings_count = details.get("findings_count", 0)
                        action_str = f"web_scan({tools_used}, {cats}, {depth}) on {target} -> {findings_count} findings"
                        feedback = details.get("attack_feedback", {})
                        if isinstance(feedback, dict):
                            hints = len(feedback.get("hints", []))
                            blocks = len(feedback.get("blocks", []))
                            policy = feedback.get("policy", "continue")
                            if hints or blocks:
                                action_str += (
                                    f", feedback: hints={hints}, blocks={blocks}, policy={policy}"
                                )
                    elif tool_type == "network_scan":
                        scanner = details.get("scanner", "nmap")
                        depth = details.get("depth", "deep")
                        ports_count = details.get("open_ports_count", 0)
                        open_ports = details.get("open_ports", [])
                        action_str = (
                            f"network_scan({scanner}, {depth}) on {target} -> {ports_count} ports"
                        )
                        if open_ports:
                            port_list = ", ".join(str(p) for p in open_ports[:20])
                            action_str += f" [{port_list}]"
                    elif tool_type == "discover_hosts":
                        hosts_count = details.get("hosts_count", 0)
                        action_str = f"discover_hosts({target}) -> {hosts_count} hosts"
                    else:
                        action_str = log.message

                    # Time ago
                    now = datetime.now(UTC)
                    created = log.created_at
                    if created.tzinfo is None:
                        # Assume UTC if no timezone
                        created = created.replace(tzinfo=UTC)
                    delta = now - created
                    if delta.total_seconds() < 3600:
                        time_ago = f"{int(delta.total_seconds() / 60)}m ago"
                    elif delta.total_seconds() < 86400:
                        time_ago = f"{int(delta.total_seconds() / 3600)}h ago"
                    else:
                        time_ago = f"{int(delta.total_seconds() / 86400)}d ago"

                    parts.append(f"- {action_str} [{time_ago}]")
                except (json.JSONDecodeError, KeyError):
                    # Fallback to message if JSON parsing fails
                    parts.append(f"- {log.message}")

        # Current attack plan
        plan_status = session.format_plan_status()
        if plan_status:
            parts.append(f"\n{plan_status}")

        # Findings grouped by attack type
        findings_by_type = session.get_findings_by_attack_type()
        if findings_by_type:
            parts.append("\nExisting findings by type:")
            for attack_type, findings in sorted(findings_by_type.items()):
                # Get severity counts
                sev_counts = {}
                for f in findings:
                    sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

                # Format: "sqli: 2 (1 high, 1 medium)"
                if findings:
                    sev_str = ", ".join(f"{cnt} {sev}" for sev, cnt in sorted(sev_counts.items()))
                    # Show one example title
                    example = findings[0].title if findings else ""
                    parts.append(f"- {attack_type}: {len(findings)} ({sev_str}) - e.g., {example}")
                else:
                    parts.append(f"- {attack_type}: scanned, nothing found")

        return "\n".join(parts)
    except Exception:
        # Fallback to basic context if enrichment fails
        try:
            from clawpwn.config import get_project_db_path
            from clawpwn.modules.session import SessionManager

            db_path = get_project_db_path(project_dir)
            if not db_path:
                return ""
            session = SessionManager(db_path)
            state = session.get_state()
            if not state:
                return ""
            parts: list[str] = []
            if state.target:
                parts.append(f"Active target: {state.target}")
            if state.current_phase:
                parts.append(f"Phase: {state.current_phase}")
            if state.findings_count:
                parts.append(
                    f"Findings so far: {state.findings_count} "
                    f"({state.critical_count} critical, {state.high_count} high)"
                )
            return "\n".join(parts)
        except Exception:
            return ""
