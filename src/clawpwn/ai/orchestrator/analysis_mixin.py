"""Analysis and summary helpers for AI orchestrator."""

from typing import Any

from clawpwn.modules.scanner import ScanResult


class AnalysisMixin:
    """Provide analysis, selection, and summary helper methods."""

    async def _analyze_findings_with_ai(self, findings: list[ScanResult]) -> str:
        """Ask AI to analyze findings and provide insights."""
        system_prompt = (
            "You are a security analyst. Review these findings and provide a brief "
            "tactical assessment. Be concise."
        )
        findings_summary = "\n".join(
            [
                f"- {finding.title} ({finding.severity}): {finding.attack_type}"
                for finding in findings[:5]
            ]
        )
        message = f"Found these issues:\n{findings_summary}\n\nTactical assessment?"

        try:
            return self.llm.chat(message, system_prompt)
        except Exception:
            return "Analysis complete. Review findings for exploitation opportunities."

    def _select_finding_for_exploitation(self, findings: list[ScanResult]) -> ScanResult | None:
        """Select the best finding for exploitation."""
        for severity in ["critical", "high"]:
            for finding in findings:
                if finding.severity.lower() != severity:
                    continue
                if finding.attack_type in ["SQL Injection", "Command Injection", "Path Traversal"]:
                    return finding
        return None

    def _map_finding_to_exploit_type(self, finding: ScanResult) -> str | None:
        """Map a finding to an exploit type."""
        attack_type = finding.attack_type.lower()
        if "sql" in attack_type:
            return "sql_injection"
        if "command" in attack_type:
            return "command_injection"
        if "path" in attack_type or "traversal" in attack_type:
            return "path_traversal"
        if "xss" in attack_type:
            return "xss"
        return None

    def _get_state_summary(self) -> str:
        """Get a summary of current state for AI decisioning."""
        if not self.kill_chain_state:
            return "No state initialized"

        lines = [
            f"Target: {self.kill_chain_state.target}",
            f"Phase: {self.kill_chain_state.current_phase.value}",
            f"Findings: {len(self.kill_chain_state.findings)}",
            f"Hosts: {len(self.kill_chain_state.hosts_discovered)}",
            f"Services: {len(self.kill_chain_state.services_discovered)}",
            f"Exploited: {len(self.kill_chain_state.exploited)}",
        ]
        if self.kill_chain_state.findings:
            lines.append("\nKey Findings:")
            for finding in self.kill_chain_state.findings[:3]:
                lines.append(f"  - {finding.title} ({finding.severity})")
        return "\n".join(lines)

    def _print_kill_chain_summary(self, results: dict[str, Any]) -> None:
        """Print final kill chain summary."""
        print(f"\n{'=' * 60}")
        print("KILL CHAIN COMPLETE")
        print(f"{'=' * 60}")
        print(f"Phases completed: {', '.join(results['phases_completed'])}")
        print(f"Findings: {len(results['findings'])}")
        print(f"Successful exploits: {len([e for e in results['exploits'] if e.success])}")
        if results["stopped"]:
            print(f"Status: Stopped - {results['reason']}")
        else:
            print("Status: Completed successfully")
        print(f"{'=' * 60}\n")

    def plan_recon(self, target: str) -> list[dict[str, Any]]:
        """Plan reconnaissance tasks."""
        _ = target
        return [
            {"task": "Port scanning", "tool": "nmap", "priority": "high"},
            {"task": "Service detection", "tool": "nmap", "priority": "high"},
            {"task": "Web enumeration", "tool": "crawler", "priority": "medium"},
        ]

    def should_exploit(self, finding: dict[str, Any]) -> bool:
        """Determine if a finding should be automatically exploited."""
        if finding.get("severity") == "critical":
            return False
        return True

    def generate_report_summary(self) -> str:
        """Generate an executive summary for the report."""
        state = self.session.get_state()
        if not state:
            return "No project data available."

        system_prompt = (
            "You are a security report writer. Write an executive summary for this "
            "penetration test. Be professional and concise."
        )
        message = (
            f"Target: {state.target}\n"
            f"Phase: {state.current_phase}\n"
            f"Findings: {state.findings_count} ({state.critical_count} critical, {state.high_count} high)"
        )
        return self.llm.chat(message, system_prompt)
