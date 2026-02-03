"""AI Orchestrator for ClawPwn - manages AI decision making and kill chain automation."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable

from clawpwn.ai.llm import LLMClient
from clawpwn.modules.session import SessionManager
from clawpwn.modules.scanner import Scanner, ScanConfig, ScanResult
from clawpwn.modules.network import NetworkDiscovery
from clawpwn.modules.vulndb import VulnDB
from clawpwn.modules.exploit import ExploitManager, ExploitResult


class Phase(Enum):
    """Kill chain phases."""

    NOT_STARTED = "Not Started"
    INITIALIZED = "Initialized"
    RECONNAISSANCE = "Reconnaissance"
    ENUMERATION = "Enumeration"
    VULNERABILITY_RESEARCH = "Vulnerability Research"
    EXPLOITATION = "Exploitation"
    POST_EXPLOITATION = "Post-Exploitation"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    EXFILTRATION = "Exfiltration"
    REPORTING = "Reporting"


class ActionType(Enum):
    """Types of actions AI can decide to take."""

    SCAN = "scan"
    EXPLOIT = "exploit"
    ENUMERATE = "enumerate"
    RESEARCH = "research"
    WAIT = "wait"
    STOP = "stop"
    ASK_USER = "ask_user"


@dataclass
class AIAction:
    """Represents an AI-decided action."""

    action_type: ActionType
    reason: str
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    risk_level: str = "low"  # low, medium, high, critical


@dataclass
class KillChainState:
    """Tracks the current state of the kill chain."""

    current_phase: Phase
    target: str
    findings: List[ScanResult] = field(default_factory=list)
    exploited: List[ExploitResult] = field(default_factory=list)
    hosts_discovered: List[str] = field(default_factory=list)
    services_discovered: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    auto_mode: bool = False


class AIOrchestrator:
    """Orchestrates AI decisions and actions during penetration testing."""

    def __init__(self, project_dir: Path, llm_client: Optional[LLMClient] = None):
        self.project_dir = project_dir
        self.db_path = project_dir / ".clawpwn" / "clawpwn.db"
        self.session = SessionManager(self.db_path)
        self.llm = llm_client or LLMClient()

        # Initialize modules
        self.scanner = Scanner(project_dir)
        self.network = NetworkDiscovery(project_dir)
        self.vulndb = VulnDB()
        self.exploit_manager = ExploitManager(project_dir)

        # State tracking
        self.kill_chain_state: Optional[KillChainState] = None

        # Safety configuration
        self.require_approval_for = ["critical", "exploitation", "exfiltration"]
        self.auto_mode = False

    def set_auto_mode(self, enabled: bool) -> None:
        """Enable or disable automatic mode (AI makes decisions without asking)."""
        self.auto_mode = enabled
        if self.kill_chain_state:
            self.kill_chain_state.auto_mode = enabled

    async def run_kill_chain(
        self,
        target: str,
        auto: bool = False,
        approval_callback: Optional[Callable[[AIAction], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Run the full kill chain with AI guidance.

        Args:
            target: Target URL or IP
            auto: Whether to run in automatic mode
            approval_callback: Function to call when approval is needed

        Returns:
            Dictionary with kill chain results
        """
        self.set_auto_mode(auto)
        self.kill_chain_state = KillChainState(
            current_phase=Phase.RECONNAISSANCE, target=target, auto_mode=auto
        )

        results = {
            "target": target,
            "phases_completed": [],
            "findings": [],
            "exploits": [],
            "stopped": False,
            "reason": "",
        }

        print(f"\n{'=' * 60}")
        print("AI-GUIDED KILL CHAIN")
        print(f"{'=' * 60}")
        print(f"Target: {target}")
        print(f"Mode: {'AUTO' if auto else 'AI-ASSISTED'}")
        print(f"{'=' * 60}\n")

        try:
            # Phase 1: Reconnaissance
            if not await self._run_phase(Phase.RECONNAISSANCE, approval_callback):
                results["stopped"] = True
                results["reason"] = "Stopped during reconnaissance"
                return results
            results["phases_completed"].append("reconnaissance")

            # Phase 2: Enumeration
            if not await self._run_phase(Phase.ENUMERATION, approval_callback):
                results["stopped"] = True
                results["reason"] = "Stopped during enumeration"
                return results
            results["phases_completed"].append("enumeration")

            # Phase 3: Vulnerability Research
            if not await self._run_phase(
                Phase.VULNERABILITY_RESEARCH, approval_callback
            ):
                results["stopped"] = True
                results["reason"] = "Stopped during vulnerability research"
                return results
            results["phases_completed"].append("vulnerability_research")

            # Phase 4: Exploitation (requires approval for critical)
            if not await self._run_phase(Phase.EXPLOITATION, approval_callback):
                results["stopped"] = True
                results["reason"] = "Stopped during exploitation"
                return results
            results["phases_completed"].append("exploitation")

            # Phase 5: Post-Exploitation
            if self.kill_chain_state.exploited:
                if not await self._run_phase(
                    Phase.POST_EXPLOITATION, approval_callback
                ):
                    results["stopped"] = True
                    results["reason"] = "Stopped during post-exploitation"
                    return results
                results["phases_completed"].append("post_exploitation")

            results["findings"] = self.kill_chain_state.findings
            results["exploits"] = self.kill_chain_state.exploited

        except Exception as e:
            results["stopped"] = True
            results["reason"] = f"Error: {str(e)}"

        # Generate summary
        self._print_kill_chain_summary(results)

        return results

    async def _run_phase(
        self, phase: Phase, approval_callback: Optional[Callable[[AIAction], bool]]
    ) -> bool:
        """Run a single kill chain phase."""
        print(f"\n[PHASE] {phase.value}")
        print("-" * 40)

        if self.kill_chain_state:
            self.kill_chain_state.current_phase = phase
        self.session.update_phase(phase.value)

        # Get AI decision for this phase
        action = await self._decide_phase_action(phase)

        # Check if approval needed
        if action.requires_approval and not self.auto_mode:
            if approval_callback:
                approved = approval_callback(action)
                if not approved:
                    print(f"[!] Action not approved by user. Stopping.")
                    return False
            else:
                # Default: ask via console
                print(f"\n[!] AI wants to: {action.reason}")
                print(f"    Target: {action.target}")
                print(f"    Risk Level: {action.risk_level}")

                if action.risk_level in ["critical", "high"]:
                    response = (
                        input("\nApprove this action? (yes/no): ").lower().strip()
                    )
                    if response != "yes":
                        print("[!] Action not approved. Stopping.")
                        return False

        # Execute the action
        return await self._execute_action(action)

    async def _decide_phase_action(self, phase: Phase) -> AIAction:
        """Ask AI what to do in this phase."""
        state_summary = self._get_state_summary()

        system_prompt = """You are an AI penetration testing orchestrator. Based on the current state and phase, decide the next action to take.

Respond in this format:
ACTION: <scan|exploit|enumerate|research|wait|stop>
TARGET: <target URL or resource>
REASON: <brief explanation>
RISK: <low|medium|high|critical>
APPROVAL: <yes|no> (whether this needs human approval)

Be specific and actionable."""

        message = f"Current Phase: {phase.value}\n\nState:\n{state_summary}\n\nWhat action should I take?"

        try:
            response = self.llm.chat(message, system_prompt)

            # Parse response
            action_type = ActionType.SCAN
            target = ""
            reason = ""
            risk = "low"
            requires_approval = False

            for line in response.split("\n"):
                if line.startswith("ACTION:"):
                    action_str = line.replace("ACTION:", "").strip().lower()
                    action_type = (
                        ActionType(action_str)
                        if action_str
                        in [
                            "scan",
                            "exploit",
                            "enumerate",
                            "research",
                            "wait",
                            "stop",
                            "ask_user",
                        ]
                        else ActionType.SCAN
                    )
                elif line.startswith("TARGET:"):
                    target = line.replace("TARGET:", "").strip()
                elif line.startswith("REASON:"):
                    reason = line.replace("REASON:", "").strip()
                elif line.startswith("RISK:"):
                    risk = line.replace("RISK:", "").strip().lower()
                elif line.startswith("APPROVAL:"):
                    requires_approval = (
                        line.replace("APPROVAL:", "").strip().lower() == "yes"
                    )

            # If no target specified, use current target
            if not target and self.kill_chain_state:
                target = self.kill_chain_state.target

            return AIAction(
                action_type=action_type,
                reason=reason or f"Execute {phase.value} phase",
                target=target,
                risk_level=risk,
                requires_approval=requires_approval,
            )

        except Exception as e:
            # Fallback action
            return AIAction(
                action_type=ActionType.SCAN,
                reason=f"Default {phase.value} action (AI decision failed: {e})",
                target=self.kill_chain_state.target if self.kill_chain_state else "",
                risk_level="low",
                requires_approval=False,
            )

    async def _execute_action(self, action: AIAction) -> bool:
        """Execute an AI-decided action."""
        print(f"[*] Executing: {action.reason}")

        if action.action_type == ActionType.SCAN:
            return await self._execute_scan(action)

        elif action.action_type == ActionType.EXPLOIT:
            return await self._execute_exploit(action)

        elif action.action_type == ActionType.ENUMERATE:
            return await self._execute_enumeration(action)

        elif action.action_type == ActionType.RESEARCH:
            return await self._execute_research(action)

        elif action.action_type == ActionType.WAIT:
            print("[*] Waiting for user input...")
            return True

        elif action.action_type == ActionType.STOP:
            print("[*] AI decided to stop the kill chain.")
            return False

        elif action.action_type == ActionType.ASK_USER:
            print(f"\n[?] AI needs guidance: {action.reason}")
            return True

        return True

    async def _execute_scan(self, action: AIAction) -> bool:
        """Execute a scan action."""
        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        target = action.target or (
            self.kill_chain_state.target if self.kill_chain_state else ""
        )

        config = ScanConfig(
            target=target,
            depth="normal"
            if self.kill_chain_state.current_phase == Phase.RECONNAISSANCE
            else "deep",
        )

        print(f"[*] Scanning {target}...")
        findings = await self.scanner.scan(target, config)

        self.kill_chain_state.findings.extend(findings)

        # Analyze with AI
        if findings:
            print(f"[+] Found {len(findings)} potential issues")
            analysis = await self._analyze_findings_with_ai(findings)
            print(f"[AI] {analysis}")

        return True

    async def _execute_exploit(self, action: AIAction) -> bool:
        """Execute an exploitation action."""
        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        # Find a suitable target to exploit
        findings = self.kill_chain_state.findings

        if not findings:
            print("[!] No findings to exploit")
            return True

        # Get AI recommendation on which to exploit
        target_finding = self._select_finding_for_exploitation(findings)

        if not target_finding:
            print("[!] No suitable finding for exploitation")
            return True

        print(f"[*] Attempting to exploit: {target_finding.title}")

        # Determine exploit type
        exploit_type = self._map_finding_to_exploit_type(target_finding)

        if exploit_type:
            # Extract parameter if present in evidence
            parameter = "id"  # default
            if "parameter" in target_finding.evidence.lower():
                # Try to extract parameter name
                import re

                match = re.search(
                    r"parameter ['\"](\w+)['\"]", target_finding.evidence, re.IGNORECASE
                )
                if match:
                    parameter = match.group(1)

            result = await self.exploit_manager.auto_exploit(
                target=self.kill_chain_state.target,
                finding_type=exploit_type,
                parameter=parameter,
            )

            if result.success:
                print(f"[+] Exploitation successful!")
                self.kill_chain_state.exploited.append(result)
                self.session.add_log(
                    f"Successfully exploited {target_finding.title}",
                    level="CRITICAL",
                    phase="Exploitation",
                )
            else:
                print(f"[-] Exploitation failed: {result.error}")

        return True

    async def _execute_enumeration(self, action: AIAction) -> bool:
        """Execute enumeration action."""
        target = action.target or (
            self.kill_chain_state.target if self.kill_chain_state else ""
        )

        print(f"[*] Enumerating {target}...")

        try:
            results = await self.network.enumerate_target(target)

            if self.kill_chain_state:
                self.kill_chain_state.hosts_discovered.extend(
                    [h.ip for h in results.get("hosts", [])]
                )
                self.kill_chain_state.services_discovered.extend(
                    results.get("services", [])
                )

            self.network.print_summary(results)

        except Exception as e:
            print(f"[!] Enumeration error: {e}")

        return True

    async def _execute_research(self, action: AIAction) -> bool:
        """Execute vulnerability research action."""
        print(f"[*] Researching vulnerabilities...")

        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        for service in self.kill_chain_state.services_discovered:
            service_name = service.get("name", "")
            version = service.get("version", "")

            if service_name:
                try:
                    results = await self.vulndb.research_service(service_name, version)
                    self.vulndb.print_research_summary(results)
                except Exception as e:
                    print(f"[!] Research error for {service_name}: {e}")

        return True

    async def _analyze_findings_with_ai(self, findings: List[ScanResult]) -> str:
        """Ask AI to analyze findings and provide insights."""
        system_prompt = "You are a security analyst. Review these findings and provide a brief tactical assessment. Be concise."

        findings_summary = "\n".join(
            [f"- {f.title} ({f.severity}): {f.attack_type}" for f in findings[:5]]
        )

        message = f"Found these issues:\n{findings_summary}\n\nTactical assessment?"

        try:
            return self.llm.chat(message, system_prompt)
        except Exception:
            return "Analysis complete. Review findings for exploitation opportunities."

    def _select_finding_for_exploitation(
        self, findings: List[ScanResult]
    ) -> Optional[ScanResult]:
        """Select the best finding for exploitation."""
        # Priority order
        for severity in ["critical", "high"]:
            for finding in findings:
                if finding.severity.lower() == severity:
                    # Check if it's exploitable
                    if finding.attack_type in [
                        "SQL Injection",
                        "Command Injection",
                        "Path Traversal",
                    ]:
                        return finding

        return None

    def _map_finding_to_exploit_type(self, finding: ScanResult) -> Optional[str]:
        """Map a finding to an exploit type."""
        attack_type = finding.attack_type.lower()

        if "sql" in attack_type:
            return "sql_injection"
        elif "command" in attack_type:
            return "command_injection"
        elif "path" in attack_type or "traversal" in attack_type:
            return "path_traversal"
        elif "xss" in attack_type:
            return "xss"

        return None

    def _get_state_summary(self) -> str:
        """Get a summary of current state for AI."""
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
            for f in self.kill_chain_state.findings[:3]:
                lines.append(f"  - {f.title} ({f.severity})")

        return "\n".join(lines)

    def _print_kill_chain_summary(self, results: Dict[str, Any]) -> None:
        """Print final kill chain summary."""
        print(f"\n{'=' * 60}")
        print("KILL CHAIN COMPLETE")
        print(f"{'=' * 60}")
        print(f"Phases completed: {', '.join(results['phases_completed'])}")
        print(f"Findings: {len(results['findings'])}")
        print(
            f"Successful exploits: {len([e for e in results['exploits'] if e.success])}"
        )

        if results["stopped"]:
            print(f"Status: Stopped - {results['reason']}")
        else:
            print("Status: Completed successfully")

        print(f"{'=' * 60}\n")

    def plan_recon(self, target: str) -> List[Dict[str, Any]]:
        """Plan reconnaissance tasks."""
        return [
            {"task": "Port scanning", "tool": "nmap", "priority": "high"},
            {"task": "Service detection", "tool": "nmap", "priority": "high"},
            {"task": "Web enumeration", "tool": "crawler", "priority": "medium"},
        ]

    def should_exploit(self, finding: Dict[str, Any]) -> bool:
        """Determine if a finding should be automatically exploited."""
        # Don't auto-exploit critical without approval
        if finding.get("severity") == "critical":
            return False

        return True

    def generate_report_summary(self) -> str:
        """Generate an executive summary for the report."""
        state = self.session.get_state()
        if not state:
            return "No project data available."

        system_prompt = "You are a security report writer. Write an executive summary for this penetration test. Be professional and concise."

        message = f"Target: {state.target}\nPhase: {state.current_phase}\nFindings: {state.findings_count} ({state.critical_count} critical, {state.high_count} high)"
        return self.llm.chat(message, system_prompt)
