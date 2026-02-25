"""Action execution for orchestrator decisions."""

import re

from clawpwn.modules.scanner import ScanConfig

from .models import ActionType, AIAction, Phase


class ExecuteMixin:
    """Provide methods to execute AI-decided actions."""

    async def _execute_action(self, action: AIAction) -> bool:
        """Execute an AI-decided action."""
        print(f"[*] Executing: {action.reason}")

        if action.action_type == ActionType.SCAN:
            return await self._execute_scan(action)
        if action.action_type == ActionType.EXPLOIT:
            return await self._execute_exploit(action)
        if action.action_type == ActionType.ENUMERATE:
            return await self._execute_enumeration(action)
        if action.action_type == ActionType.RESEARCH:
            return await self._execute_research(action)
        if action.action_type == ActionType.WAIT:
            print("[*] Waiting for user input...")
            return True
        if action.action_type == ActionType.STOP:
            print("[*] AI decided to stop the kill chain.")
            return False
        if action.action_type == ActionType.ASK_USER:
            print(f"\n[?] AI needs guidance: {action.reason}")
            return True

        return True

    async def _execute_scan(self, action: AIAction) -> bool:
        """Execute a scan action."""
        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        target = action.target or self.kill_chain_state.target
        depth = "normal" if self.kill_chain_state.current_phase == Phase.RECONNAISSANCE else "deep"
        config = ScanConfig(target=target, depth=depth)

        print(f"[*] Scanning {target}...")
        findings = await self.scanner.scan(target, config)
        self.kill_chain_state.findings.extend(findings)

        if findings:
            print(f"[+] Found {len(findings)} potential issues")
            analysis = await self._analyze_findings_with_ai(findings)
            print(f"[AI] {analysis}")

        return True

    async def _execute_exploit(self, action: AIAction) -> bool:
        """Execute an exploitation action."""
        _ = action
        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        findings = self.kill_chain_state.findings
        if not findings:
            print("[!] No findings to exploit")
            return True

        target_finding = self._select_finding_for_exploitation(findings)
        if not target_finding:
            print("[!] No suitable finding for exploitation")
            return True

        print(f"[*] Attempting to exploit: {target_finding.title}")
        exploit_type = self._map_finding_to_exploit_type(target_finding)
        if not exploit_type:
            return True

        parameter = self._extract_parameter(target_finding.evidence)
        result = await self.exploit_manager.auto_exploit(
            target=self.kill_chain_state.target,
            finding_type=exploit_type,
            parameter=parameter,
        )

        if result.success:
            print("[+] Exploitation successful!")
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
        target = action.target or (self.kill_chain_state.target if self.kill_chain_state else "")
        print(f"[*] Enumerating {target}...")

        try:
            results = await self.network.enumerate_target(target)
            if self.kill_chain_state:
                self.kill_chain_state.hosts_discovered.extend(
                    [host.ip for host in results.get("hosts", [])]
                )
                self.kill_chain_state.services_discovered.extend(results.get("services", []))
            self.network.print_summary(results)
        except Exception as exc:
            print(f"[!] Enumeration error: {exc}")

        return True

    async def _execute_research(self, action: AIAction) -> bool:
        """Execute vulnerability research action."""
        _ = action
        print("[*] Researching vulnerabilities...")

        if not self.kill_chain_state:
            print("[!] No kill chain state initialized")
            return False

        for service in self.kill_chain_state.services_discovered:
            service_name = service.get("name", "")
            version = service.get("version", "")
            if not service_name:
                continue
            try:
                results = await self.vulndb.research_service(service_name, version)
                self.vulndb.print_research_summary(results)
            except Exception as exc:
                print(f"[!] Research error for {service_name}: {exc}")

        return True

    def _extract_parameter(self, evidence: str) -> str:
        """Extract vulnerable parameter name from finding evidence."""
        parameter = "id"
        if "parameter" not in evidence.lower():
            return parameter

        match = re.search(r"parameter ['\"](\w+)['\"]", evidence, re.IGNORECASE)
        return match.group(1) if match else parameter
