"""Natural language interface for ClawPwn.

Allows users to interact with the tool using natural language commands.
"""

import re
from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.orchestrator import AIOrchestrator
from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


class NaturalLanguageInterface:
    """Process natural language commands and convert to tool actions."""

    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.llm = LLMClient()
        self.orchestrator = AIOrchestrator(project_dir, self.llm)
        self.context: dict[str, Any] = {}

    def process_command(self, command: str) -> dict[str, Any]:
        """
        Process a natural language command.

        Args:
            command: User's natural language input

        Returns:
            Dictionary with action and response
        """
        # First, try to understand intent using LLM
        system_prompt = """You are a pentest command parser. Analyze the user's input and extract:
1. Intent: scan, exploit, check_status, set_target, help, or unknown
2. Target: URL, IP, or parameter mentioned
3. Parameters: Any specific options or flags

Respond in this exact format:
INTENT: <intent>
TARGET: <target or empty>
PARAMETERS: <comma-separated list or empty>
CONFIDENCE: <high|medium|low>"""

        try:
            response = self.llm.chat(command, system_prompt)

            # Parse the response
            parsed = self._parse_intent_response(response)

            # Execute based on intent
            return self._execute_intent(parsed, command)

        except Exception as e:
            return {
                "success": False,
                "response": f"I couldn't understand that command. Error: {str(e)}",
                "action": "error",
            }

    def _parse_intent_response(self, response: str) -> dict[str, str]:
        """Parse the LLM intent classification response."""
        result = {
            "intent": "unknown",
            "target": "",
            "parameters": "",
            "confidence": "low",
        }

        for line in response.strip().split("\n"):
            if line.startswith("INTENT:"):
                result["intent"] = line.replace("INTENT:", "").strip().lower()
            elif line.startswith("TARGET:"):
                result["target"] = line.replace("TARGET:", "").strip()
            elif line.startswith("PARAMETERS:"):
                result["parameters"] = line.replace("PARAMETERS:", "").strip()
            elif line.startswith("CONFIDENCE:"):
                result["confidence"] = line.replace("CONFIDENCE:", "").strip().lower()

        return result

    def _execute_intent(self, parsed: dict[str, str], original_command: str) -> dict[str, Any]:
        """Execute the parsed intent."""
        intent = parsed.get("intent", "unknown")
        target = parsed.get("target", "")

        # High-level intent handlers
        handlers = {
            "scan": self._handle_scan,
            "exploit": self._handle_exploit,
            "check_status": self._handle_status,
            "set_target": self._handle_set_target,
            "help": self._handle_help,
            "discover": self._handle_discover,
            "find_vulnerabilities": self._handle_find_vulns,
            "research": self._handle_research,
        }

        handler = handlers.get(intent, self._handle_unknown)
        return handler(target, parsed, original_command)

    def _handle_scan(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle scan intent."""
        import asyncio

        scan_target = target or self._extract_url(command) or self._get_current_target()

        if not scan_target:
            return {
                "success": False,
                "response": "I need a target to scan. Please specify a URL or IP address.",
                "action": "scan",
                "needs_input": True,
            }

        # Run the scan
        from clawpwn.modules.scanner import Scanner

        scanner = Scanner(self.project_dir)

        try:
            findings = asyncio.run(scanner.scan(scan_target))

            if findings:
                finding_count = len(findings)
                critical = len([f for f in findings if f.severity == "critical"])
                high = len([f for f in findings if f.severity == "high"])

                return {
                    "success": True,
                    "response": f"Scan complete! Found {finding_count} issues ({critical} critical, {high} high). Check 'clawpwn status' for details.",
                    "action": "scan",
                    "findings_count": finding_count,
                }
            else:
                return {
                    "success": True,
                    "response": "Scan complete! No obvious vulnerabilities found.",
                    "action": "scan",
                    "findings_count": 0,
                }

        except Exception as e:
            return {
                "success": False,
                "response": f"Scan failed: {str(e)}",
                "action": "scan",
            }

    def _handle_exploit(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle exploit intent."""
        return {
            "success": False,
            "response": "To exploit a finding, use the killchain command or specify the finding ID. Use 'clawpwn killchain --auto' for AI-guided exploitation.",
            "action": "exploit",
            "needs_approval": True,
        }

    def _handle_status(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle status check intent."""
        db_path = get_project_db_path(self.project_dir)
        if db_path is None:
            raise ValueError("Project storage not found. Run 'clawpwn init' first.")
        session = SessionManager(db_path)
        state = session.get_state()

        if not state:
            return {
                "success": False,
                "response": "No project state found.",
                "action": "status",
            }

        response = "Current Status:\n"
        response += f"  Target: {state.target or 'Not set'}\n"
        response += f"  Phase: {state.current_phase}\n"
        response += f"  Findings: {state.findings_count} ({state.critical_count} critical, {state.high_count} high)\n"

        if state.findings_count > 0:
            response += "\nUse 'clawpwn status' to see detailed findings."

        return {"success": True, "response": response, "action": "status"}

    def _handle_set_target(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, Any]:
        """Handle set target intent."""
        url = target or self._extract_url(command)

        if not url:
            return {
                "success": False,
                "response": "I need a target URL. Please provide one.",
                "action": "set_target",
                "needs_input": True,
            }

        db_path = get_project_db_path(self.project_dir)
        if db_path is None:
            raise ValueError("Project storage not found. Run 'clawpwn init' first.")
        session = SessionManager(db_path)
        session.set_target(url)

        return {
            "success": True,
            "response": f"Target set to: {url}",
            "action": "set_target",
        }

    def _handle_help(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle help intent."""
        help_text = """Available Commands:

Scanning:
  "scan example.com" - Scan a target
  "scan for vulnerabilities" - Scan current target
  "check security" - Run security scan

Target Management:
  "set target to example.com" - Change target
  "what's the status?" - Show project status
  "show findings" - List discovered issues

Exploitation:
  "run killchain" - Execute full attack chain
  "exploit SQL injection" - Exploit specific finding
  "check for exploits" - Research available exploits

Discovery:
  "discover hosts on 192.168.1.0/24" - Network discovery
  "find open ports" - Port scan
  "enumerate services" - Service detection

Research:
  "research apache 2.4" - Look up CVEs
  "find exploits for nginx" - Search exploit DB

General:
  "help" - Show this help
  "what can you do?" - List capabilities
"""

        return {"success": True, "response": help_text, "action": "help"}

    def _handle_discover(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle network discovery intent."""
        import asyncio

        # Extract network range
        network = target or self._extract_network(command)

        if not network:
            return {
                "success": False,
                "response": "Please specify a network range (e.g., '192.168.1.0/24')",
                "action": "discover",
                "needs_input": True,
            }

        from clawpwn.modules.network import NetworkDiscovery

        try:
            discovery = NetworkDiscovery(self.project_dir)
            hosts = asyncio.run(discovery.discover_hosts(network))

            return {
                "success": True,
                "response": f"Found {len(hosts)} live hosts on {network}: {', '.join(hosts[:5])}{'...' if len(hosts) > 5 else ''}",
                "action": "discover",
                "hosts": hosts,
            }

        except Exception as e:
            return {
                "success": False,
                "response": f"Discovery failed: {str(e)}",
                "action": "discover",
            }

    def _handle_find_vulns(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, Any]:
        """Handle vulnerability finding intent."""
        return self._handle_scan(target, parsed, command)

    def _handle_research(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle research intent."""
        import asyncio

        # Extract service and version
        service_info = self._extract_service_info(command)

        if not service_info.get("service"):
            return {
                "success": False,
                "response": "Please specify what to research (e.g., 'research apache 2.4')",
                "action": "research",
                "needs_input": True,
            }

        from clawpwn.modules.vulndb import VulnDB

        try:
            vulndb = VulnDB()
            results = asyncio.run(
                vulndb.research_service(service_info["service"], service_info.get("version", ""))
            )

            cves = results.get("cves", [])
            exploits = results.get("exploits", [])

            response = f"Research complete for {service_info['service']}:\n"
            response += f"  CVEs found: {len(cves)}\n"
            response += f"  Exploits available: {len(exploits)}\n"

            return {"success": True, "response": response, "action": "research"}

        except Exception as e:
            return {
                "success": False,
                "response": f"Research failed: {str(e)}",
                "action": "research",
            }

    def _handle_unknown(self, target: str, parsed: dict[str, str], command: str) -> dict[str, Any]:
        """Handle unknown commands with LLM."""
        system_prompt = "You are ClawPwn, an AI-powered penetration testing tool. The user gave a command you don't recognize. Provide a helpful response suggesting what they might want to do. Be concise."

        try:
            response = self.llm.chat(command, system_prompt)
            return {"success": False, "response": response, "action": "unknown"}
        except Exception:
            return {
                "success": False,
                "response": "I'm not sure what you want to do. Try 'help' for available commands.",
                "action": "unknown",
            }

    # Helper methods
    def _extract_url(self, text: str) -> str | None:
        """Extract URL from text."""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        match = re.search(url_pattern, text)
        return match.group(0) if match else None

    def _extract_network(self, text: str) -> str | None:
        """Extract network range from text."""
        network_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
        match = re.search(network_pattern, text)
        return match.group(0) if match else None

    def _extract_service_info(self, text: str) -> dict[str, str]:
        """Extract service name and version from text."""
        # Pattern: "service X version Y" or "X Y"
        patterns = [
            r"(\w+)\s+(\d+\.?\d*\.?\d*)",  # apache 2.4
            r"(\w+)\s+version\s+(\d+\.?\d*\.?\d*)",  # apache version 2.4
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return {"service": match.group(1).lower(), "version": match.group(2)}

        # Just service name
        words = text.lower().split()
        common_services = [
            "apache",
            "nginx",
            "mysql",
            "ssh",
            "ftp",
            "wordpress",
            "joomla",
            "drupal",
            "php",
            "tomcat",
            "iis",
        ]

        for word in words:
            if word in common_services:
                return {"service": word, "version": ""}

        return {"service": "", "version": ""}

    def _get_current_target(self) -> str | None:
        """Get current target from project state."""
        try:
            db_path = get_project_db_path(self.project_dir)
            if db_path is None:
                raise ValueError("Project storage not found. Run 'clawpwn init' first.")
            session = SessionManager(db_path)
            state = session.get_state()
            return state.target if state else None
        except Exception:
            return None


# Convenience function
def process_nl_command(command: str, project_dir: Path) -> dict[str, Any]:
    """Process a natural language command."""
    nli = NaturalLanguageInterface(project_dir)
    return nli.process_command(command)
