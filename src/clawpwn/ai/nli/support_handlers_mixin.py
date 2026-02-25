"""Status, target, and help handlers for NLI."""

import re

from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


class SupportHandlersMixin:
    """Handlers for non-scan operational intents."""

    def _handle_status(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        db_path = get_project_db_path(self.project_dir)
        if db_path is None:
            msg = "Project storage not found. Run 'clawpwn init' first."
            return {"success": False, "error": msg, "response": msg, "action": "status"}

        session = SessionManager(db_path)
        state = session.get_state()
        if not state:
            return {"success": False, "response": "No project state found.", "action": "status"}

        response = "Current Status:\n"
        response += f"  Target: {state.target or 'Not set'}\n"
        response += f"  Phase: {state.current_phase}\n"
        response += (
            f"  Findings: {state.findings_count} "
            f"({state.critical_count} critical, {state.high_count} high)\n"
        )
        if state.findings_count > 0:
            response += "\nUse 'clawpwn status' to see detailed findings."
        return {"success": True, "response": response, "action": "status"}

    def _handle_set_target(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
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
            msg = "Project storage not found. Run 'clawpwn init' first."
            return {"success": False, "error": msg, "response": msg, "action": "set_target"}

        session = SessionManager(db_path)
        session.set_target(url)
        return {"success": True, "response": f"Target set to: {url}", "action": "set_target"}

    def _handle_help(self, target: str, parsed: dict[str, str], command: str) -> dict[str, object]:
        cleaned = re.sub(r"[^a-z0-9]+", " ", command.lower()).strip()
        if "topic" in cleaned or "topics" in cleaned or "list" in cleaned:
            topics = ", ".join(sorted(self.HELP_TOPICS.keys()))
            return {
                "success": True,
                "response": f"Help topics: {topics}\nUse: help <topic>",
                "action": "help",
            }

        topic = self._extract_help_topic(command)
        if topic:
            return {"success": True, "response": self.HELP_TOPICS[topic], "action": "help"}

        topics = ", ".join(sorted(self.HELP_TOPICS.keys()))
        help_text = f"""Available Commands:

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
  "lan --range 192.168.1.0/24" - LAN discovery (CLI)
  "discover hosts on 192.168.1.0/24" - Network discovery
  "find open ports" - Port scan
  "enumerate services" - Service detection

Research:
  "research apache 2.4" - Look up CVEs
  "find exploits for nginx" - Search exploit DB

General:
  "help" - Show this help
  "help <topic>" - Show a help topic ({topics})
  "how do I restart console" - Natural-language help search
  "what can you do?" - List capabilities
  Note: use 'restart' inside console to relaunch session
"""
        return {"success": True, "response": help_text, "action": "help"}

    def _handle_unknown(
        self, target: str, parsed: dict[str, str], command: str
    ) -> dict[str, object]:
        prompt = (
            "You are ClawPwn, an AI-powered penetration testing tool. "
            "The user gave a command you don't recognize. "
            "Provide a helpful response suggesting what they might want to do. Be concise."
        )
        try:
            response = self.llm.chat(command, prompt)
            return {"success": False, "response": response, "action": "unknown"}
        except Exception:
            return {
                "success": False,
                "response": "I'm not sure what you want to do. Try 'help' for available commands.",
                "action": "unknown",
            }
