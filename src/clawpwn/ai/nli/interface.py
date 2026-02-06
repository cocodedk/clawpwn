"""NaturalLanguageInterface implementation."""

from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.context_mixin import ContextMixin
from clawpwn.ai.nli.conversation_mixin import ConversationMixin
from clawpwn.ai.nli.discovery_handlers_mixin import DiscoveryHandlersMixin
from clawpwn.ai.nli.extract_help_mixin import ExtractHelpMixin
from clawpwn.ai.nli.help_topics import HELP_TOPIC_ALIASES, HELP_TOPICS
from clawpwn.ai.nli.parse_params_mixin import ParseParamsMixin
from clawpwn.ai.nli.scan_handlers_mixin import ScanHandlersMixin
from clawpwn.ai.nli.scan_options_mixin import ScanOptionsMixin
from clawpwn.ai.nli.scope_mixin import ScopeMixin
from clawpwn.ai.nli.support_handlers_mixin import SupportHandlersMixin
from clawpwn.ai.orchestrator import AIOrchestrator
from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


class NaturalLanguageInterface(
    ContextMixin,
    ConversationMixin,
    ParseParamsMixin,
    ScanOptionsMixin,
    ExtractHelpMixin,
    ScopeMixin,
    ScanHandlersMixin,
    SupportHandlersMixin,
    DiscoveryHandlersMixin,
):
    """Process natural language commands and convert to tool actions."""

    HELP_TOPICS = HELP_TOPICS
    HELP_TOPIC_ALIASES = HELP_TOPIC_ALIASES

    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.llm = LLMClient(project_dir=project_dir)
        self.orchestrator = AIOrchestrator(project_dir, self.llm)
        self.context: dict[str, Any] = {}
        self.session_manager = None
        db_path = get_project_db_path(project_dir)
        if db_path:
            self.session_manager = SessionManager(db_path)

    def close(self) -> None:
        if getattr(self, "llm", None) is not None:
            self.llm.close()

    def process_command(self, command: str) -> dict[str, Any]:
        response: dict[str, Any] | None = None

        if self._is_help_query(command):
            topic = self._extract_help_topic(command)
            if topic:
                response = {"success": True, "response": self.HELP_TOPICS[topic], "action": "help"}
                self._record_interaction(command, response.get("response", ""))
                return response

        network = self._extract_network(command)
        if network and any(
            word in command.lower() for word in ("discover", "lan", "network", "subnet", "hosts")
        ):
            parsed = {
                "intent": "discover",
                "target": network,
                "parameters": "",
                "confidence": "high",
            }
            response = self._handle_discover(network, parsed, command)
            self._record_interaction(command, response.get("response", ""))
            return response

        memory_context = ""
        if self._should_include_memory_context(command):
            memory_context = self._build_memory_context(compact=True)

        system_prompt = """You are the ClawPwn AI planner. The user may speak any language (including Arabic).
Translate internally if needed, then choose the best intent from the supported tool capabilities.

Supported intents and capabilities:
- discover: LAN/network discovery (CIDR like 192.168.1.0/24)
- scan: scan a single target URL/IP
- exploit: exploitation actions
- check_status: show project status/findings
- set_target: set target URL/IP
- find_vulnerabilities: look up known issues for a service/version
- research: search for CVEs/exploits
- help: show help for capabilities
- unknown: if unclear

Rules:
- If input includes a CIDR (e.g., 192.168.1.0/24) and mentions network/hosts/LAN, use intent=discover.
- If input includes a URL or host without CIDR, use intent=scan.
- For host/IP scan requests without explicit scan options, prefer robust defaults:
  scanner=nmap, depth=deep, verify_tcp=true, verbose=true.
- Keep output strictly in the required format.

Output in this exact format:
ACTION: <discover|scan|exploit|check_status|set_target|help|find_vulnerabilities|research|unknown>
TARGET: <target or empty>
PARAMS: <JSON object or empty>  # single-line JSON; keys: ports, depth, udp, udp_full, verify_tcp, scanner, parallel, verbose, scan_hosts, concurrency, max_hosts
CONFIDENCE: <high|medium|low>
NEEDS_INPUT: <yes|no>
QUESTION: <short question if needs_input=yes, else empty>"""
        if memory_context:
            system_prompt = f"{system_prompt}\n\nProject context:\n{memory_context}"

        try:
            response = self.llm.chat(command, system_prompt)
            parsed = self._parse_action_response(response)
            if not parsed.get("intent"):
                parsed = self._parse_intent_response(response)
            result = self._execute_intent(parsed, command)
            self._record_interaction(command, result.get("response", ""))
            return result
        except Exception as e:
            response = {
                "success": False,
                "response": f"I couldn't understand that command. Error: {e}",
                "action": "error",
            }
            self._record_interaction(command, response.get("response", ""))
            return response

    def _execute_intent(self, parsed: dict[str, str], original_command: str) -> dict[str, Any]:
        intent = parsed.get("intent", "unknown")
        target = parsed.get("target", "")

        if parsed.get("needs_input"):
            question = parsed.get("question") or "Please clarify your request."
            return {"success": False, "response": question, "action": "needs_input"}

        scope_block = self._enforce_target_scope(intent, parsed, original_command)
        if scope_block:
            return scope_block

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


def process_nl_command(command: str, project_dir: Path) -> dict[str, Any]:
    nli = NaturalLanguageInterface(project_dir)
    try:
        return nli.process_command(command)
    finally:
        nli.close()
