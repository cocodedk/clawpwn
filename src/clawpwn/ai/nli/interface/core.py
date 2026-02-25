"""NaturalLanguageInterface — core class definition."""

from __future__ import annotations

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

from .legacy import LegacyTextParseMixin


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
    LegacyTextParseMixin,
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
        self._tool_agent: Any = None  # lazy-init ToolUseAgent
        self.debug_enabled = False  # session-level debug toggle
        db_path = get_project_db_path(project_dir)
        if db_path:
            self.session_manager = SessionManager(db_path)

    def close(self) -> None:
        if getattr(self, "llm", None) is not None:
            self.llm.close()

    @property
    def _use_tool_agent(self) -> bool:
        """True when the Anthropic SDK tool-use path should be used.

        Set ``force_legacy = True`` on the instance to disable the agent
        (useful for tests that mock ``llm.chat`` directly).
        """
        if getattr(self, "force_legacy", False):
            return False
        return self.llm.provider == "anthropic"

    @property
    def tool_agent(self) -> Any:
        """Lazy-init the ToolUseAgent (only when Anthropic provider)."""
        if self._tool_agent is None:
            from clawpwn.ai.nli.agent import ToolUseAgent

            self._tool_agent = ToolUseAgent(self.llm, self.project_dir)
        return self._tool_agent

    def process_command(self, command: str) -> dict[str, Any]:
        # ---- Fast-path local checks (no LLM needed) ----
        # Check for debug toggle commands
        cmd_lower = command.lower().strip()
        if cmd_lower in ("enable debug", "debug on", "turn on debug"):
            self.debug_enabled = True
            return {
                "success": True,
                "response": "✓ Debug mode enabled. LLM requests and agent decisions will be shown.",
                "action": "debug_toggle",
            }
        if cmd_lower in ("disable debug", "debug off", "turn off debug"):
            self.debug_enabled = False
            return {
                "success": True,
                "response": "✓ Debug mode disabled.",
                "action": "debug_toggle",
            }

        if self._is_help_query(command):
            topic = self._extract_help_topic(command)
            if topic:
                result: dict[str, Any] = {
                    "success": True,
                    "response": self.HELP_TOPICS[topic],
                    "action": "help",
                }
                self._record_interaction(command, result.get("response", ""))
                return result
            # Generic help (no specific topic matched) — answer locally
            result = self._handle_help("", {}, command)
            self._record_interaction(command, result.get("response", ""))
            return result

        # ---- Anthropic tool-use path (agent-driven) ----
        if self._use_tool_agent:
            return self._process_via_agent(command)

        # ---- Legacy text-parse path (OpenAI / OpenRouter) ----
        return self._process_via_text_parse(command)

    def _process_via_agent(self, command: str) -> dict[str, Any]:
        """Route through the Claude tool-use agent."""
        try:
            result = self.tool_agent.run(command, debug=self.debug_enabled)
            self._record_interaction(command, result.get("response", ""))
            return result
        except Exception as e:
            fallback: dict[str, Any] = {
                "success": False,
                "response": f"Agent error: {e}",
                "action": "error",
            }
            self._record_interaction(command, fallback.get("response", ""))
            return fallback


def process_nl_command(command: str, project_dir: Path) -> dict[str, Any]:
    nli = NaturalLanguageInterface(project_dir)
    try:
        return nli.process_command(command)
    finally:
        nli.close()
