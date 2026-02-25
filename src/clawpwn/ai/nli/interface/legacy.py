"""Legacy text-parse NLI path for non-Anthropic providers."""

from __future__ import annotations

from typing import Any


class LegacyTextParseMixin:
    """Handles the OpenAI / OpenRouter text-parse NLI path."""

    def _process_via_text_parse(self, command: str) -> dict[str, Any]:
        """Legacy text-parse NLI for non-Anthropic providers."""
        response: dict[str, Any] | None = None

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

        system_prompt = self._build_legacy_system_prompt()
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

    @staticmethod
    def _build_legacy_system_prompt() -> str:
        return (
            "You are the ClawPwn AI planner. The user may speak any language "
            "(including Arabic).\n"
            "Translate internally if needed, then choose the best intent from "
            "the supported tool capabilities.\n\n"
            "Supported intents and capabilities:\n"
            "- discover: LAN/network discovery (CIDR like 192.168.1.0/24)\n"
            "- scan: scan a single target URL/IP\n"
            "- exploit: exploitation actions\n"
            "- check_status: show project status/findings\n"
            "- set_target: set target URL/IP\n"
            "- find_vulnerabilities: look up known issues for a service/version\n"
            "- research: search for CVEs/exploits\n"
            "- help: show help for capabilities\n"
            "- unknown: if unclear\n\n"
            "Rules:\n"
            "- If input includes a CIDR and mentions network/hosts/LAN, use intent=discover.\n"
            "- If input includes a URL or host without CIDR, use intent=scan.\n"
            "- For host/IP scan requests without explicit options, prefer robust defaults: "
            "scanner=nmap, depth=deep, verify_tcp=true, verbose=true.\n"
            "- When the user mentions specific vulnerability types, set vuln_categories. "
            "Supported: sqli, xss, path_traversal, command_injection, idor, "
            "content_discovery, misconfig, headers.\n"
            "- When vuln_categories is set, prefer depth=deep.\n"
            "- Keep output strictly in the required format.\n\n"
            "Output in this exact format:\n"
            "ACTION: <discover|scan|exploit|check_status|set_target|help|"
            "find_vulnerabilities|research|unknown>\n"
            "TARGET: <target or empty>\n"
            "PARAMS: <JSON object or empty>  # single-line JSON; keys: ports, depth, "
            "udp, udp_full, verify_tcp, scanner, parallel, verbose, web_tools, "
            "web_timeout, web_concurrency, scan_hosts, concurrency, max_hosts, "
            "vuln_categories\n"
            "CONFIDENCE: <high|medium|low>\n"
            "NEEDS_INPUT: <yes|no>\n"
            "QUESTION: <short question if needs_input=yes, else empty>"
        )

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
