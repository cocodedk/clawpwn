"""AI decision parsing for orchestrator phases."""

from __future__ import annotations

from typing import Any

from .models import ActionType, AIAction, Phase

# ---------------------------------------------------------------------------
# Tool-use schema for kill-chain decisions (Anthropic SDK path)
# ---------------------------------------------------------------------------

_DECIDE_ACTION_TOOL: dict[str, Any] = {
    "name": "decide_action",
    "description": (
        "Choose the next action for the current kill-chain phase. "
        "Provide the action type, a target, a reason, a risk level, "
        "and whether human approval is required."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["scan", "exploit", "enumerate", "research", "wait", "stop", "ask_user"],
                "description": "The action to take.",
            },
            "target": {
                "type": "string",
                "description": "Target URL or host for the action.",
            },
            "reason": {
                "type": "string",
                "description": "Brief explanation for this decision.",
            },
            "risk": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Risk level of this action.",
            },
            "needs_approval": {
                "type": "boolean",
                "description": "Whether human approval is required.",
            },
        },
        "required": ["action", "reason"],
    },
}

_DECISION_SYSTEM_PROMPT = (
    "You are an AI penetration testing orchestrator. Based on the current "
    "state and phase, decide the next action to take. Be specific and actionable."
)


class DecisionMixin:
    """Provide AI decision-making for each kill chain phase."""

    async def _decide_phase_action(self, phase: Phase) -> AIAction:
        """Ask AI what to do in this phase."""
        state_summary = self._get_state_summary()
        message = (
            f"Current Phase: {phase.value}\n\nState:\n{state_summary}\n\nWhat action should I take?"
        )

        # Try tool-use path when using Anthropic provider
        if getattr(self.llm, "provider", "") == "anthropic":
            return self._decide_via_tools(phase, message)

        return self._decide_via_text(phase, message)

    # ------------------------------------------------------------------
    # Anthropic tool-use path
    # ------------------------------------------------------------------

    def _decide_via_tools(self, phase: Phase, message: str) -> AIAction:
        """Use Claude tool-use to get a structured decision."""
        try:
            response = self.llm.chat_with_tools(
                messages=[{"role": "user", "content": message}],
                tools=[_DECIDE_ACTION_TOOL],
                system_prompt=_DECISION_SYSTEM_PROMPT,
                max_tokens=512,
            )
            for block in response.content:
                if getattr(block, "type", None) == "tool_use" and block.name == "decide_action":
                    return self._action_from_tool_input(block.input, phase)
            # No tool call — fall through to text
            return self._fallback_action(phase)
        except Exception as exc:
            return self._fallback_action(phase, exc)

    def _action_from_tool_input(self, data: dict[str, Any], phase: Phase) -> AIAction:
        """Convert a ``decide_action`` tool-call input into an ``AIAction``."""
        valid_actions = {item.value for item in ActionType}
        action_str = str(data.get("action", "scan")).lower()
        action_type = ActionType(action_str) if action_str in valid_actions else ActionType.SCAN

        action = AIAction(
            action_type=action_type,
            reason=str(data.get("reason", f"Execute {phase.value} phase")),
            target=str(data.get("target", "")),
            risk_level=str(data.get("risk", "low")),
            requires_approval=bool(data.get("needs_approval", False)),
        )
        if not action.target and self.kill_chain_state:
            action.target = self.kill_chain_state.target
        return action

    # ------------------------------------------------------------------
    # Legacy text-parse path (OpenAI / OpenRouter)
    # ------------------------------------------------------------------

    def _decide_via_text(self, phase: Phase, message: str) -> AIAction:
        """Use text-parse path for non-Anthropic providers."""
        system_prompt = (
            "You are an AI penetration testing orchestrator. Based on the current "
            "state and phase, decide the next action to take.\n\n"
            "Respond in this format:\n"
            "ACTION: <scan|exploit|enumerate|research|wait|stop>\n"
            "TARGET: <target URL or resource>\n"
            "REASON: <brief explanation>\n"
            "RISK: <low|medium|high|critical>\n"
            "APPROVAL: <yes|no> (whether this needs human approval)\n\n"
            "Be specific and actionable."
        )
        try:
            response = self.llm.chat(message, system_prompt)
            action = self._parse_ai_action(response)
            if not action.target and self.kill_chain_state:
                action.target = self.kill_chain_state.target
            if not action.reason:
                action.reason = f"Execute {phase.value} phase"
            return action
        except Exception as exc:
            return self._fallback_action(phase, exc)

    def _parse_ai_action(self, response: str) -> AIAction:
        """Parse LLM text response into an AIAction."""
        action_type = ActionType.SCAN
        target = ""
        reason = ""
        risk = "low"
        requires_approval = False

        valid_actions = {item.value for item in ActionType}
        for line in response.split("\n"):
            if line.startswith("ACTION:"):
                action_str = line.replace("ACTION:", "").strip().lower()
                action_type = (
                    ActionType(action_str) if action_str in valid_actions else ActionType.SCAN
                )
            elif line.startswith("TARGET:"):
                target = line.replace("TARGET:", "").strip()
            elif line.startswith("REASON:"):
                reason = line.replace("REASON:", "").strip()
            elif line.startswith("RISK:"):
                risk = line.replace("RISK:", "").strip().lower()
            elif line.startswith("APPROVAL:"):
                requires_approval = line.replace("APPROVAL:", "").strip().lower() == "yes"

        return AIAction(
            action_type=action_type,
            reason=reason,
            target=target,
            risk_level=risk,
            requires_approval=requires_approval,
        )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback_action(self, phase: Phase, exc: Exception | None = None) -> AIAction:
        target = self.kill_chain_state.target if self.kill_chain_state else ""
        reason = f"Default {phase.value} action"
        if exc:
            reason += f" (AI decision failed: {exc})"
        return AIAction(
            action_type=ActionType.SCAN,
            reason=reason,
            target=target,
            risk_level="low",
            requires_approval=False,
        )
