"""AI decision parsing for orchestrator phases."""

from .models import ActionType, AIAction, Phase


class DecisionMixin:
    """Provide AI decision-making for each kill chain phase."""

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

        message = (
            f"Current Phase: {phase.value}\n\nState:\n{state_summary}\n\nWhat action should I take?"
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
            target = self.kill_chain_state.target if self.kill_chain_state else ""
            return AIAction(
                action_type=ActionType.SCAN,
                reason=f"Default {phase.value} action (AI decision failed: {exc})",
                target=target,
                risk_level="low",
                requires_approval=False,
            )

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
