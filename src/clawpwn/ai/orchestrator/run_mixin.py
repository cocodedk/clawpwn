"""Kill-chain lifecycle execution methods."""

from collections.abc import Callable
from typing import Any

from .models import AIAction, KillChainState, Phase


class RunMixin:
    """Provide kill-chain orchestration lifecycle methods."""

    async def run_kill_chain(
        self,
        target: str,
        auto: bool = False,
        approval_callback: Callable[[AIAction], bool] | None = None,
    ) -> dict[str, Any]:
        """Run the full kill chain with AI guidance."""
        self.set_auto_mode(auto)
        self.kill_chain_state = KillChainState(
            current_phase=Phase.RECONNAISSANCE,
            target=target,
            auto_mode=auto,
        )

        results: dict[str, Any] = {
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
            phase_sequence = [
                (Phase.RECONNAISSANCE, "reconnaissance"),
                (Phase.ENUMERATION, "enumeration"),
                (Phase.VULNERABILITY_RESEARCH, "vulnerability_research"),
                (Phase.EXPLOITATION, "exploitation"),
            ]

            for phase, label in phase_sequence:
                if not await self._run_phase(phase, approval_callback):
                    results["stopped"] = True
                    results["reason"] = f"Stopped during {label.replace('_', ' ')}"
                    return results
                results["phases_completed"].append(label)

            if self.kill_chain_state and self.kill_chain_state.exploited:
                if not await self._run_phase(Phase.POST_EXPLOITATION, approval_callback):
                    results["stopped"] = True
                    results["reason"] = "Stopped during post-exploitation"
                    return results
                results["phases_completed"].append("post_exploitation")

            if self.kill_chain_state:
                results["findings"] = self.kill_chain_state.findings
                results["exploits"] = self.kill_chain_state.exploited
        except Exception as exc:
            results["stopped"] = True
            results["reason"] = f"Error: {exc}"

        self._print_kill_chain_summary(results)
        return results

    async def _run_phase(
        self,
        phase: Phase,
        approval_callback: Callable[[AIAction], bool] | None,
    ) -> bool:
        """Run a single kill-chain phase."""
        print(f"\n[PHASE] {phase.value}")
        print("-" * 40)

        if self.kill_chain_state:
            self.kill_chain_state.current_phase = phase
        self.session.update_phase(phase.value)

        action = await self._decide_phase_action(phase)
        if action.requires_approval and not self.auto_mode:
            if approval_callback:
                if not approval_callback(action):
                    print("[!] Action not approved by user. Stopping.")
                    return False
            elif not self._prompt_approval(action):
                return False

        return await self._execute_action(action)

    def _prompt_approval(self, action: AIAction) -> bool:
        """Prompt the user for approval in interactive mode."""
        print(f"\n[!] AI wants to: {action.reason}")
        print(f"    Target: {action.target}")
        print(f"    Risk Level: {action.risk_level}")

        if action.risk_level in ["critical", "high"]:
            response = input("\nApprove this action? (yes/no): ").lower().strip()
            if response != "yes":
                print("[!] Action not approved. Stopping.")
                return False
        return True
