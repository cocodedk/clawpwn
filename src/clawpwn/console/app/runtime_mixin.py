"""Prompt rendering and REPL loop for ConsoleApp."""

import os

from prompt_toolkit import PromptSession


class RuntimeMixin:
    """Provide runtime loop and prompt formatting methods."""

    def _build_prompt(self) -> str:
        """Build context-aware prompt string."""
        parts = ["clawpwn"]
        mode_label = getattr(self.router.mode, "value", "auto")
        parts.append(f"({mode_label})")

        if self.session:
            state = None
            try:
                state = self.session.get_state()
            except Exception:
                state = None

            if state and state.target:
                target = state.target
                if len(target) > 20:
                    target = target[:17] + "..."
                phase = getattr(state, "phase", None) or getattr(state, "current_phase", None)
                suffix = f"/{phase}" if phase else ""
                parts.append(f"[{target}{suffix}]")

        return "".join(parts) + "> "

    def run(self) -> bool:
        """Start the REPL loop. Returns True if restart was requested."""
        self._print_banner()
        self.running = True
        self.restart_requested = False

        prev_flag = os.environ.get("CLAWPWN_CONSOLE_ACTIVE")
        os.environ["CLAWPWN_CONSOLE_ACTIVE"] = "1"

        session = PromptSession(
            history=self.history.get_history(),
            completer=self.completer,
            complete_while_typing=False,
            enable_history_search=True,
        )

        try:
            while self.running:
                try:
                    line = session.prompt(self._build_prompt())
                    if not line.strip():
                        continue
                    if self._handle_builtin(line):
                        continue
                    self._process_input(line)
                except KeyboardInterrupt:
                    try:
                        self.console.print("\n[dim]Use 'exit' to quit[/dim]")
                    except ValueError:
                        pass
                except EOFError:
                    self.console.print("\n[green]Goodbye![/green]")
                    break
        finally:
            if self.nli is not None:
                self.nli.close()
            if prev_flag is None:
                os.environ.pop("CLAWPWN_CONSOLE_ACTIVE", None)
            else:
                os.environ["CLAWPWN_CONSOLE_ACTIVE"] = prev_flag

        return self.restart_requested
