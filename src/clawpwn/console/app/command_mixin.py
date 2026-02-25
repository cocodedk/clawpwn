"""Built-in command handling and input dispatch for ConsoleApp."""

import re
import sys

from clawpwn.console.router import InputMode


class CommandMixin:
    """Provide built-in command and routing methods."""

    def _handle_builtin(self, line: str) -> bool:
        """Handle built-in commands. Returns True if handled."""
        lower = line.strip().lower()
        if lower.startswith("help"):
            topic = lower[4:].strip()
            if not topic:
                self._print_banner()
                return True
            if topic in ("topic", "topics", "list"):
                self._print_help_topics()
                return True
            self._print_help_topic(topic)
            return True

        if lower in ("exit", "quit", "q"):
            self.console.print("[green]Goodbye![/green]")
            self.running = False
            self.restart_requested = False
            return True

        if lower == "restart":
            self.console.print("[cyan]Restarting console...[/cyan]")
            self.running = False
            self.restart_requested = True
            return True

        if lower in ("clear", "cls"):
            self.console.clear()
            return True

        if lower == "history":
            for index, cmd in enumerate(self.history.get_recent(20), 1):
                self.console.print(f"  [dim]{index}[/]  {cmd}")
            return True

        if lower.startswith("mode "):
            arg = lower[5:].strip()
            if arg == "cli":
                self.router.mode = InputMode.CLI
                self.console.print("[dim]Input mode: CLI (type commands only)[/dim]")
            elif arg == "nli":
                self.router.mode = InputMode.NLI
                self.console.print("[dim]Input mode: NLI (natural language only)[/dim]")
            elif arg == "auto":
                self.router.mode = InputMode.AUTO
                self.console.print("[dim]Input mode: auto (CLI or NLI by content)[/dim]")
            else:
                self.console.print("[yellow]Usage: mode [cli|nli|auto][/yellow]")
            return True

        return False

    def _invoke_cli(self, argv: list[str]) -> None:
        """Invoke the Typer CLI app with the given argv."""
        if not argv:
            return

        from clawpwn.cli import app as typer_app

        original_argv = sys.argv
        try:
            sys.argv = ["clawpwn"] + argv
            try:
                typer_app()
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    self.console.print(f"[red]Command exited with code {exc.code}[/red]")
        finally:
            sys.argv = original_argv

    def _invoke_nli(self, text: str) -> None:
        """Process natural language via NLI."""
        if not self.nli:
            self.console.print(
                "[yellow]Natural language mode requires a project. Run from a project "
                "directory or use CLI commands.[/yellow]"
            )
            return
        if not text.strip():
            return

        try:
            # Register live progress callback so tool calls print immediately
            self._register_live_progress()

            result = self.nli.process_command(text)

            # Show reasoning/progress only if not already streamed live
            progress_streamed = bool(result.get("progress_streamed"))

            if not progress_streamed:
                reasoning = result.get("reasoning")
                if isinstance(reasoning, str) and reasoning.strip():
                    self.console.print(f"[italic dim]{reasoning.strip()}[/italic dim]")

                progress_updates = result.get("progress_updates")
                if isinstance(progress_updates, list):
                    for item in progress_updates:
                        if isinstance(item, str) and item.strip():
                            self.console.print(f"[dim]{item.strip()}[/dim]")

            execution_note = result.get("execution_note")
            if isinstance(execution_note, str) and execution_note.strip():
                self.console.print(f"[cyan]{execution_note.strip()}[/cyan]")

            executed_command = result.get("executed_command")
            if not (isinstance(executed_command, str) and executed_command.strip()):
                executed_command = self._fallback_cli_equivalent(text, result)
            if isinstance(executed_command, str) and executed_command.strip():
                self.console.print(f"[dim]CLI equivalent: {executed_command.strip()}[/dim]")

            if result.get("success"):
                self.console.print(f"[green]✓[/green] {result.get('response', '')}")
            else:
                self.console.print(f"[yellow]![/yellow] {result.get('response', '')}")

            # Show which model was used
            model = result.get("model")
            if isinstance(model, str) and model:
                self.console.print(f"[dim]model: {model}[/dim]")

            # Tool suggestions from the agent
            suggestions = result.get("suggestions")
            if isinstance(suggestions, list) and suggestions:
                self.console.print("\n[bold]Recommended tools:[/bold]")
                for s in suggestions:
                    name = s.get("name", "?")
                    reason = s.get("reason", "")
                    install = s.get("install_command", "")
                    usage = s.get("example_usage", "")
                    self.console.print(f"  [cyan]{name}[/cyan] — {reason}")
                    if install:
                        self.console.print(f"    Install: [dim]{install}[/dim]")
                    if usage:
                        self.console.print(f"    Usage:   [dim]{usage}[/dim]")
        except Exception as exc:
            self.console.print(f"[red]Error: {exc}[/red]")

    def _register_live_progress(self) -> None:
        """Attach a live progress callback to the NLI tool agent."""
        if not self.nli or not getattr(self.nli, "_use_tool_agent", False):
            return
        try:
            agent = self.nli.tool_agent
            console = self.console

            def _on_progress(msg: str) -> None:
                if msg.startswith("→"):
                    console.print(f"[cyan]{msg}[/cyan]")
                elif msg.startswith("✓"):
                    console.print(f"[green]{msg}[/green]")
                else:
                    console.print(f"[italic dim]{msg}[/italic dim]")

            agent.on_progress = _on_progress
        except Exception:
            pass

    def _fallback_cli_equivalent(self, text: str, result: dict[str, object]) -> str:
        """Build a best-effort CLI equivalent when NLI metadata is missing."""
        action = str(result.get("action", "")).strip().lower()
        if action == "scan":
            return "!scan"
        if action == "discover":
            cidr_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text)
            network = cidr_match.group(0) if cidr_match else "<CIDR>"
            return f"!discover --range {network}"
        if action == "check_status":
            return "!status"
        if action == "set_target":
            return "!target <target>"
        if action == "research":
            return "!research <service> <version>"
        if action == "exploit":
            return "!killchain --auto"
        return ""

    def _process_input(self, line: str) -> None:
        """Route input to CLI or NLI and execute."""
        dest, payload = self.router.route(line)
        if dest == "cli":
            if isinstance(payload, list) and payload:
                self._invoke_cli(payload)
            elif isinstance(payload, list):
                self.console.print("[dim]No command.[/dim]")
            return

        self._invoke_nli(str(payload))
