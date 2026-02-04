"""Interactive console application for ClawPwn."""

import sys
from pathlib import Path

from prompt_toolkit import PromptSession
from rich.console import Console
from rich.panel import Panel

from clawpwn.config import get_project_db_path
from clawpwn.console.completer import CommandCompleter
from clawpwn.console.history import HistoryManager
from clawpwn.console.router import InputMode, InputRouter


class ConsoleApp:
    """Interactive console for clawpwn with CLI and NLI support."""

    def __init__(self, project_dir: Path | None = None) -> None:
        self.project_dir = project_dir
        self.session = None
        self.nli = None
        self.console = Console()
        self.history = HistoryManager()
        self.completer = CommandCompleter()
        self.router = InputRouter(mode=InputMode.AUTO)
        self.running = False

        if project_dir:
            db_path = get_project_db_path(project_dir)
            if db_path and db_path.exists():
                from clawpwn.modules.session import SessionManager

                self.session = SessionManager(db_path)
            from clawpwn.ai.nli import NaturalLanguageInterface

            self.nli = NaturalLanguageInterface(project_dir)

    def _print_banner(self) -> None:
        """Print the console welcome banner."""
        banner = """[bold green]ClawPwn Console[/bold green]

[dim]Commands:[/dim]
  [cyan]scan[/cyan], [cyan]target[/cyan], [cyan]status[/cyan], [cyan]killchain[/cyan], [cyan]report[/cyan], [cyan]logs[/cyan], [cyan]config[/cyan]

[dim]Special:[/dim]
  [yellow]![/yellow]command  - Force CLI mode (e.g., !scan --help)
  [yellow]?[/yellow]question - Force NLI mode (e.g., ?what did we find)

[dim]Built-in:[/dim]
  [cyan]exit[/cyan], [cyan]quit[/cyan], [cyan]q[/cyan] - Exit console
  [cyan]clear[/cyan], [cyan]cls[/cyan]     - Clear screen
  [cyan]history[/cyan]       - Show command history
  [cyan]mode[/cyan] [cli|nli|auto] - Switch input mode

[dim]Tab completion and history (↑↓) are available.[/dim]
"""
        self.console.print(Panel(banner, border_style="green"))

    def _build_prompt(self) -> str:
        """Build context-aware prompt string."""
        parts = ["clawpwn"]
        if self.session:
            try:
                state = self.session.get_state()
                if state and state.target:
                    target = state.target
                    if len(target) > 20:
                        target = target[:17] + "..."
                    parts.append(f"[{target}")
                    if state.phase:
                        parts.append(f"/{state.phase}")
                    parts.append("]")
            except Exception:
                pass
        return "".join(parts) + "> "

    def _handle_builtin(self, line: str) -> bool:
        """Handle built-in commands. Returns True if handled."""
        lower = line.strip().lower()
        if lower in ("exit", "quit", "q"):
            self.console.print("[green]Goodbye![/green]")
            self.running = False
            return True
        if lower in ("clear", "cls"):
            self.console.clear()
            return True
        if lower == "history":
            recent = self.history.get_recent(20)
            for i, cmd in enumerate(recent, 1):
                self.console.print(f"  [dim]{i}[/]  {cmd}")
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
        if lower == "help":
            self._print_banner()
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
            except SystemExit as e:
                if e.code not in (None, 0):
                    self.console.print(f"[red]Command exited with code {e.code}[/red]")
        finally:
            sys.argv = original_argv

    def _invoke_nli(self, text: str) -> None:
        """Process natural language via NLI."""
        if not self.nli:
            self.console.print(
                "[yellow]Natural language mode requires a project. Run from a project directory or use CLI commands.[/yellow]"
            )
            return
        if not text.strip():
            return
        try:
            result = self.nli.process_command(text)
            if result.get("success"):
                self.console.print(f"[green]✓[/green] {result.get('response', '')}")
            else:
                self.console.print(f"[yellow]![/yellow] {result.get('response', '')}")
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")

    def _process_input(self, line: str) -> None:
        """Route input to CLI or NLI and execute."""
        dest, payload = self.router.route(line)
        if dest == "cli":
            if isinstance(payload, list) and payload:
                self._invoke_cli(payload)
            elif isinstance(payload, list) and not payload:
                self.console.print("[dim]No command.[/dim]")
        else:
            self._invoke_nli(str(payload))

    def run(self) -> None:
        """Start the REPL loop."""
        self._print_banner()
        self.running = True

        session = PromptSession(
            history=self.history.get_history(),
            completer=self.completer,
            complete_while_typing=False,
            enable_history_search=True,
        )

        try:
            while self.running:
                try:
                    prompt = self._build_prompt()
                    line = session.prompt(prompt)
                    if not line.strip():
                        continue
                    if self._handle_builtin(line):
                        continue
                    self._process_input(line)
                except KeyboardInterrupt:
                    self.console.print("\n[dim]Use 'exit' to quit[/dim]")
                except EOFError:
                    self.console.print("\n[green]Goodbye![/green]")
                    break
        finally:
            if self.nli is not None:
                self.nli.close()
