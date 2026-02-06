"""Help and banner behavior for ConsoleApp."""

import re

from rich.panel import Panel

from .banner import BANNER_TEXT


class HelpMixin:
    """Provide help topic resolution and rendering."""

    def _print_banner(self) -> None:
        """Print the console welcome banner."""
        self.console.print(Panel(BANNER_TEXT, border_style="green"))

    def _resolve_help_topic(self, topic: str) -> str | None:
        cleaned = re.sub(r"[^a-z0-9]+", " ", topic.lower()).strip()
        if not cleaned:
            return None
        if cleaned in self.HELP_TOPIC_ALIASES:
            cleaned = self.HELP_TOPIC_ALIASES[cleaned]

        compact = cleaned.replace(" ", "")
        if compact in self.HELP_TOPICS:
            return compact
        if cleaned in self.HELP_TOPICS:
            return cleaned

        for key in self.HELP_TOPICS:
            if key in cleaned.split():
                return key
        return None

    def _print_help_topics(self) -> None:
        topics = ", ".join(sorted(self.HELP_TOPICS.keys()))
        self.console.print(f"[dim]Help topics:[/dim] {topics}")
        self.console.print("[dim]Use: help <topic>[/dim]")
        self.console.print("[dim]Note: 'console' cannot be started from inside the console.[/dim]")

    def _print_help_topic(self, topic: str) -> None:
        key = self._resolve_help_topic(topic)
        if not key:
            self.console.print(f"[yellow]Unknown help topic:[/yellow] {topic}")
            self._print_help_topics()
            return
        self.console.print(Panel(self.HELP_TOPICS[key], title=f"Help: {key}", border_style="cyan"))
