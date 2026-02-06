"""Console banner content."""

BANNER_TEXT = """[bold green]ClawPwn Console[/bold green]

[dim]Quick start (authorized scope):[/dim]
  1. init project: [cyan]clawpwn init[/cyan]
  2. set target:  [cyan]target https://example.com[/cyan]
  3. scan:        [cyan]scan --depth normal[/cyan]
  4. report:      [cyan]report --format html[/cyan]

[dim]Find help fast:[/dim]
  [cyan]help topics[/cyan]    - List help topics
  [cyan]help workflow[/cyan]  - Pentest workflow
  [cyan]help scan[/cyan]      - Scan flags and examples
  [cyan]help lan[/cyan]       - LAN discovery and scanning
  [cyan]!scan --help[/cyan]   - Full CLI help for a command
  [cyan]?how do I ...[/cyan]  - Ask in natural language

[dim]Note:[/dim]
  [cyan]console[/cyan] is not available inside the console (prevents nested sessions)

[dim]Commands:[/dim]
  [cyan]scan[/cyan], [cyan]target[/cyan], [cyan]status[/cyan], [cyan]killchain[/cyan], [cyan]report[/cyan], [cyan]logs[/cyan], [cyan]config[/cyan]
  [cyan]objective[/cyan], [cyan]memory[/cyan]

[dim]Special:[/dim]
  [yellow]![/yellow]command  - Force CLI mode (e.g., !scan --help)
  [yellow]?[/yellow]question - Force NLI mode (e.g., ?what did we find)

[dim]Built-in:[/dim]
  [cyan]exit[/cyan], [cyan]quit[/cyan], [cyan]q[/cyan] - Exit console
  [cyan]restart[/cyan]       - Restart console session
  [cyan]clear[/cyan], [cyan]cls[/cyan]     - Clear screen
  [cyan]history[/cyan]       - Show command history
  [cyan]mode[/cyan] [cli|nli|auto] - Switch input mode (also shown in prompt)
    [dim]Examples:[/dim] [cyan]mode cli[/cyan] / [cyan]mode nli[/cyan] / [cyan]mode auto[/cyan]

[dim]Tab completion and history (↑↓) are available.[/dim]
"""
