"""Autopilot CLI command — autonomous recon mode."""

import typer
from rich.panel import Panel

from .deps import cli_module
from .shared import app, console


@app.command()
def autopilot(
    target: str | None = typer.Argument(None, help="Target URL/IP (uses active if omitted)"),
    max_cycles: int = typer.Option(5, "--cycles", "-c", help="Max recon cycles"),
    max_duration: float = typer.Option(4.0, "--duration", "-d", help="Max hours"),
    scanner: str = typer.Option("naabu", "--scanner", "-s", help="Port scanner"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show progress details"),
) -> None:
    """Run autonomous reconnaissance and vulnerability detection.

    Scans the target through multiple cycles of recon, analysing results
    between cycles to discover and test new attack surfaces.  No exploitation
    or credential brute-forcing is performed.
    """
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    state = session.get_state()

    # Resolve target: explicit arg → active session target.
    effective_target = target or (state.target if state else None)
    if not effective_target:
        console.print("[red]No target specified and no active target set.[/red]")
        console.print(
            "[dim]Usage: clawpwn autopilot <target> or set one with 'clawpwn target'[/dim]"
        )
        raise typer.Exit(1)

    # Ensure scheme is present.
    if "://" not in effective_target:
        effective_target = f"http://{effective_target}"

    # Persist target in session so plan executor can find it.
    session.set_target(effective_target)

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {effective_target}\n"
            f"[bold cyan]Cycles:[/bold cyan] {max_cycles}  "
            f"[bold cyan]Duration limit:[/bold cyan] {max_duration}h\n"
            f"[bold cyan]Scanner:[/bold cyan] {scanner}\n\n"
            "[dim]Recon only — no exploitation or credential brute-forcing.[/dim]",
            title="Autopilot",
            border_style="cyan",
        )
    )

    from clawpwn.ai.llm import LLMClient
    from clawpwn.ai.nli.agent.autopilot import run_autopilot

    llm = LLMClient(project_dir=project_dir)
    report = run_autopilot(
        llm=llm,
        project_dir=project_dir,
        max_cycles=max_cycles,
        max_duration_hours=max_duration,
        verbose=verbose,
        console=console,
    )

    console.print(
        Panel(
            f"[green]{report.cycles} cycle(s) completed[/green]\n"
            f"[dim]{report.final_summary[:500]}[/dim]",
            title="Autopilot Complete",
            border_style="green",
        )
    )
