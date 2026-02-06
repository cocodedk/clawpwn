"""Objective and memory CLI commands."""

import typer

from .deps import cli_module
from .shared import app, console


@app.command()
def objective(
    action: str = typer.Argument("show", help="Action: show, set, clear"),
    text: str | None = typer.Argument(None, help="Objective text for 'set'"),
) -> None:
    """Manage the current objective for this project."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    memory_record = session.get_memory()

    if action == "show":
        if memory_record and memory_record.objective:
            console.print(f"[bold]Objective:[/bold] {memory_record.objective}")
        else:
            console.print("[dim]No objective set.[/dim]")
        return

    if action == "set":
        if not text:
            console.print("[yellow]Provide objective text.[/yellow]")
            raise typer.Exit(1)
        session.set_objective(text)
        console.print("[green]Objective updated.[/green]")
        return

    if action == "clear":
        session.set_objective("")
        console.print("[green]Objective cleared.[/green]")
        return

    console.print("[yellow]Usage: objective [show|set|clear] [text][/yellow]")
    raise typer.Exit(1)


@app.command()
def memory(
    action: str = typer.Argument("show", help="Action: show, clear"),
    limit: int = typer.Option(8, "--limit", help="Number of recent messages to show"),
) -> None:
    """Show or clear project memory."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    memory_record = session.get_memory()

    if action == "show":
        summary = memory_record.summary if memory_record else ""
        objective_text = memory_record.objective if memory_record else ""
        if objective_text:
            console.print(f"[bold]Objective:[/bold] {objective_text}")
        if summary:
            console.print(f"[bold]Summary:[/bold]\n{summary}")
        if not objective_text and not summary:
            console.print("[dim]Memory is empty.[/dim]")

        recent_messages = list(reversed(session.get_recent_messages(limit=limit)))
        if recent_messages:
            console.print("\n[bold]Recent messages:[/bold]")
            for msg in recent_messages:
                console.print(f"  [dim]{msg.role}:[/dim] {msg.content}")
        return

    if action == "clear":
        session.clear_memory()
        console.print("[green]Memory cleared.[/green]")
        return

    console.print("[yellow]Usage: memory [show|clear][/yellow]")
    raise typer.Exit(1)
