"""Project information and status CLI commands."""

from pathlib import Path

import typer
from rich.panel import Panel

from .deps import cli_module
from .shared import app, console


@app.command()
def version() -> None:
    """Show the installed ClawPwn version."""
    try:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as pkg_version
    except ImportError:  # pragma: no cover
        from importlib_metadata import PackageNotFoundError
        from importlib_metadata import version as pkg_version

    try:
        current_version = pkg_version("clawpwn")
    except PackageNotFoundError:
        current_version = "0.0.0+unknown"

    console.print(f"ClawPwn {current_version}")


@app.command()
def target(url: str = typer.Argument(..., help="Target URL or IP address")) -> None:
    """Set the primary target for this project."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    session.set_target(url)
    console.print(f"[green]Target set to:[/green] {url}")


@app.command()
def status() -> None:
    """Show current project status and phase."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    state = session.get_state()
    if not state:
        console.print("[red]No project state found.[/red]")
        return

    target_display = state.target or "[dim]Not set[/dim]"
    findings_text = (
        f"{state.findings_count} ({state.critical_count} critical, {state.high_count} high)"
        if state.findings_count > 0
        else "0"
    )
    console.print(
        Panel(
            f"[bold]Project:[/bold] {state.project_path}\n"
            f"[bold]Target:[/bold] {target_display}\n"
            f"[bold]Current Phase:[/bold] {state.current_phase}\n"
            f"[bold]Findings:[/bold] {findings_text}\n"
            f"[bold]Created:[/bold] {state.created_at}",
            title="Project Status",
            border_style="blue",
        )
    )


@app.command()
def list_projects() -> None:
    """List all ClawPwn projects."""
    cli = cli_module()
    home = Path.home()
    projects: list[dict[str, str | Path]] = []

    for search_dir in [home / "pentest", home / "projects", home / "Documents", home]:
        if not search_dir.exists():
            continue
        try:
            for item in search_dir.iterdir():
                if not (item.is_dir() and (item / ".clawpwn").exists()):
                    continue
                db_path = cli.get_project_db_path(item)
                if not (db_path and db_path.exists()):
                    continue
                try:
                    session = cli.SessionManager(db_path)
                    state = session.get_state()
                except Exception:
                    continue
                if state:
                    projects.append(
                        {
                            "name": item.name,
                            "path": item,
                            "target": state.target or "No target",
                            "phase": state.current_phase,
                        }
                    )
        except PermissionError:
            continue

    if not projects:
        console.print("[dim]No projects found.[/dim]")
        return

    console.print("[bold]Projects:[/bold]")
    for project in projects:
        console.print(
            f"  • [cyan]{project['name']}[/cyan] - "
            f"Phase: {project['phase']} - Target: {project['target']}"
        )
