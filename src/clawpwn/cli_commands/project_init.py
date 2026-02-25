"""Project initialization CLI command."""

from pathlib import Path

import typer
from rich.panel import Panel

from clawpwn.db.init import init_db

from .deps import cli_module
from .shared import app, console


@app.command()
def init() -> None:
    """Initialize a new pentest project in the current directory."""
    project_dir = Path.cwd()
    clawpwn_dir = project_dir / ".clawpwn"

    if clawpwn_dir.exists():
        console.print(f"[yellow]Project already initialized at {project_dir}[/yellow]")
        return

    try:
        (project_dir / "evidence").mkdir(exist_ok=True)
        (project_dir / "exploits").mkdir(exist_ok=True)
        (project_dir / "report").mkdir(exist_ok=True)
    except PermissionError as exc:
        console.print(
            "[red]Error: Cannot write to this directory.[/red]\n"
            "[dim]Choose a writable location (e.g., under your workspace or /tmp) and "
            "run 'clawpwn init' again.[/dim]"
        )
        raise typer.Exit(1) from exc

    cli = cli_module()
    try:
        storage_dir = cli.ensure_project_storage_dir(project_dir)
        write_test = storage_dir / ".write_test"
        write_test.write_text("ok")
        write_test.unlink()
    except PermissionError as exc:
        console.print(
            "[red]Error: Project directory is not writable.[/red]\n"
            "[dim]Choose a writable location (e.g., under your workspace or /tmp) and "
            "run 'clawpwn init' again.[/dim]"
        )
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Error initializing project storage: {exc}[/red]")
        raise typer.Exit(1) from exc

    db_path = storage_dir / "clawpwn.db"
    init_db(db_path)

    session = cli.SessionManager(db_path)
    session.create_project(str(project_dir))
    env_path = cli.create_project_config_template(project_dir)

    if storage_dir == clawpwn_dir:
        storage_text = "  .clawpwn/       - Config & database\n"
    else:
        storage_text = (
            "  .clawpwn/       - Project marker\n"
            f"  data/           - Config & database ({storage_dir})\n"
        )

    console.print(
        Panel(
            f"[green]Initialized ClawPwn project at[/green]\n{project_dir}\n\n"
            f"[dim]Structure:[/dim]\n"
            f"{storage_text}"
            f"  evidence/       - Screenshots, logs\n"
            f"  exploits/       - Downloaded exploits\n"
            f"  report/         - Generated reports\n\n"
            f"[yellow]Next steps:[/yellow]\n"
            "  1. Configure LLM:\n"
            f"     Edit: {env_path}\n"
            "     Set: CLAWPWN_LLM_PROVIDER and CLAWPWN_LLM_API_KEY\n"
            "  2. Set target: clawpwn target https://example.com\n"
            "  3. Run scan: clawpwn scan",
            title="ClawPwn",
            border_style="green",
        )
    )
