"""Configuration CLI command."""

from pathlib import Path

import typer

from .deps import cli_module
from .shared import app, console, get_project_dir


@app.command()
def config(
    action: str = typer.Argument("show", help="Action: show, edit, init"),
    global_config: bool = typer.Option(
        False,
        "--global",
        help="Edit global config instead of project",
    ),
) -> None:
    """Manage ClawPwn configuration and API keys."""
    cli = cli_module()

    if action == "init":
        if global_config:
            config_path = cli.create_global_config()
            console.print(f"[green]Created global config:[/green] {config_path}")
            return

        project_dir = cli.require_project()
        env_path = cli.create_project_config_template(project_dir)
        console.print(f"[green]Created project config:[/green] {env_path}")
        console.print("[dim]Edit the file and uncomment the API keys you want to use.[/dim]")
        return

    if action == "show":
        if global_config:
            config_data = cli.load_global_config()
            console.print("[bold]Global Configuration (~/.clawpwn/config.yml):[/bold]")

            import yaml

            console.print(yaml.dump(config_data, default_flow_style=False))
            return

        project_dir = get_project_dir()
        if not project_dir:
            console.print(
                "[yellow]Not in a project directory. Use --global to show global config.[/yellow]"
            )
            return

        env_config = cli.load_project_config(project_dir)
        if not env_config:
            console.print("[dim]No project config found. Run 'clawpwn config init'.[/dim]")
            return

        env_path = cli.get_project_env_path(project_dir) or Path("unknown")
        console.print(f"[bold]Project Configuration ({env_path}):[/bold]")
        for key, value in env_config.items():
            if "key" in key.lower() and value:
                masked = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
                console.print(f"  {key}={masked}")
            else:
                console.print(f"  {key}={value}")
        return

    if action == "edit":
        if global_config:
            config_path = cli.create_global_config()
            console.print(f"[green]Edit this file:[/green] {config_path}")
            return

        project_dir = cli.require_project()
        env_path = cli.create_project_config_template(project_dir)
        console.print(f"[green]Edit this file:[/green] {env_path}")
        return

    console.print(f"[red]Unknown action: {action}. Use 'show', 'edit', or 'init'.[/red]")
