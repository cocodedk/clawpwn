"""Report generation and log viewing CLI commands."""

import typer

from .deps import cli_module
from .shared import app, console


@app.command()
def report(
    format: str = typer.Option("html", "--format", help="Report format: html, pdf, json, md"),
    include_evidence: bool = typer.Option(
        True,
        "--include-evidence/--no-evidence",
        help="Include evidence in report",
    ),
) -> None:
    """Generate a penetration testing report."""
    cli = cli_module()
    project_dir = cli.require_project()

    from clawpwn.modules.report import ReportConfig, ReportGenerator

    console.print(f"[blue]Generating {format.upper()} report...[/blue]")
    try:
        generator = ReportGenerator(project_dir)
        try:
            config = ReportConfig(
                format=format,
                include_evidence=include_evidence,
                include_remediation=True,
                executive_summary=True,
            )
            report_file = generator.generate(config)
            console.print(f"[green]Report generated:[/green] {report_file}")
            console.print(f"[dim]Location: {report_file.parent}[/dim]")
        finally:
            generator.close()
    except Exception as exc:
        console.print(f"[red]Report generation failed: {exc}[/red]")
        raise typer.Exit(1) from exc


@app.command()
def logs(
    limit: int = typer.Option(50, "--limit", help="Number of log entries to show"),
    level: str | None = typer.Option(
        None,
        "--level",
        help="Filter by level (DEBUG, INFO, WARNING, ERROR)",
    ),
) -> None:
    """Show project logs."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)

    from sqlalchemy import desc

    from clawpwn.db.models import Log

    query = session.session.query(Log).order_by(desc(Log.created_at))
    if level:
        query = query.filter_by(level=level.upper())
    logs_list = query.limit(limit).all()

    if not logs_list:
        console.print("[dim]No logs found.[/dim]")
        return

    console.print(f"[bold]Recent Logs ({len(logs_list)} entries):[/bold]\n")

    level_colors = {
        "DEBUG": "dim",
        "INFO": "blue",
        "WARNING": "yellow",
        "ERROR": "red",
    }
    for entry in logs_list:
        level_str = str(entry.level)
        color = level_colors.get(level_str, "white")
        timestamp = (
            entry.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(entry.created_at, "strftime")
            else str(entry.created_at)
        )
        console.print(
            f"[{color}]{timestamp}[/] | "
            f"[bold {color}]{level_str:8}[/] | "
            f"[cyan]{str(entry.phase) or 'N/A':15}[/] | "
            f"{entry.message}"
        )
