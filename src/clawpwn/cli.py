"""ClawPwn CLI - AI-powered penetration testing tool."""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from clawpwn.db.init import init_db
from clawpwn.db.models import ProjectState
from clawpwn.modules.session import SessionManager
from clawpwn.modules.scanner import Scanner, ScanConfig
from clawpwn.modules.network import NetworkDiscovery
from clawpwn.ai.orchestrator import AIOrchestrator
from clawpwn.ai.nli import NaturalLanguageInterface

app = typer.Typer(
    name="clawpwn",
    help="AI-powered penetration testing tool",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Show the installed ClawPwn version."""
    try:
        from importlib.metadata import PackageNotFoundError, version as pkg_version
    except ImportError:  # pragma: no cover
        from importlib_metadata import PackageNotFoundError, version as pkg_version

    try:
        current_version = pkg_version("clawpwn")
    except PackageNotFoundError:
        current_version = "0.0.0+unknown"

    console.print(f"ClawPwn {current_version}")


def get_project_dir() -> Optional[Path]:
    """Find the project directory by looking for .clawpwn folder."""
    current = Path.cwd()
    while current != current.parent:
        if (current / ".clawpwn").exists():
            return current
        current = current.parent
    return None


def require_project() -> Path:
    """Ensure we're in a clawpwn project directory."""
    project_dir = get_project_dir()
    if not project_dir:
        console.print(
            "[red]Error: Not in a clawpwn project. Run 'clawpwn init' first.[/red]"
        )
        raise typer.Exit(1)
    return project_dir


@app.command()
def init():
    """Initialize a new pentest project in the current directory."""
    project_dir = Path.cwd()
    clawpwn_dir = project_dir / ".clawpwn"

    if clawpwn_dir.exists():
        console.print(f"[yellow]Project already initialized at {project_dir}[/yellow]")
        return

    # Create directory structure
    clawpwn_dir.mkdir(exist_ok=True)
    (project_dir / "evidence").mkdir(exist_ok=True)
    (project_dir / "exploits").mkdir(exist_ok=True)
    (project_dir / "report").mkdir(exist_ok=True)

    # Initialize database
    db_path = clawpwn_dir / "clawpwn.db"
    init_db(db_path)

    # Create initial project state
    session = SessionManager(db_path)
    session.create_project(str(project_dir))

    # Create config template
    from clawpwn.config import create_project_config_template
    env_path = create_project_config_template(project_dir)

    console.print(
        Panel(
            f"[green]Initialized ClawPwn project at[/green]\n{project_dir}\n\n"
            f"[dim]Structure:[/dim]\n"
            f"  .clawpwn/       - Config & database\n"
            f"  evidence/       - Screenshots, logs\n"
            f"  exploits/       - Downloaded exploits\n"
            f"  report/         - Generated reports\n\n"
            f"[yellow]Next steps:[/yellow]\n"
            f"  1. Set API key: export ANTHROPIC_API_KEY=your-key\n"
            f"     Or edit: {env_path}\n"
            f"  2. Set target: clawpwn target https://example.com\n"
            f"  3. Run scan: clawpwn scan",
            title="ClawPwn",
            border_style="green",
        )
    )


@app.command()
def target(
    url: str = typer.Argument(..., help="Target URL or IP address"),
):
    """Set the primary target for this project."""
    project_dir = require_project()
    db_path = project_dir / ".clawpwn" / "clawpwn.db"

    session = SessionManager(db_path)
    session.set_target(url)

    console.print(f"[green]Target set to:[/green] {url}")


@app.command()
def status():
    """Show current project status and phase."""
    project_dir = require_project()
    db_path = project_dir / ".clawpwn" / "clawpwn.db"

    session = SessionManager(db_path)
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
def list_projects():
    """List all ClawPwn projects."""
    home = Path.home()
    projects = []

    # Search common pentest directories
    search_dirs = [
        home / "pentest",
        home / "projects",
        home / "Documents",
        home,
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        try:
            for item in search_dir.iterdir():
                if item.is_dir() and (item / ".clawpwn").exists():
                    db_path = item / ".clawpwn" / "clawpwn.db"
                    if db_path.exists():
                        try:
                            session = SessionManager(db_path)
                            state = session.get_state()
                            if state:
                                projects.append(
                                    {
                                        "name": item.name,
                                        "path": item,
                                        "target": state.target or "No target",
                                        "phase": state.current_phase,
                                    }
                                )
                        except Exception:
                            pass
        except PermissionError:
            continue

    if not projects:
        console.print("[dim]No projects found.[/dim]")
        return

    console.print("[bold]Projects:[/bold]")
    for p in projects:
        console.print(
            f"  • [cyan]{p['name']}[/cyan] - Phase: {p['phase']} - Target: {p['target']}"
        )


@app.command()
def scan(
    auto: bool = typer.Option(False, "--auto", help="Run AI-guided scan automatically"),
    depth: str = typer.Option(
        "normal", "--depth", help="Scan depth: quick, normal, deep"
    ),
):
    """Start the scanning phase."""
    project_dir = require_project()
    db_path = project_dir / ".clawpwn" / "clawpwn.db"

    session = SessionManager(db_path)
    state = session.get_state()

    if not state or not state.target:
        console.print("[red]No target set. Run 'clawpwn target <url>' first.[/red]")
        raise typer.Exit(1)

    target_url = state.target

    console.print(f"[blue]Starting scan phase for {target_url}...[/blue]")

    # Run network discovery first
    console.print("[*] Phase 1: Network Discovery")

    async def run_scan():
        # Initialize scanner
        scanner = Scanner(project_dir)

        # Run web vulnerability scan
        config = ScanConfig(
            target=target_url,
            depth=depth,
        )

        console.print(f"[*] Phase 2: Web Application Scanning ({depth} mode)")
        findings = await scanner.scan(target_url, config)

        return findings

    try:
        findings = asyncio.run(run_scan())

        if findings:
            console.print(
                f"\n[green]Scan complete! Found {len(findings)} potential issues.[/green]"
            )
            console.print("\n[dim]Use 'clawpwn status' to see detailed findings.[/dim]")
        else:
            console.print(
                "\n[green]Scan complete! No obvious vulnerabilities found.[/green]"
            )

        session.update_phase("Vulnerability Research")

    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def killchain(
    auto: bool = typer.Option(
        False, "--auto", help="Run full kill chain automatically with AI guidance"
    ),
    target: Optional[str] = typer.Option(None, "--target", help="Override target URL"),
):
    """Run the full attack kill chain with AI guidance."""
    project_dir = require_project()
    db_path = project_dir / ".clawpwn" / "clawpwn.db"

    session = SessionManager(db_path)
    state = session.get_state()

    if not state or not state.target:
        console.print("[red]No target set. Run 'clawpwn target <url>' first.[/red]")
        raise typer.Exit(1)

    target_url = target or state.target

    console.print(
        Panel(
            f"[yellow]Starting AI-guided kill chain for {target_url}...[/yellow]\n\n"
            f"[dim]This will run through all phases:[/dim]\n"
            f"  1. Reconnaissance\n"
            f"  2. Enumeration\n"
            f"  3. Vulnerability Research\n"
            f"  4. Exploitation\n"
            f"  5. Post-Exploitation\n"
            f"  6. Lateral Movement\n"
            f"  7. Persistence\n"
            f"  8. Exfiltration\n\n"
            f"[cyan]Mode: {'AUTO (AI makes all decisions)' if auto else 'AI-ASSISTED (will ask for approval on critical actions)'}[/cyan]",
            title="AI Kill Chain",
            border_style="yellow",
        )
    )

    async def run_killchain():
        orchestrator = AIOrchestrator(project_dir)

        if auto:
            # Auto mode - AI makes all decisions
            console.print("[blue]Running in automatic mode...[/blue]")
            results = await orchestrator.run_kill_chain(target_url, auto=True)
        else:
            # AI-assisted mode - ask for approval on critical actions
            console.print("[blue]Running in AI-assisted mode...[/blue]")
            console.print(
                "[dim]You will be prompted for approval on high-risk actions.[/dim]\n"
            )

            def approval_callback(action):
                console.print(f"\n[yellow]AI wants to:[/yellow] {action.reason}")
                console.print(
                    f"[dim]Target: {action.target} | Risk: {action.risk_level}[/dim]"
                )

                if action.risk_level in ["critical", "high"]:
                    response = input("Approve? (yes/no): ").lower().strip()
                    return response == "yes"
                return True

            results = await orchestrator.run_kill_chain(
                target_url, auto=False, approval_callback=approval_callback
            )

        return results

    try:
        results = asyncio.run(run_killchain())

        if results["stopped"]:
            console.print(f"\n[yellow]Kill chain stopped: {results['reason']}[/yellow]")
        else:
            console.print(f"\n[green]Kill chain complete![/green]")
            console.print(f"  Phases: {len(results['phases_completed'])}")
            console.print(f"  Findings: {len(results['findings'])}")
            console.print(
                f"  Exploits: {len([e for e in results['exploits'] if e.success])}"
            )

        session.update_phase(
            "Exploitation" if results["exploits"] else "Vulnerability Research"
        )

    except Exception as e:
        console.print(f"[red]Kill chain failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def report(
    format: str = typer.Option(
        "html", "--format", help="Report format: html, pdf, json, md"
    ),
    include_evidence: bool = typer.Option(
        True, "--include-evidence/--no-evidence", help="Include evidence in report"
    ),
):
    """Generate a penetration testing report."""
    project_dir = require_project()

    from clawpwn.modules.report import ReportGenerator, ReportConfig

    console.print(f"[blue]Generating {format.upper()} report...[/blue]")

    try:
        generator = ReportGenerator(project_dir)
        config = ReportConfig(
            format=format,
            include_evidence=include_evidence,
            include_remediation=True,
            executive_summary=True,
        )

        report_file = generator.generate(config)

        console.print(f"[green]Report generated:[/green] {report_file}")
        console.print(f"[dim]Location: {report_file.parent}[/dim]")

    except Exception as e:
        console.print(f"[red]Report generation failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def logs(
    limit: int = typer.Option(50, "--limit", help="Number of log entries to show"),
    level: Optional[str] = typer.Option(
        None, "--level", help="Filter by level (DEBUG, INFO, WARNING, ERROR)"
    ),
):
    """Show project logs."""
    project_dir = require_project()
    db_path = project_dir / ".clawpwn" / "clawpwn.db"

    session = SessionManager(db_path)

    from clawpwn.db.models import Log
    from sqlalchemy import desc

    query = session.session.query(Log).order_by(desc(Log.created_at))

    if level:
        query = query.filter_by(level=level.upper())

    logs = query.limit(limit).all()

    if not logs:
        console.print("[dim]No logs found.[/dim]")
        return

    console.print(f"[bold]Recent Logs ({len(logs)} entries):[/bold]\n")

    level_colors = {
        "DEBUG": "dim",
        "INFO": "blue",
        "WARNING": "yellow",
        "ERROR": "red",
    }

    for log in logs:
        level_str = str(log.level)
        color = level_colors.get(level_str, "white")
        timestamp = (
            log.created_at.strftime("%Y-%m-%d %H:%M:%S")
            if hasattr(log.created_at, "strftime")
            else str(log.created_at)
        )

        console.print(
            f"[{color}]{timestamp}[/] | "
            f"[bold {color}]{level_str:8}[/] | "
            f"[cyan]{str(log.phase) or 'N/A':15}[/] | "
            f"{log.message}"
        )


@app.command()
def interactive():
    """Start interactive natural language mode."""
    project_dir = require_project()

    console.print(
        Panel(
            "[green]Interactive Natural Language Mode[/green]\n\n"
            "You can now type commands in natural language:\n"
            "  • 'scan example.com'\n"
            "  • 'check for vulnerabilities'\n"
            "  • 'run killchain'\n"
            "  • 'what's the status?'\n"
            "  • 'help'\n\n"
            "Type 'exit' or 'quit' to exit.",
            title="Interactive Mode",
            border_style="green",
        )
    )

    nli = NaturalLanguageInterface(project_dir)

    while True:
        try:
            console.print("\n[blue]clawpwn>[/blue] ", end="")
            command = input()

            if command.lower() in ["exit", "quit", "q"]:
                console.print("[green]Goodbye![/green]")
                break

            if not command.strip():
                continue

            result = nli.process_command(command)

            if result["success"]:
                console.print(f"[green]✓[/green] {result['response']}")
            else:
                console.print(f"[yellow]![/yellow] {result['response']}")

        except KeyboardInterrupt:
            console.print("\n[green]Goodbye![/green]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


@app.command()
def config(
    action: str = typer.Argument("show", help="Action: show, edit, init"),
    global_config: bool = typer.Option(False, "--global", help="Edit global config instead of project"),
):
    """Manage ClawPwn configuration and API keys."""
    from clawpwn.config import (
        create_global_config,
        create_project_config_template,
        load_global_config,
        load_project_config,
        get_project_dir,
    )
    
    if action == "init":
        if global_config:
            config_path = create_global_config()
            console.print(f"[green]Created global config:[/green] {config_path}")
        else:
            project_dir = require_project()
            env_path = create_project_config_template(project_dir)
            console.print(f"[green]Created project config:[/green] {env_path}")
            console.print("[dim]Edit the file and uncomment the API keys you want to use.[/dim]")
    
    elif action == "show":
        if global_config:
            config = load_global_config()
            console.print("[bold]Global Configuration (~/.clawpwn/config.yml):[/bold]")
            import yaml
            console.print(yaml.dump(config, default_flow_style=False))
        else:
            project_dir = get_project_dir()
            if project_dir:
                env_config = load_project_config(project_dir)
                if env_config:
                    console.print(f"[bold]Project Configuration ({project_dir}/.clawpwn/.env):[/bold]")
                    for key, value in env_config.items():
                        # Mask API keys
                        if "key" in key.lower() and value:
                            masked = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
                            console.print(f"  {key}={masked}")
                        else:
                            console.print(f"  {key}={value}")
                else:
                    console.print("[dim]No project config found. Run 'clawpwn config init' to create one.[/dim]")
            else:
                console.print("[yellow]Not in a project directory. Use --global to show global config.[/yellow]")
    
    elif action == "edit":
        if global_config:
            config_path = create_global_config()
            console.print(f"[green]Edit this file:[/green] {config_path}")
        else:
            project_dir = require_project()
            env_path = create_project_config_template(project_dir)
            console.print(f"[green]Edit this file:[/green] {env_path}")
    
    else:
        console.print(f"[red]Unknown action: {action}. Use 'show', 'edit', or 'init'.[/red]")


def main():
    """Entry point for the CLI."""
    app()
