"""Kill chain CLI command."""

import typer
from rich.panel import Panel

from clawpwn.ai.orchestrator import AIOrchestrator

from .deps import cli_module
from .shared import app, console


@app.command()
def killchain(
    auto: bool = typer.Option(
        False,
        "--auto",
        help="Run full kill chain automatically with AI guidance",
    ),
    target: str | None = typer.Option(None, "--target", help="Override target URL"),
) -> None:
    """Run the full attack kill chain with AI guidance."""
    cli = cli_module()
    project_dir = cli.require_project()
    db_path = cli.get_project_db_path(project_dir)
    if db_path is None:
        console.print("[red]Project storage not found. Run 'clawpwn init' first.[/red]")
        raise typer.Exit(1)

    session = cli.SessionManager(db_path)
    state = session.get_state()
    if not (state and state.target):
        console.print("[red]No target set. Run 'clawpwn target <url>' first.[/red]")
        raise typer.Exit(1)

    target_url = target or state.target
    if target_url and "://" not in target_url:
        target_url_with_scheme = f"http://{target_url}"
        console.print(
            "[dim]No scheme provided. Using "
            f"{target_url_with_scheme} for this run only (session target unchanged).[/dim]"
        )
        if typer.confirm("Save this as the project target?", default=False):
            session.set_target(target_url_with_scheme)
            console.print(f"[dim]Target saved: {target_url_with_scheme}[/dim]")
        target_url = target_url_with_scheme

    console.print(
        Panel(
            f"[yellow]Starting AI-guided kill chain for {target_url}...[/yellow]\n\n"
            "[dim]This will run through all phases:[/dim]\n"
            "  1. Reconnaissance\n"
            "  2. Enumeration\n"
            "  3. Vulnerability Research\n"
            "  4. Exploitation\n"
            "  5. Post-Exploitation\n"
            "  6. Lateral Movement\n"
            "  7. Persistence\n"
            "  8. Exfiltration\n\n"
            "[cyan]Mode: "
            f"{'AUTO (AI makes all decisions)' if auto else 'AI-ASSISTED (will ask for approval on critical actions)'}"
            "[/cyan]",
            title="AI Kill Chain",
            border_style="yellow",
        )
    )

    async def run_killchain():
        orchestrator = AIOrchestrator(project_dir)
        try:
            if auto:
                console.print("[blue]Running in automatic mode...[/blue]")
                return await orchestrator.run_kill_chain(target_url, auto=True)

            console.print("[blue]Running in AI-assisted mode...[/blue]")
            console.print("[dim]You will be prompted for approval on high-risk actions.[/dim]\n")

            def approval_callback(action):
                console.print(f"\n[yellow]AI wants to:[/yellow] {action.reason}")
                console.print(f"[dim]Target: {action.target} | Risk: {action.risk_level}[/dim]")
                if action.risk_level in ["critical", "high"]:
                    response = input("Approve? (yes/no): ").lower().strip()
                    return response == "yes"
                return True

            return await orchestrator.run_kill_chain(
                target_url,
                auto=False,
                approval_callback=approval_callback,
            )
        finally:
            orchestrator.close()

    try:
        results = cli.safe_async_run(run_killchain())
        if results["stopped"]:
            console.print(f"\n[yellow]Kill chain stopped: {results['reason']}[/yellow]")
        else:
            console.print("\n[green]Kill chain complete![/green]")
            console.print(f"  Phases: {len(results['phases_completed'])}")
            console.print(f"  Findings: {len(results['findings'])}")
            console.print(
                f"  Exploits: {len([item for item in results['exploits'] if item.success])}"
            )

        session.update_phase("Exploitation" if results["exploits"] else "Vulnerability Research")
    except Exception as exc:
        console.print(f"[red]Kill chain failed: {exc}[/red]")
        raise typer.Exit(1) from exc
