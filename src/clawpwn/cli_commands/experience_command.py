"""Experience database CLI command."""

import typer

from .shared import app, console


@app.command()
def experience(
    domain: str | None = typer.Option(None, "--domain", help="Show history for a specific domain"),
    clear: bool = typer.Option(False, "--clear", help="Wipe all experience data"),
) -> None:
    """Show or manage the global experience database."""
    from clawpwn.modules.experience import ExperienceManager

    mgr = ExperienceManager()
    if clear:
        mgr.clear()
        console.print("[green]Experience database cleared.[/green]")
        return
    if domain:
        history = mgr.get_target_history(domain)
        if not history:
            console.print(f"[dim]No experience for {domain}.[/dim]")
            return
        console.print(f"[bold]Experience for {domain}:[/bold]")
        for rec in history:
            tag = "[red]VULN[/red]" if rec.result == "vulnerable" else "[green]OK[/green]"
            payload = f" | payload: {rec.effective_payload}" if rec.effective_payload else ""
            console.print(f"  {tag} {rec.check_type} (x{rec.hit_count}){payload}")
        return
    stats = mgr.get_stats()
    if not stats or stats.get("total_records", 0) == 0:
        console.print("[dim]No experience data yet. Run a scan first.[/dim]")
        return
    console.print("[bold]Experience Database Stats:[/bold]")
    console.print(f"  Total records:  {stats['total_records']}")
    console.print(f"  Vulnerable:     {stats['vulnerable']}")
    console.print(f"  Not vulnerable: {stats['not_vulnerable']}")
    console.print(f"  Unique domains: {stats['unique_domains']}")
