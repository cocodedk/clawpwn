"""Subdomain enumeration CLI command."""

import typer

from .deps import cli_module
from .shared import app, console


@app.command("recon")
def recon(
    domain: str = typer.Argument(..., help="Target domain to enumerate subdomains for"),
    mode: str = typer.Option("passive", "--mode", "-m", help="Enumeration mode: passive or active"),
    timeout: int = typer.Option(300, "--timeout", "-t", help="Timeout in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    max_dns_queries: int = typer.Option(
        0, "--max-dns-queries", help="Maximum concurrent DNS queries (0 = unlimited)"
    ),
) -> None:
    """Enumerate subdomains for a domain using OWASP Amass."""
    cli = cli_module()

    from clawpwn.modules.recon import AmassConfig, run_amass

    config = AmassConfig(
        mode=mode,
        timeout=timeout,
        verbose=verbose,
        max_dns_queries=max_dns_queries,
    )

    console.print(f"[blue]Starting {mode} subdomain enumeration for {domain}...[/blue]")

    try:
        results = cli.safe_async_run(run_amass(domain, config))
    except Exception as exc:
        console.print(f"[red]Amass enumeration failed: {exc}[/red]")
        raise typer.Exit(1) from exc

    if not results:
        console.print("[yellow]No subdomains discovered.[/yellow]")
        _log_to_session(cli, domain, 0)
        return

    console.print(f"[green]Discovered {len(results)} subdomain(s):[/green]")
    for sub in results:
        ips = ", ".join(sub.addresses) if sub.addresses else "no IP"
        console.print(f"  [cyan]{sub.name}[/cyan]  ({ips})")

    _log_to_session(cli, domain, len(results))


def _log_to_session(cli, domain: str, count: int) -> None:
    """Log recon results to the active project session if available."""
    try:
        project_dir = cli.get_project_dir()
        if project_dir is None:
            return
        db_path = cli.get_project_db_path(project_dir)
        if db_path is None:
            return
        session = cli.SessionManager(db_path)
        session.add_log(
            f"Subdomain enumeration ({domain}): {count} subdomains",
            phase="Reconnaissance",
        )
    except Exception:
        pass
