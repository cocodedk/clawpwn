"""``clawpwn doctor`` — pre-flight health check command."""

from __future__ import annotations

import typer

from .shared import app, console, get_project_dir

STATUS_ICONS = {
    "pass": "[green]✓[/green]",
    "fail": "[red]✗[/red]",
    "warn": "[yellow]![/yellow]",
}


@app.command()
def doctor() -> None:
    """Check system readiness for penetration testing."""
    from .doctor_checks import (
        CheckResult,
        check_external_tools,
        check_privileges,
        check_python_version,
        check_wordlists,
    )
    from .doctor_env_checks import (
        check_api_key,
        check_api_key_valid,
        check_llm_provider,
        check_project_status,
    )

    console.print("\n[bold]ClawPwn Doctor[/bold]")
    console.print("─" * 36)
    console.print()

    project_dir = get_project_dir()
    results: list[CheckResult] = []

    # Scalar checks
    results.append(check_python_version())
    results.append(check_llm_provider(project_dir))
    results.append(check_api_key(project_dir))
    results.append(check_api_key_valid(project_dir))

    # Tool checks (returns a list)
    results.extend(check_external_tools())

    results.append(check_privileges())
    results.append(check_wordlists())

    # Project check (may be None)
    proj = check_project_status(project_dir)
    if proj:
        results.append(proj)

    # Render
    for r in results:
        icon = STATUS_ICONS.get(r.status, "?")
        console.print(f"  {icon} {r.message}")
        if r.fix and r.status in ("fail", "warn"):
            for line in r.fix.splitlines():
                console.print(f"    {line}")

    # Summary
    counts = {"pass": 0, "fail": 0, "warn": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    console.print()
    console.print(
        f"  Summary: {counts['pass']} passed, {counts['warn']} warnings, {counts['fail']} failed"
    )
    console.print()

    if counts["fail"] > 0:
        raise typer.Exit(1)
