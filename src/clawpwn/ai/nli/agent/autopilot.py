"""Autonomous recon supervisor loop over the plan executor."""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

from clawpwn.ai.llm import LLMClient

from .autopilot_helpers import (
    AutopilotReport,
    attach_context,
    build_final_summary,
    build_system_prompt,
    clear_plan,
    cycle_message,
    filter_recon_tools,
    fmt_duration,
    should_continue,
)
from .plan_executor import run_plan_executor

# Re-export for public API.
__all__ = ["AutopilotReport", "run_autopilot"]


def run_autopilot(
    llm: LLMClient,
    project_dir: Path,
    max_cycles: int = 5,
    max_duration_hours: float = 4.0,
    verbose: bool = False,
    console: Console | None = None,
) -> AutopilotReport:
    """Run the autonomous recon supervisor loop.

    Each cycle delegates to ``run_plan_executor`` with a recon-only tool set
    and system prompt.  Between cycles a cheap LLM call decides whether new
    attack surfaces warrant another pass.
    """
    con = console or Console()
    report = AutopilotReport()
    start = time.monotonic()
    max_seconds = max_duration_hours * 3600

    tools = filter_recon_tools()
    base_prompt = build_system_prompt()

    for cycle in range(max_cycles):
        elapsed = time.monotonic() - start
        if elapsed >= max_seconds:
            con.print("[yellow]Duration limit reached — stopping.[/yellow]")
            break

        con.print(
            f"\n[bold cyan]Autopilot[/bold cyan] Cycle {cycle + 1}/{max_cycles}"
            f"  [dim]elapsed {fmt_duration(elapsed)}[/dim]"
        )

        system_prompt = attach_context(base_prompt, project_dir)
        user_message = cycle_message(cycle, report)

        if verbose:
            con.print(f"[dim]User message: {user_message[:120]}...[/dim]")

        progress_cb = _make_progress_cb(con) if verbose else None

        clear_plan(project_dir)

        result = run_plan_executor(
            llm=llm,
            project_dir=project_dir,
            tools=tools,
            system_prompt=system_prompt,
            user_message=user_message,
            on_progress=progress_cb,
            debug=verbose,
            replace_plan=True,
        )

        summary = str(result.get("text", "No summary available."))
        report.cycle_summaries.append(summary)
        report.cycles = cycle + 1
        con.print(f"\n[green]Cycle {cycle + 1} complete.[/green]")

        if cycle + 1 >= max_cycles:
            break

        cont, focus = should_continue(llm, summary, project_dir)
        if not cont:
            con.print("[cyan]No significant new surfaces — autopilot finished.[/cyan]")
            break
        con.print(f"[dim]Next focus: {focus}[/dim]")
        report._next_focus = focus  # type: ignore[attr-defined]

    report.duration_seconds = time.monotonic() - start
    report.final_summary = build_final_summary(report)
    return report


def _make_progress_cb(con: Console):
    """Return a progress callback that prints to the console."""

    def _on_progress(msg: str) -> None:
        if msg.startswith("\u2192"):
            con.print(f"[cyan]{msg}[/cyan]")
        elif msg.startswith("\u2713"):
            con.print(f"[green]{msg}[/green]")
        else:
            con.print(f"[italic dim]{msg}[/italic dim]")

    return _on_progress
