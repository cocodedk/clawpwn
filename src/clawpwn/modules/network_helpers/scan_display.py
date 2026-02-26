"""Live display panel for single-range port scans."""

import asyncio
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from clawpwn.tools.masscan import HostResult


@dataclass
class ScanProgressState:
    """Tracks discovered ports and timing for the live display."""

    ports: list[int] = field(default_factory=list)
    started: float = field(default_factory=time.perf_counter)
    complete: bool = False

    @property
    def elapsed(self) -> float:
        return time.perf_counter() - self.started

    def add_port(self, port: int) -> None:
        if port not in self.ports:
            self.ports.append(port)


def create_scan_panel(state: ScanProgressState, scanner_type: str, target: str) -> Panel:
    """Build a Rich Panel showing scan progress."""
    elapsed = f"{state.elapsed:.1f}s"
    count = len(state.ports)

    if state.complete:
        status = Text("✓ Complete", style="green")
    else:
        status = Text("● Scanning", style="cyan")

    line1 = Text()
    line1.append_text(status)
    line1.append(f"    ⏱ {elapsed}    {count} found", style="dim")

    content = Text()
    content.append_text(line1)

    if state.ports:
        port_str = ", ".join(str(p) for p in sorted(state.ports))
        if len(port_str) > 60:
            port_str = port_str[:57] + "..."
        content.append("\n")
        content.append(f"Ports: {port_str}", style="green")

    return Panel(
        content,
        title=f"[bold cyan]Port Scan[/] [dim]({scanner_type})[/]",
        subtitle=f"[dim]{target}[/]",
        border_style="cyan",
        padding=(0, 1),
    )


async def run_scan_with_live_display(
    scan_coro_factory: Callable[..., Coroutine[Any, Any, list[HostResult]]],
    scanner_type: str,
    target: str,
    console: Any,
) -> list[HostResult]:
    """Run a scan coroutine with a Rich Live progress panel.

    Args:
        scan_coro_factory: callable(**kwargs) returning the scan coroutine.
            Receives ``on_port=callback`` kwarg for naabu.
        scanner_type: scanner name for the panel title.
        target: scan target for the panel subtitle.
        console: Rich Console instance.
    """
    state = ScanProgressState()

    def on_port(_ip: str, port: int) -> None:
        state.add_port(port)

    with Live(
        create_scan_panel(state, scanner_type, target),
        console=console,
        refresh_per_second=4,
    ) as live:
        scan_task = asyncio.ensure_future(scan_coro_factory(on_port=on_port))
        while not scan_task.done():
            await asyncio.sleep(0.25)
            live.update(create_scan_panel(state, scanner_type, target))

        state.complete = True
        live.update(create_scan_panel(state, scanner_type, target))

    return scan_task.result()
