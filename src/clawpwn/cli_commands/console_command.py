"""Interactive console CLI commands."""

import os
from shutil import which

from .shared import app, console, get_project_dir


@app.command(name="console")
def console_cmd() -> None:
    """Start the interactive console (recommended)."""
    from clawpwn.console import ConsoleApp

    if os.environ.get("CLAWPWN_CONSOLE_ACTIVE") == "1":
        console.print(
            "[yellow]Console already running. Use 'exit' to leave the current session.[/yellow]"
        )
        return

    while True:
        project_dir = get_project_dir()
        app_instance = ConsoleApp(project_dir)
        restart = app_instance.run()
        if not restart:
            return

        # Full process re-exec ensures newly installed code is loaded.
        os.environ.pop("CLAWPWN_CONSOLE_ACTIVE", None)
        console_binary = which("clawpwn")
        if console_binary:
            os.execvp(console_binary, [console_binary, "console"])

        console.print(
            "[yellow]Could not re-exec 'clawpwn'; falling back to in-process restart.[/yellow]"
        )


@app.command(hidden=True)
def interactive() -> None:
    """Alias for 'console' command."""
    console_cmd()
