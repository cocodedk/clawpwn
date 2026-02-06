"""Capability sync tests to keep CLI, console, and NLI in sync."""

from __future__ import annotations

import re
from pathlib import Path

from clawpwn.console.completer import CommandCompleter
from clawpwn.console.router import InputRouter


def _extract_cli_commands(cli_path: Path) -> set[str]:
    """Parse src/clawpwn/cli.py decorators to extract CLI command names."""
    command_re = re.compile(r"^\s*@app\.command(?:\((.*)\))?\s*$")
    def_re = re.compile(r"^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")

    commands: set[str] = set()
    pending_default = 0

    for line in cli_path.read_text().splitlines():
        match = command_re.match(line)
        if match:
            args = (match.group(1) or "").strip()
            if not args:
                pending_default += 1
                continue
            name_match = re.search(r"name\s*=\s*['\"]([a-zA-Z0-9_-]+)['\"]", args)
            if name_match:
                commands.add(name_match.group(1))
                continue
            first_str = re.match(r"\s*['\"]([a-zA-Z0-9_-]+)['\"]", args)
            if first_str:
                commands.add(first_str.group(1))
                continue
            pending_default += 1
            continue

        def_match = def_re.match(line)
        if def_match and pending_default:
            func_name = def_match.group(1)
            commands.add(func_name.replace("_", "-"))
            pending_default = 0

    return commands


def test_cli_commands_synced_to_console_router_and_completer():
    cli_path = Path(__file__).resolve().parents[1] / "src" / "clawpwn" / "cli.py"
    cli_commands = _extract_cli_commands(cli_path)
    router_commands = set(InputRouter.CLI_COMMANDS)
    completer_commands = set(CommandCompleter.COMMANDS.keys())

    missing_router = sorted(cli_commands - router_commands)
    missing_completer = sorted(cli_commands - completer_commands)

    assert not missing_router, f"Add to InputRouter.CLI_COMMANDS: {missing_router}"
    assert not missing_completer, f"Add to CommandCompleter.COMMANDS: {missing_completer}"
