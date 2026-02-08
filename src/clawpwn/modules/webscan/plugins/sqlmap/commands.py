"""sqlmap command construction helpers."""

from __future__ import annotations

from .context import SqlmapRequestContext


def build_command(binary: str, target: str, depth: str, tmpdir: str) -> list[str]:
    """Build the default sqlmap command for a target."""
    command = [
        binary,
        "-u",
        target,
        "--batch",
        "--output-dir",
        tmpdir,
        "--forms",
        "--crawl=1",
    ]
    apply_depth_flags(command, depth)
    return command


def build_stateful_command(
    binary: str,
    target: str,
    depth: str,
    tmpdir: str,
    request_context: SqlmapRequestContext,
) -> list[str]:
    """Build a stateful sqlmap command using POST/cookies/CSRF hints."""
    command = [
        binary,
        "-u",
        request_context.action_url or target,
        "--batch",
        "--output-dir",
        tmpdir,
        "--method",
        "POST",
    ]

    if request_context.post_data:
        command.extend(["--data", request_context.post_data])
    else:
        command.extend(["--forms", "--crawl=1"])

    if request_context.cookie_header:
        command.extend(["--cookie", request_context.cookie_header])
    if request_context.csrf_token:
        command.extend(["--csrf-token", request_context.csrf_token])
        command.extend(["--csrf-url", request_context.action_url or target])

    apply_depth_flags(command, depth)
    return command


def apply_depth_flags(command: list[str], depth: str) -> None:
    """Apply depth-specific sqlmap flags."""
    if depth == "quick":
        command.extend(["--level=1", "--risk=1"])
    elif depth == "deep":
        command.extend(["--level=5", "--risk=3", "--technique=BEUSTQ"])
    else:
        command.extend(["--level=3", "--risk=2"])
