"""Tests for scan CLI helpers."""

import pytest

from clawpwn.cli_commands.scan_helpers import parse_web_tools


def test_parse_web_tools_defaults_to_builtin() -> None:
    assert parse_web_tools(None) == ["builtin"]
    assert parse_web_tools("") == ["builtin"]


def test_parse_web_tools_all_keyword() -> None:
    assert parse_web_tools("all") == [
        "builtin",
        "nuclei",
        "feroxbuster",
        "ffuf",
        "nikto",
        "searchsploit",
        "zap",
    ]


def test_parse_web_tools_aliases_and_dedupe() -> None:
    tools = parse_web_tools("default,owasp-zap,zap-baseline,dirbuster,nuclei")
    assert tools == ["builtin", "zap", "feroxbuster", "nuclei"]


def test_parse_web_tools_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown web scanner tool"):
        parse_web_tools("builtin,unknown")
