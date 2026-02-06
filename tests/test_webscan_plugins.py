"""Tests for external web scanner plugin adapters."""

import json
from pathlib import Path

import pytest

from clawpwn.modules.webscan import WebScanConfig
from clawpwn.modules.webscan.plugins.feroxbuster import FeroxbusterWebScannerPlugin
from clawpwn.modules.webscan.plugins.ffuf import FFUFWebScannerPlugin
from clawpwn.modules.webscan.plugins.nikto import NiktoWebScannerPlugin
from clawpwn.modules.webscan.plugins.nuclei import NucleiWebScannerPlugin
from clawpwn.modules.webscan.plugins.zap import ZAPWebScannerPlugin
from clawpwn.modules.webscan.runtime import CommandResult


@pytest.mark.asyncio
async def test_nuclei_plugin_parses_jsonl(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = json.dumps(
        {
            "template-id": "test-id",
            "matched-at": "https://example.com/login",
            "matcher-name": "body-word",
            "info": {
                "name": "Test Finding",
                "severity": "high",
                "description": "Detected issue",
            },
        }
    )

    async def fake_runner(*args, **kwargs):
        return CommandResult(
            command=["nuclei"],
            returncode=0,
            stdout=sample + "\n",
            stderr="",
        )

    monkeypatch.setattr(
        "clawpwn.modules.webscan.plugins.nuclei.resolve_binary", lambda _: "/bin/nuclei"
    )
    plugin = NucleiWebScannerPlugin(command_runner=fake_runner)

    findings = await plugin.scan("https://example.com", WebScanConfig())

    assert len(findings) == 1
    assert findings[0].title == "Test Finding"
    assert findings[0].severity == "high"


@pytest.mark.asyncio
async def test_ffuf_plugin_parses_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_runner(command, **kwargs):
        out_idx = command.index("-o") + 1
        out_file = Path(command[out_idx])
        out_file.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.com/admin",
                            "status": 200,
                            "length": 1234,
                            "input": {"FUZZ": "admin"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return CommandResult(command=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "clawpwn.modules.webscan.plugins.ffuf.resolve_binary", lambda _: "/bin/ffuf"
    )
    plugin = FFUFWebScannerPlugin(command_runner=fake_runner)

    findings = await plugin.scan("https://example.com", WebScanConfig(depth="quick"))

    assert len(findings) == 1
    assert "Discovered endpoint" in findings[0].title
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_feroxbuster_plugin_parses_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_runner(command, **kwargs):
        out_idx = command.index("-o") + 1
        out_file = Path(command[out_idx])
        out_file.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "url": "https://example.com/admin",
                            "status": 200,
                            "method": "GET",
                            "content_length": 512,
                        }
                    ),
                    json.dumps(
                        {
                            "response": {
                                "url": "https://example.com/private",
                                "status": 403,
                                "method": "GET",
                            }
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return CommandResult(command=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "clawpwn.modules.webscan.plugins.feroxbuster.resolve_binary",
        lambda _: "/bin/feroxbuster",
    )
    plugin = FeroxbusterWebScannerPlugin(command_runner=fake_runner)

    findings = await plugin.scan("https://example.com", WebScanConfig(depth="quick"))

    assert len(findings) == 2
    assert findings[0].tool == "feroxbuster"
    assert "Discovered endpoint" in findings[0].title
    assert {f.severity for f in findings} >= {"medium", "low"}


@pytest.mark.asyncio
async def test_nikto_plugin_parses_issue_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    output = """
+ Target IP: 1.1.1.1
+ /admin/: Admin panel discovered.
+ /old.php: vulnerable component references CVE-2020-1234.
"""

    async def fake_runner(*args, **kwargs):
        return CommandResult(command=["nikto"], returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(
        "clawpwn.modules.webscan.plugins.nikto.resolve_binary", lambda _: "/bin/nikto"
    )
    plugin = NiktoWebScannerPlugin(command_runner=fake_runner)

    findings = await plugin.scan("https://example.com", WebScanConfig())

    assert len(findings) == 2
    assert any(f.severity == "high" for f in findings)


def test_zap_plugin_parses_alert_json(tmp_path: Path) -> None:
    out_file = tmp_path / "zap.json"
    out_file.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "https://example.com",
                        "alerts": [
                            {
                                "name": "Missing Header",
                                "riskcode": "2",
                                "desc": "Header absent",
                                "instances": [{"uri": "https://example.com", "method": "GET"}],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    plugin = ZAPWebScannerPlugin(command_runner=None)
    findings = plugin._parse_output(out_file)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].title == "Missing Header"
