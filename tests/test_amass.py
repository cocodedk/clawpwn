"""Tests for OWASP Amass subdomain enumeration."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from clawpwn.modules.recon.amass_models import AmassConfig, SubdomainResult
from clawpwn.modules.recon.amass_runner import _parse_output, run_amass

# -- Model tests --


def test_amass_config_defaults():
    config = AmassConfig()
    assert config.mode == "passive"
    assert config.timeout == 300
    assert config.verbose is False
    assert config.max_dns_queries == 0


def test_subdomain_result_fields():
    result = SubdomainResult(
        name="sub.example.com",
        domain="example.com",
        addresses=["1.2.3.4"],
        tag="cert",
        sources=["CertSpotter"],
    )
    assert result.name == "sub.example.com"
    assert result.domain == "example.com"
    assert result.addresses == ["1.2.3.4"]
    assert result.tag == "cert"
    assert result.sources == ["CertSpotter"]
    assert result.raw == {}


# -- Parser tests --

SAMPLE_JSONL = [
    {
        "name": "api.example.com",
        "domain": "example.com",
        "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24"}],
        "tag": "cert",
        "sources": ["CertSpotter"],
    },
    {
        "name": "mail.example.com",
        "domain": "example.com",
        "addresses": [{"ip": "5.6.7.8"}],
        "tag": "dns",
        "sources": ["DNS"],
    },
]


def test_parse_valid_jsonl(tmp_path):
    out_file = tmp_path / "amass.jsonl"
    out_file.write_text("\n".join(json.dumps(obj) for obj in SAMPLE_JSONL))

    results = _parse_output(out_file)
    assert len(results) == 2
    assert results[0].name == "api.example.com"
    assert results[0].addresses == ["1.2.3.4"]
    assert results[1].name == "mail.example.com"
    assert results[1].tag == "dns"


def test_parse_empty_output(tmp_path):
    out_file = tmp_path / "amass.jsonl"
    out_file.write_text("")
    assert _parse_output(out_file) == []


def test_parse_missing_file(tmp_path):
    out_file = tmp_path / "nonexistent.jsonl"
    assert _parse_output(out_file) == []


def test_parse_deduplicates_by_name(tmp_path):
    duped = [SAMPLE_JSONL[0], SAMPLE_JSONL[0]]
    out_file = tmp_path / "amass.jsonl"
    out_file.write_text("\n".join(json.dumps(obj) for obj in duped))

    results = _parse_output(out_file)
    assert len(results) == 1


def test_parse_skips_invalid_json(tmp_path):
    out_file = tmp_path / "amass.jsonl"
    out_file.write_text("not json\n" + json.dumps(SAMPLE_JSONL[0]))

    results = _parse_output(out_file)
    assert len(results) == 1
    assert results[0].name == "api.example.com"


# -- Runner tests --


@pytest.mark.asyncio
async def test_run_amass_binary_missing():
    with patch("clawpwn.modules.recon.amass_runner.resolve_binary", return_value=None):
        with pytest.raises(RuntimeError, match="amass binary not found"):
            await run_amass("example.com")


@pytest.mark.asyncio
async def test_run_amass_success():
    jsonl_content = "\n".join(json.dumps(obj) for obj in SAMPLE_JSONL)

    async def fake_run_command(command, *, timeout=None, allowed_exit_codes=(0,), verbose=False):
        json_idx = command.index("-json")
        out_path = Path(command[json_idx + 1])
        out_path.write_text(jsonl_content)

    with (
        patch(
            "clawpwn.modules.recon.amass_runner.resolve_binary",
            return_value="/usr/bin/amass",
        ),
        patch(
            "clawpwn.modules.recon.amass_runner.run_command",
            side_effect=fake_run_command,
        ),
    ):
        results = await run_amass("example.com")
        assert len(results) == 2
        assert results[0].name == "api.example.com"
