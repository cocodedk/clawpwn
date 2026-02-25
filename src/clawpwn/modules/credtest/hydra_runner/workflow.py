"""Hydra credential testing workflow."""

from __future__ import annotations

import tempfile
from pathlib import Path
from shutil import which
from urllib.parse import urlencode, urlparse

import httpx

from ..candidates import build_credential_candidates
from ..helpers import extract_base_form_data, extract_field_name
from ..hydra_helpers import (
    escape_hydra_segment,
    extract_valid_credentials,
    filter_hydra_compatible_pairs,
    find_login_form,
    hydra_failure_condition,
    resolve_form_action,
)
from ..tester import CredTestResult
from .process import run_hydra_command


async def test_credentials_with_hydra(
    url: str,
    credentials: list[tuple[str, str]] | None = None,
    app_hint: str | None = None,
) -> CredTestResult:
    """Test credentials using hydra against an HTTP(S) login form."""
    details: list[str] = []
    hydra_bin = which("hydra")
    if not hydra_bin:
        return CredTestResult(
            form_found=False,
            form_action="",
            credentials_tested=0,
            valid_credentials=[],
            details=details,
            error="hydra binary not found in PATH (install with: sudo apt install hydra)",
        )

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
        except Exception as exc:
            return CredTestResult(
                form_found=False,
                form_action="",
                credentials_tested=0,
                valid_credentials=[],
                details=details,
                error=str(exc),
            )

    html = response.text
    form_html = find_login_form(html)
    if not form_html:
        return CredTestResult(
            form_found=False,
            form_action="",
            credentials_tested=0,
            valid_credentials=[],
            details=["No login form found on the page."],
        )

    form_action = resolve_form_action(url, form_html)
    username_field = extract_field_name(form_html, ["user", "login", "email"])
    password_field = extract_field_name(form_html, ["pass", "pwd"])
    base_form_data = extract_base_form_data(form_html)

    if not username_field or not password_field:
        return CredTestResult(
            form_found=True,
            form_action=form_action,
            credentials_tested=0,
            valid_credentials=[],
            details=[
                "Could not identify login fields. "
                f"Found username field: {username_field}, password field: {password_field}"
            ],
        )

    test_creds, strategy = build_credential_candidates(credentials, app_hint)
    details.append(f"Form action: {form_action}")
    details.append(f"Username field: {username_field}, Password field: {password_field}")
    details.append(f"Credential strategy: {strategy} ({len(test_creds)} candidates, capped)")

    hydra_creds, skipped = filter_hydra_compatible_pairs(test_creds)
    if skipped:
        details.append(f"Skipped {skipped} candidate(s) not compatible with hydra -C format.")
    if not hydra_creds:
        return CredTestResult(
            form_found=True,
            form_action=form_action,
            credentials_tested=0,
            valid_credentials=[],
            details=details,
            error="No hydra-compatible credential pairs available to test.",
        )

    parsed = urlparse(form_action)
    if not parsed.hostname:
        return CredTestResult(
            form_found=True,
            form_action=form_action,
            credentials_tested=0,
            valid_credentials=[],
            details=details,
            error=f"Unable to parse target host from form action: {form_action}",
        )

    is_https = parsed.scheme.lower() == "https"
    module = "https-post-form" if is_https else "http-post-form"
    port = parsed.port or (443 if is_https else 80)
    form_path = parsed.path or "/"
    if parsed.query:
        form_path = f"{form_path}?{parsed.query}"

    request_data = {**base_form_data, username_field: "^USER^", password_field: "^PASS^"}
    payload = urlencode(request_data, safe="^")
    failure_cond = hydra_failure_condition(html)
    service_spec = (
        f"{escape_hydra_segment(form_path)}:{escape_hydra_segment(payload)}:"
        f"{escape_hydra_segment(failure_cond)}"
    )

    with tempfile.TemporaryDirectory(prefix="clawpwn-hydra-") as tmpdir:
        combo_path = Path(tmpdir) / "credentials.txt"
        output_path = Path(tmpdir) / "hydra.out"
        combo_path.write_text(
            "\n".join(f"{user}:{password}" for user, password in hydra_creds) + "\n",
            encoding="utf-8",
        )

        command = [
            hydra_bin,
            "-I",
            "-C",
            str(combo_path),
            "-s",
            str(port),
            "-f",
            "-t",
            "4",
            "-o",
            str(output_path),
            parsed.hostname,
            module,
            service_spec,
        ]
        details.append(f"Hydra module: {module}")
        details.append(f"Hydra target: {parsed.hostname}:{port}{form_path}")
        details.append(f"Hydra failure condition: {failure_cond}")

        execution = await run_hydra_command(command, output_path, timeout=180.0)
        if execution.timed_out:
            return CredTestResult(
                form_found=True,
                form_action=form_action,
                credentials_tested=len(hydra_creds),
                valid_credentials=[],
                details=details,
                error="hydra timed out after 180 seconds.",
            )

        valid_credentials = extract_valid_credentials(execution.combined_output)
        details.append(f"Hydra exit code: {execution.returncode}")

        error: str | None = None
        if execution.returncode not in {0} and not valid_credentials:
            first_error = (
                execution.stderr.strip().splitlines()
                or execution.stdout.strip().splitlines()
                or [""]
            )[0]
            error = first_error or f"hydra failed with exit code {execution.returncode}"

    return CredTestResult(
        form_found=True,
        form_action=form_action,
        credentials_tested=len(hydra_creds),
        valid_credentials=valid_credentials,
        details=details,
        error=error,
    )
