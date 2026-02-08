"""Executors for attack and exploitation tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


def execute_credential_test(params: dict[str, Any], _project_dir: Path) -> str:
    """Execute credential testing and format results."""
    target = params.get("target", "")
    credentials = params.get("credentials")
    app_hint = params.get("app_hint")

    if not target:
        return "Error: target parameter is required."

    # Convert credentials format if provided
    creds_list = None
    if credentials:
        creds_list = [(cred[0], cred[1]) for cred in credentials if len(cred) == 2]

    from clawpwn.modules.credtest import test_credentials

    result = safe_async_run(test_credentials(target, creds_list, app_hint))

    output = [f"Credential testing results for {target}:\n"]

    if not result.form_found:
        output.append("No login form found on the target page.")
        return "\n".join(output)

    output.append(f"Login form found: {result.form_action}")
    output.append(f"Credentials tested: {result.credentials_tested}")

    if result.valid_credentials:
        output.append(f"\n✓ VALID CREDENTIALS FOUND ({len(result.valid_credentials)}):")
        for username, password in result.valid_credentials:
            output.append(f"  • {username}:{password}")
    else:
        output.append("\nNo valid credentials found.")

    if result.details:
        output.append("\nDetails:")
        for detail in result.details:
            output.append(f"  {detail}")

    if result.error:
        output.append(f"\nError: {result.error}")

    return "\n".join(output)


def execute_run_custom_script(params: dict[str, Any], project_dir: Path) -> str:
    """Execute custom Python script and return results."""
    script = params.get("script", "")
    description = params.get("description", "Custom script")
    timeout = params.get("timeout", 30)

    if not script:
        return "Error: script parameter is required."

    from clawpwn.tools.sandbox import run_sandboxed_script

    result = safe_async_run(run_sandboxed_script(script, timeout, project_dir))

    output = [f"Custom script execution: {description}\n"]

    if result.exit_code == 0:
        output.append("✓ Script completed successfully")
    else:
        output.append(f"✗ Script exited with code {result.exit_code}")

    output.append(f"\nScript saved to: {result.script_path}")

    if result.stdout:
        output.append(f"\n--- STDOUT ---\n{result.stdout}")

    if result.stderr:
        output.append(f"\n--- STDERR ---\n{result.stderr}")

    if result.error:
        output.append(f"\nError: {result.error}")

    return "\n".join(output)
