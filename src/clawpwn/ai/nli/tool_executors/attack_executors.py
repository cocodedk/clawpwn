"""Executors for attack and exploitation tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


def _hydra_troubleshooting_notes() -> list[str]:
    """Common reasons hydra misses valid web form credentials."""
    return [
        "Dynamic CSRF/session tokens can invalidate static hydra form payloads.",
        "Success/failure match strings may be too broad or incorrect for the target app.",
        "Hidden fields, redirects, or multi-step login flows may not be fully modeled.",
        "Rate limiting, lockouts, CAPTCHA, or WAF behavior can cause false negatives.",
        "Use builtin form testing as a cross-check when hydra reports no hits.",
    ]


def execute_credential_test(params: dict[str, Any], _project_dir: Path) -> str:
    """Execute credential testing and format results."""
    target = params.get("target", "")
    credentials = params.get("credentials")
    app_hint = params.get("app_hint")
    selected_tool = str(params.get("tool", "builtin")).strip().lower()

    if not target:
        return "Error: target parameter is required."
    if selected_tool not in {"builtin", "hydra"}:
        return "Error: tool must be one of: builtin, hydra."

    # Convert credentials format if provided
    creds_list = None
    if credentials:
        creds_list = [(cred[0], cred[1]) for cred in credentials if len(cred) == 2]

    from clawpwn.modules.credtest import test_credentials, test_credentials_with_hydra

    fallback_result = None
    if selected_tool == "hydra":
        result = safe_async_run(test_credentials_with_hydra(target, creds_list, app_hint))
        # Hydra can miss valid creds on dynamic forms; always cross-check failures/errors.
        if result.error or not result.valid_credentials:
            fallback_result = safe_async_run(test_credentials(target, creds_list, app_hint))
    else:
        result = safe_async_run(test_credentials(target, creds_list, app_hint))

    output = [f"Credential testing results for {target}:\n"]
    output.append(f"Tool: {selected_tool}")

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
        if selected_tool == "hydra":
            output.append("Hydra may miss dynamic web login forms.")

    if fallback_result is not None:
        output.append("\nHydra vs builtin cross-check:")
        output.append(
            f"  builtin tested {fallback_result.credentials_tested} credential pairs "
            f"and found {len(fallback_result.valid_credentials)} valid."
        )
        if fallback_result.valid_credentials:
            output.append("  Builtin detected valid credentials that hydra missed:")
            for username, password in fallback_result.valid_credentials:
                output.append(f"    • {username}:{password}")
            output.append("  Likely cause: target login workflow requires dynamic form handling.")
        else:
            output.append("  Builtin also found no valid credentials.")

        output.append("  Troubleshooting notes:")
        for note in _hydra_troubleshooting_notes():
            output.append(f"    • {note}")

    if result.details:
        output.append("\nDetails:")
        for detail in result.details:
            output.append(f"  {detail}")

    if result.hints:
        output.append("\nResponse hints:")
        for hint in result.hints:
            output.append(f"  • {hint}")

    if result.block_signals:
        output.append("\nBlocking signals:")
        for signal in result.block_signals:
            output.append(f"  • {signal}")

    if result.policy_action != "continue":
        output.append(f"\nPolicy action: {result.policy_action}")
    if result.stopped_early:
        output.append("Stopped early due to target defense signals.")

    if result.error:
        output.append(f"\nError: {result.error}")

    return "\n".join(output)


def _build_validation_note(stdout: str, stderr: str) -> str:
    """Return confidence guidance for potentially ambiguous exploit output."""
    text = f"{stdout}\n{stderr}".lower()
    markers = ("302", "redirect", "bypass", "sql injection", "sqli", "potential")
    if any(marker in text for marker in markers):
        return (
            "Heuristic indicators are not proof of exploitation by themselves. "
            "Confirm with post-auth behavior or extracted data before marking as confirmed."
        )
    return ""


def execute_run_custom_script(params: dict[str, Any], project_dir: Path) -> str:
    """Execute custom Python script and return results."""
    script = params.get("script", "")
    description = params.get("description", "Custom script")
    timeout = params.get("timeout", 30)
    user_approved = bool(params.get("user_approved", False))

    if not script:
        return "Error: script parameter is required."
    if not user_approved:
        return (
            "Approval required: custom script execution is blocked until the user explicitly "
            "approves it. Ask: 'Allow creating/running this script? (yes/no)' and retry with "
            "user_approved=true only if the user says yes."
        )

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

    validation_note = _build_validation_note(result.stdout, result.stderr)
    if validation_note:
        output.append(f"\nValidation note: {validation_note}")

    return "\n".join(output)
