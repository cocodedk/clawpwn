"""Credential testing workflow."""

from __future__ import annotations

import httpx

from clawpwn.modules.attack_feedback import (
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)

from ..candidates import build_credential_candidates
from ..helpers import extract_base_form_data, extract_field_name, is_login_successful
from .form import resolve_form_action, select_login_form
from .result import CredTestResult


async def test_credentials(
    url: str,
    credentials: list[tuple[str, str]] | None = None,
    app_hint: str | None = None,
) -> CredTestResult:
    """Test credentials against a login form."""
    valid_credentials: list[tuple[str, str]] = []
    details: list[str] = []
    form_found = False
    form_action = ""
    credentials_tested = 0
    hints: list[str] = []
    block_signals: list[str] = []
    policy_action = "continue"
    stopped_early = False
    block_streak = 0

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url)
            form_html = select_login_form(response.text)
            if not form_html:
                return CredTestResult(
                    form_found=False,
                    form_action="",
                    credentials_tested=0,
                    valid_credentials=[],
                    details=["No login form found on the page."],
                )

            form_found = True
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

            details.append(f"Form action: {form_action}")
            details.append(f"Username field: {username_field}, Password field: {password_field}")

            test_creds, strategy = build_credential_candidates(credentials, app_hint)
            details.append(
                f"Credential strategy: {strategy} ({len(test_creds)} candidates, capped)"
            )

            for username, password in test_creds:
                credentials_tested += 1
                data = {
                    **base_form_data,
                    username_field: username,
                    password_field: password,
                }

                try:
                    login_response = await client.post(form_action, data=data)
                    signals = extract_attack_signals(
                        login_response.text,
                        status_code=login_response.status_code,
                        headers=login_response.headers,
                    )

                    hint_messages = summarize_signals(signals, "hint", limit=2)
                    for message in hint_messages:
                        if message not in hints:
                            hints.append(message)
                            details.append(f"Hint observed ({username}): {message}")

                    block_messages = summarize_signals(signals, "block", limit=2)
                    if block_messages:
                        block_streak += 1
                        for message in block_messages:
                            if message not in block_signals:
                                block_signals.append(message)
                            details.append(f"Block signal ({username}): {message}")
                    else:
                        block_streak = 0

                    decision = decide_attack_policy(signals, block_streak=block_streak)
                    if decision.action != "continue":
                        policy_action = decision.action
                        details.append(f"Policy action: {decision.action} ({decision.reason})")
                    if decision.action == "stop_and_replan":
                        stopped_early = True
                        break

                    if is_login_successful(login_response, password_field):
                        valid_credentials.append((username, password))
                        details.append(f"✓ Valid credentials found: {username}:{password}")
                except Exception as exc:
                    details.append(f"Error testing {username}:{password} - {exc}")
                    signals = extract_attack_signals(str(exc))
                    decision = decide_attack_policy(signals, block_streak=block_streak + 1)
                    if decision.action == "stop_and_replan":
                        policy_action = decision.action
                        stopped_early = True
                        details.append(f"Policy action: {decision.action} ({decision.reason})")
                        break

    except Exception as exc:
        return CredTestResult(
            form_found=form_found,
            form_action=form_action,
            credentials_tested=credentials_tested,
            valid_credentials=valid_credentials,
            details=details,
            hints=hints,
            block_signals=block_signals,
            policy_action=policy_action,
            stopped_early=stopped_early,
            error=str(exc),
        )

    return CredTestResult(
        form_found=form_found,
        form_action=form_action,
        credentials_tested=credentials_tested,
        valid_credentials=valid_credentials,
        details=details,
        hints=hints,
        block_signals=block_signals,
        policy_action=policy_action,
        stopped_early=stopped_early,
    )
