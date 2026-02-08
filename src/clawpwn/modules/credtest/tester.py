"""Credential testing implementation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from .defaults import APP_SPECIFIC_CREDENTIALS, DEFAULT_CREDENTIALS


@dataclass
class CredTestResult:
    """Result of credential testing."""

    form_found: bool
    form_action: str
    credentials_tested: int
    valid_credentials: list[tuple[str, str]]
    details: list[str] = field(default_factory=list)
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

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            # Get the login page
            response = await client.get(url)
            html = response.text

            # Look for login form
            form_match = re.search(
                r"<form[^>]*>.*?</form>",
                html,
                re.DOTALL | re.IGNORECASE,
            )

            if not form_match:
                return CredTestResult(
                    form_found=False,
                    form_action="",
                    credentials_tested=0,
                    valid_credentials=[],
                    details=["No login form found on the page."],
                )

            form_found = True
            form_html = form_match.group(0)

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
            username_field = _extract_field_name(form_html, ["user", "login", "email"])
            password_field = _extract_field_name(form_html, ["pass", "pwd"])

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

            # Determine credentials to test
            if credentials:
                test_creds = credentials
            elif app_hint and app_hint.lower() in APP_SPECIFIC_CREDENTIALS:
                test_creds = APP_SPECIFIC_CREDENTIALS[app_hint.lower()]
                details.append(f"Using {len(test_creds)} app-specific credentials for {app_hint}")
            else:
                test_creds = DEFAULT_CREDENTIALS
                details.append(f"Using {len(test_creds)} common default credentials")

            # Test each credential pair
            for username, password in test_creds:
                credentials_tested += 1
                data = {
                    username_field: username,
                    password_field: password,
                }

                try:
                    login_response = await client.post(form_action, data=data)

                    # Check for success indicators
                    if _is_login_successful(login_response):
                        valid_credentials.append((username, password))
                        details.append(f"✓ Valid credentials found: {username}:{password}")
                except Exception as e:
                    details.append(f"Error testing {username}:{password} - {e}")

    except Exception as e:
        return CredTestResult(
            form_found=form_found,
            form_action=form_action,
            credentials_tested=credentials_tested,
            valid_credentials=valid_credentials,
            details=details,
            error=str(e),
        )

    return CredTestResult(
        form_found=form_found,
        form_action=form_action,
        credentials_tested=credentials_tested,
        valid_credentials=valid_credentials,
        details=details,
    )


def _extract_field_name(html: str, patterns: list[str]) -> str:
    """Extract input field name matching any of the patterns."""
    for pattern in patterns:
        match = re.search(
            rf'<input[^>]*name=["\']([^"\']*{pattern}[^"\']*)["\']',
            html,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)
    return ""


def _is_login_successful(response: httpx.Response) -> bool:
    """Determine if login was successful based on response."""
    # Check for common failure indicators
    failure_indicators = [
        "invalid",
        "incorrect",
        "failed",
        "error",
        "wrong",
        "denied",
    ]

    text_lower = response.text.lower()
    for indicator in failure_indicators:
        if indicator in text_lower:
            return False

    # Check for success indicators
    success_indicators = [
        "dashboard",
        "welcome",
        "logout",
        "profile",
        "settings",
    ]

    for indicator in success_indicators:
        if indicator in text_lower:
            return True

    # If redirected to a different page, likely successful
    if len(response.history) > 0:
        return True

    return False
