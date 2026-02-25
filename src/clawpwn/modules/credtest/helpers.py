"""Helper functions for credential form testing."""

from __future__ import annotations

import re

import httpx


def extract_attr(tag_html: str, attr_name: str) -> str | None:
    """Extract one HTML attribute value from a tag."""
    match = re.search(rf'{attr_name}=["\']([^"\']+)["\']', tag_html, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def extract_field_name(html: str, patterns: list[str]) -> str:
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


def extract_base_form_data(form_html: str) -> dict[str, str]:
    """Extract non-button input fields and default values from a form."""
    fields: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE):
        name = extract_attr(tag, "name")
        if not name:
            continue
        field_type = (extract_attr(tag, "type") or "text").lower()
        if field_type in {"submit", "button", "reset", "file", "image"}:
            continue
        value = extract_attr(tag, "value") or ""
        if name.lower() == "server" and not value:
            value = "1"
        fields[name] = value
    return fields


def is_login_successful(
    response: httpx.Response,
    password_field: str = "",
) -> bool:
    """Determine if login was successful based on response signals.

    Uses a multi-signal approach:
    1. Success indicators first (definitive when present)
    2. Specific failure *phrases* — single words like "error" cause false
       negatives on apps whose post-login pages contain that word
    3. Login-form re-presence: if the password field is still in the
       response the server re-rendered the login form
    4. Redirect fallback (non-empty history)
    """
    text_lower = response.text.lower()

    success_indicators = [
        "logout",
        "log out",
        "sign out",
        "sign off",
        "dashboard",
        "welcome",
        "my account",
        "profile",
        "settings",
        "control panel",
    ]
    if any(ind in text_lower for ind in success_indicators):
        return True

    failure_phrases = [
        "access denied",
        "login failed",
        "incorrect password",
        "invalid credentials",
        "invalid username",
        "invalid password",
        "invalid login",
        "authentication failed",
        "wrong password",
        "wrong credentials",
        "cannot log in",
        "unable to log in",
        "login error",
        "#1045",
        "#1044",
    ]
    if any(phrase in text_lower for phrase in failure_phrases):
        return False

    if password_field:
        pw_lower = password_field.lower()
        if f'name="{pw_lower}"' in text_lower or f"name='{pw_lower}'" in text_lower:
            return False

    return len(response.history) > 0
