"""Login form extraction helpers for credential testing."""

from __future__ import annotations

import re
from urllib.parse import urljoin


def select_login_form(html: str) -> str | None:
    """Return a login form, preferring one with a password field."""
    forms = re.findall(r"<form[^>]*>.*?</form>", html, re.DOTALL | re.IGNORECASE)
    for candidate in forms:
        if re.search(r'type=["\']password["\']', candidate, re.IGNORECASE):
            return candidate
    return forms[0] if forms else None


def resolve_form_action(url: str, form_html: str) -> str:
    """Resolve form action to an absolute URL."""
    action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
    if not action_match:
        return url

    action = action_match.group(1)
    if action.startswith("http"):
        return action
    return urljoin(url, action)
