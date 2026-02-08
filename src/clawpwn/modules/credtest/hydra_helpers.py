"""Helpers for hydra-backed credential testing."""

from __future__ import annotations

import re
from urllib.parse import urljoin

_FORM_REGEX = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
_ACTION_REGEX = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
_HYDRA_HIT_REGEX = re.compile(r"login:\s*(\S+)\s+password:\s*(\S*)", re.IGNORECASE)
_FAILURE_PHRASES = (
    "access denied",
    "login failed",
    "incorrect password",
    "invalid credentials",
    "invalid login",
    "invalid password",
    "invalid username",
    "authentication failed",
    "wrong password",
    "unauthorized",
    "forbidden",
    "#1045",
)


def find_login_form(html: str) -> str | None:
    """Find a login form, preferring the one with a password field."""
    forms = _FORM_REGEX.findall(html)
    for form in forms:
        if re.search(r'type=["\']password["\']', form, re.IGNORECASE):
            return form
    return forms[0] if forms else None


def resolve_form_action(url: str, form_html: str) -> str:
    action_match = _ACTION_REGEX.search(form_html)
    if not action_match:
        return url
    action = action_match.group(1)
    if action.startswith("http://") or action.startswith("https://"):
        return action
    return urljoin(url, action)


def hydra_failure_condition(page_html: str) -> str:
    """Build a hydra failure condition from the login page content.

    Uses specific authentication-failure phrases rather than generic words
    like "error" which appear on many legitimate post-login pages.
    """
    html_lower = page_html.lower()
    for phrase in _FAILURE_PHRASES:
        if phrase in html_lower:
            return f"F={phrase}"
    return "F=invalid"


def escape_hydra_segment(value: str) -> str:
    """Escape separators used by hydra's target descriptor syntax."""
    return value.replace("\\", "\\\\").replace(":", "\\:")


def extract_valid_credentials(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        match = _HYDRA_HIT_REGEX.search(line)
        if not match:
            continue
        pair = (match.group(1), match.group(2))
        if pair in seen:
            continue
        seen.add(pair)
        found.append(pair)
    return found


def filter_hydra_compatible_pairs(
    credentials: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], int]:
    compatible: list[tuple[str, str]] = []
    skipped = 0
    for username, password in credentials:
        if ":" in username or ":" in password:
            skipped += 1
            continue
        if "\n" in username or "\n" in password:
            skipped += 1
            continue
        compatible.append((username, password))
    return compatible, skipped
