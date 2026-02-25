"""Stateful request context derivation for sqlmap."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin

import httpx


@dataclass
class SqlmapRequestContext:
    """Stateful request hints derived from target forms and session cookies."""

    action_url: str | None = None
    cookie_header: str | None = None
    post_data: str | None = None
    csrf_token: str | None = None

    @property
    def has_stateful_hints(self) -> bool:
        # Cookie-only context is too weak; require form-derived state.
        return bool(self.post_data or self.csrf_token)


async def derive_request_context(target: str) -> SqlmapRequestContext:
    """Fetch a target and infer form action, cookies, post body, and csrf token."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            response = await client.get(target)
            html = response.text
            cookie_header = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
            cookie_header = cookie_header or None
    except Exception:
        return SqlmapRequestContext()

    form_match = re.search(r"<form[^>]*>.*?</form>", html, re.DOTALL | re.IGNORECASE)
    if not form_match:
        return SqlmapRequestContext(cookie_header=cookie_header)

    form_html = form_match.group(0)
    action = extract_attr(form_html, "action")
    action_url = urljoin(str(response.url), action) if action else str(response.url)
    fields, csrf_token = extract_form_fields(form_html)
    post_data = urlencode(fields) if fields else None
    return SqlmapRequestContext(
        action_url=action_url,
        cookie_header=cookie_header,
        post_data=post_data,
        csrf_token=csrf_token,
    )


def extract_form_fields(form_html: str) -> tuple[dict[str, str], str | None]:
    """Extract input fields and return (field_map, csrf_field_name)."""
    fields: dict[str, str] = {}
    csrf_token: str | None = None
    input_tags = re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE)
    for tag in input_tags:
        name = extract_attr(tag, "name")
        if not name:
            continue
        field_type = (extract_attr(tag, "type") or "text").lower()
        if field_type in {"submit", "button", "reset", "file", "image"}:
            continue

        value = extract_attr(tag, "value") or ""
        name_lower = name.lower()
        if not value and field_type in {"text", "email", "password"}:
            value = "test"
        fields[name] = value
        if csrf_token is None and ("csrf" in name_lower or "token" in name_lower):
            csrf_token = name

    return fields, csrf_token


def extract_attr(html: str, attr_name: str) -> str | None:
    """Extract a quoted HTML attribute value."""
    match = re.search(rf'{attr_name}=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None
