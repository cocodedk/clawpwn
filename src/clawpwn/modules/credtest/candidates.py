"""Credential candidate generation strategies."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .defaults import APP_SPECIFIC_CREDENTIALS, DEFAULT_CREDENTIALS

_GENERIC_USERNAMES: tuple[str, ...] = (
    "root",
    "admin",
    "administrator",
    "user",
    "test",
    "guest",
)
_GENERIC_PASSWORDS: tuple[str, ...] = (
    "",
    "password",
    "admin",
    "123456",
    "12345",
    "toor",
    "root",
    "test",
    "guest",
    "changeme",
    "welcome",
    "letmein",
    "qwerty",
)


def build_credential_candidates(
    explicit_credentials: list[tuple[str, str]] | None,
    app_hint: str | None,
    max_candidates: int = 40,
) -> tuple[list[tuple[str, str]], str]:
    """Build ordered, deduplicated credential candidates for login testing."""
    if explicit_credentials:
        return explicit_credentials[:max_candidates], "explicit credentials"

    candidates: list[tuple[str, str]] = []
    strategy_parts: list[str] = []

    app_key = (app_hint or "").strip().lower()
    if app_key and app_key in APP_SPECIFIC_CREDENTIALS:
        candidates.extend(APP_SPECIFIC_CREDENTIALS[app_key])
        strategy_parts.append("app defaults")

    candidates.extend(DEFAULT_CREDENTIALS)
    strategy_parts.append("common defaults")

    usernames = [u for u, _ in candidates] + list(_GENERIC_USERNAMES)
    passwords = [p for _, p in candidates] + list(_GENERIC_PASSWORDS)
    if app_key:
        compact_hint = re.sub(r"[^a-z0-9]", "", app_key)
        passwords.extend([app_key, compact_hint])

    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str]] = []

    def _append_pair(username: str, password: str) -> None:
        pair = (username, password)
        if pair in seen:
            return
        seen.add(pair)
        deduped.append(pair)

    for username, password in candidates:
        _append_pair(username, password)

    wordlist_passwords = _load_wordlist_passwords(limit=30)
    for password in wordlist_passwords:
        _append_pair("root", password)
        _append_pair("admin", password)
        if len(deduped) >= max_candidates:
            break
    if wordlist_passwords:
        strategy_parts.append("wordlist expansion")

    if len(deduped) < max_candidates:
        usernames = _dedupe_values(usernames)[:8]
        passwords = _dedupe_values(passwords)[:18]
        for username in usernames:
            _append_pair(username, username)
            for password in passwords:
                _append_pair(username, password)
                if len(deduped) >= max_candidates:
                    break
            if len(deduped) >= max_candidates:
                break
        strategy_parts.append("generic combinations")

    return deduped[:max_candidates], ", ".join(strategy_parts)


def _dedupe_values(values: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


def _load_wordlist_passwords(limit: int) -> list[str]:
    env_path = os.getenv("CLAWPWN_CRED_WORDLIST", "").strip()
    path = Path(env_path) if env_path else Path("/usr/share/wordlists/rockyou.txt")
    if not path.exists():
        return []

    passwords: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                password = line.strip()
                if not password or len(password) > 64:
                    continue
                passwords.append(password)
                if len(passwords) >= limit:
                    break
    except OSError:
        return []
    return passwords
