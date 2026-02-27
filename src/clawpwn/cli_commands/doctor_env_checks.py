"""Environment and project health checks for ``clawpwn doctor``."""

from __future__ import annotations

from pathlib import Path

from .doctor_checks import CheckResult, mask_key


def check_llm_provider(project_dir: Path | None) -> CheckResult:
    """Check that an LLM provider is configured."""
    from clawpwn.config.getters import get_llm_provider

    provider = get_llm_provider(project_dir)
    if provider:
        return CheckResult("LLM provider", "pass", f"LLM provider: {provider}")
    return CheckResult(
        "LLM provider",
        "fail",
        "No LLM provider configured",
        fix="Set CLAWPWN_LLM_PROVIDER in env or .clawpwn/.env",
    )


def check_api_key(project_dir: Path | None) -> CheckResult:
    """Check that an API key is present for the configured provider."""
    from clawpwn.config.getters import get_api_key, get_llm_provider

    provider = get_llm_provider(project_dir)
    key = get_api_key(provider, project_dir)
    if key:
        masked = mask_key(key)
        return CheckResult("API key", "pass", f"API key: {masked}")
    return CheckResult(
        "API key",
        "fail",
        f"No API key found for provider '{provider}'",
        fix="Set CLAWPWN_LLM_API_KEY or provider-specific key in env",
    )


def check_api_key_valid(project_dir: Path | None) -> CheckResult:
    """Lightweight API call to verify the key works."""
    from clawpwn.config.getters import get_api_key, get_llm_model, get_llm_provider

    provider = get_llm_provider(project_dir)
    key = get_api_key(provider, project_dir)
    if not key:
        return CheckResult("API key valid", "warn", "Skipped (no API key)")

    try:
        from clawpwn.ai.llm import LLMClient

        model = get_llm_model(project_dir)
        client = LLMClient(provider=provider, api_key=key, model=model)
        client.chat("ping")
        display_model = model or provider
        return CheckResult("API key valid", "pass", f"API key valid ({display_model})")
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "auth" in msg.lower() or "401" in msg or "invalid" in msg.lower():
            return CheckResult("API key valid", "fail", "API key rejected", fix="Check your key")
        return CheckResult("API key valid", "warn", f"Could not verify: {msg[:80]}")


def check_project_status(project_dir: Path | None) -> CheckResult | None:
    """Check project health (DB, target, .env). Returns None if no project."""
    if project_dir is None:
        return None

    from clawpwn.config.project_setup import get_project_db_path, get_project_env_path

    parts: list[str] = []
    issues: list[str] = []

    db_path = get_project_db_path(project_dir)
    if db_path and db_path.exists():
        parts.append("DB ok")
    else:
        issues.append("DB missing")

    env_path = get_project_env_path(project_dir)
    if env_path and env_path.exists():
        parts.append(".env present")
    else:
        issues.append(".env missing")

    target = _read_target(project_dir)
    if target:
        parts.append(f"target set ({target})")
    else:
        issues.append("no target set")

    if issues:
        return CheckResult(
            "Project",
            "warn",
            f"Project: {', '.join(issues)}",
            fix="Run 'clawpwn init' and 'clawpwn target <ip>'",
        )
    return CheckResult("Project", "pass", f"Project: {', '.join(parts)}")


def _read_target(project_dir: Path) -> str | None:
    """Read target from project DB, returning None on any failure."""
    try:
        from clawpwn.config.project_setup import get_project_db_path

        db_path = get_project_db_path(project_dir)
        if not db_path or not db_path.exists():
            return None
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        cur = conn.execute("SELECT target FROM projects LIMIT 1")
        row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:  # noqa: BLE001
        return None
