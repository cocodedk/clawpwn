"""Tests for attack-response feedback signal analysis."""

from clawpwn.modules.attack_feedback import (
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)


def test_extracts_mysql_auth_hint_signals() -> None:
    text = "#1045 - Access denied for user 'admin'@'localhost' (using password: NO)"
    signals = extract_attack_signals(text)
    hints = summarize_signals(signals, "hint")

    assert hints
    assert any("password" in msg.lower() or "mysql" in msg.lower() for msg in hints)


def test_extracts_block_signals_from_status_and_headers() -> None:
    signals = extract_attack_signals(
        "Too many requests",
        status_code=429,
        headers={"Retry-After": "120"},
    )
    blocks = summarize_signals(signals, "block")

    assert blocks
    assert any("backoff" in msg.lower() or "http 429" in msg.lower() for msg in blocks)


def test_policy_stops_on_repeated_block_signals() -> None:
    signals = extract_attack_signals(
        "Request blocked by WAF. Too many requests.",
        status_code=403,
        headers={"Retry-After": "10"},
    )
    decision = decide_attack_policy(signals, block_streak=2)

    assert decision.action == "stop_and_replan"
