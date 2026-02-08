"""Tests for Anthropic tool-support request shaping."""

from __future__ import annotations

from types import SimpleNamespace

from clawpwn.ai.llm.tool_support import chat_with_tools


class _FakeMessages:
    def __init__(self) -> None:
        self.last_kwargs: dict | None = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return SimpleNamespace(content=[], stop_reason="end_turn")


class _FakeAnthropicSDK:
    def __init__(self) -> None:
        self.messages = _FakeMessages()


class _FakeClient:
    def __init__(self) -> None:
        self.provider = "anthropic"
        self.routing_model = "claude-test"
        self.anthropic_sdk = _FakeAnthropicSDK()


def test_chat_with_tools_disables_thinking_if_min_budget_cannot_be_met():
    client = _FakeClient()

    chat_with_tools(
        client=client,
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        max_tokens=1024,
        thinking_budget=3000,
    )

    sent = client.anthropic_sdk.messages.last_kwargs
    assert sent is not None
    assert sent["max_tokens"] == 1024
    assert "thinking" not in sent


def test_chat_with_tools_omits_thinking_when_no_valid_budget_remains():
    client = _FakeClient()

    chat_with_tools(
        client=client,
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        max_tokens=1,
        thinking_budget=10,
    )

    sent = client.anthropic_sdk.messages.last_kwargs
    assert sent is not None
    assert sent["max_tokens"] == 1
    assert "thinking" not in sent


def test_chat_with_tools_enables_thinking_when_constraints_are_satisfied():
    client = _FakeClient()

    chat_with_tools(
        client=client,
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        max_tokens=4096,
        thinking_budget=3000,
    )

    sent = client.anthropic_sdk.messages.last_kwargs
    assert sent is not None
    assert sent["max_tokens"] == 4096
    assert sent["thinking"]["budget_tokens"] == 3000
