"""LLM client for ClawPwn AI integration."""

from __future__ import annotations

from .client import ANALYSIS_MODEL_DEFAULT, ROUTING_MODEL_DEFAULT, LLMClient
from .tool_support import chat_with_tools

# Monkey-patch chat_with_tools as a method onto LLMClient for backward compatibility
LLMClient.chat_with_tools = chat_with_tools  # type: ignore[method-assign]

__all__ = [
    "LLMClient",
    "ROUTING_MODEL_DEFAULT",
    "ANALYSIS_MODEL_DEFAULT",
    "chat_with_tools",
]
