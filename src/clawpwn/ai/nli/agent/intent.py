"""LLM-based intent classification for the plan executor."""

from __future__ import annotations

from typing import Any


def classify_intent(
    llm: Any,
    user_message: str,
    has_pending_plan: bool,
) -> str:
    """Classify user intent as plan_execute, plan_new, or conversational.

    When a pending plan exists the LLM decides whether the message is a
    continuation (``plan_execute``) or a brand-new action request
    (``plan_new``).  ``plan_new`` tells the caller to clear the stale
    plan before generating a fresh one.
    """
    if has_pending_plan:
        return _classify_with_pending(llm, user_message)

    return _classify_fresh(llm, user_message)


def _classify_with_pending(llm: Any, user_message: str) -> str:
    """Classify when a plan is already in progress."""
    prompt = (
        "A penetration-test plan is already in progress. "
        "Classify this NEW user message into exactly ONE category.\n"
        "Respond with ONLY the category name, nothing else.\n\n"
        "Categories:\n"
        "- plan_resume: user wants to CONTINUE, resume, or check on "
        "the current plan (e.g. 'continue', 'go', 'next', 'status')\n"
        "- plan_new: user is asking for a DIFFERENT action than the "
        "pending plan — a new scan, different ports, different tool, "
        "or any request that should replace the current plan\n"
        "- conversational: user is asking a question, wants help, "
        "or any non-execution request. Includes queries about previous "
        "results such as 'list ports', 'show findings', 'what did you find', "
        "'what ports are open', 'summarize results'\n\n"
        f'Message: "{user_message}"'
    )
    try:
        raw = llm.chat(prompt, model=getattr(llm, "routing_model", None))
        if not isinstance(raw, str):
            return "plan_execute"
        result = raw.strip().lower()
        if "plan_new" in result:
            return "plan_new"
        if "conversational" in result:
            return "conversational"
        return "plan_execute"  # plan_resume → resume existing
    except Exception:
        return "plan_execute"


def _classify_fresh(llm: Any, user_message: str) -> str:
    """Classify when no pending plan exists."""
    prompt = (
        "Classify this user message into exactly ONE category.\n"
        "Respond with ONLY the category name, nothing else.\n\n"
        "Categories:\n"
        "- plan_execute: user wants to EXECUTE a scan, attack, or security "
        "assessment action against a target right now\n"
        "- conversational: user is asking a question, wants information, "
        "wants you to write/show/explain a command, requesting status, "
        "asking for help, setting a target, or any non-execution request. "
        "Phrases like 'write the command', 'show me', 'what command', "
        "'how do I', 'explain' are conversational even if they mention "
        "tools or testing. Also includes queries about previous scan "
        "results: 'list ports', 'show findings', 'what did you find', "
        "'what ports are open', 'summarize results'\n\n"
        f'Message: "{user_message}"'
    )
    try:
        raw = llm.chat(prompt, model=getattr(llm, "routing_model", None))
        if not isinstance(raw, str):
            return "conversational"
        result = raw.strip().lower()
        if "plan_execute" in result:
            return "plan_execute"
        return "conversational"
    except Exception:
        return "conversational"
