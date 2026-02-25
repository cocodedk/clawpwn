"""Context-selection helpers for NLI prompts."""

import re

from clawpwn.ai.nli import constants


class ContextMixin:
    """Controls when and how memory context is injected into prompts."""

    def _should_include_memory_context(self, command: str) -> bool:
        cleaned = command.strip().lower()
        if not cleaned:
            return False
        if self._extract_url(cleaned) or self._extract_network(cleaned):
            return False
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", cleaned):
            return False

        follow_up_terms = {
            "it",
            "that",
            "those",
            "them",
            "again",
            "same",
            "previous",
            "earlier",
            "before",
            "continue",
            "next",
            "last",
            "above",
        }
        tokens = set(re.findall(r"[a-z0-9]+", cleaned))
        if tokens & follow_up_terms:
            return True

        follow_up_phrases = (
            "what did we",
            "from before",
            "as discussed",
            "based on that",
            "same target",
        )
        return any(phrase in cleaned for phrase in follow_up_phrases)

    def _build_memory_context(self, compact: bool = False) -> str:
        if self.session_manager is None:
            return ""
        memory = self.session_manager.get_memory()

        summary_limit = (
            constants.MEMORY_COMPACT_SUMMARY_MAX_CHARS
            if compact
            else constants.MEMORY_SUMMARY_MAX_CHARS
        )
        recent_limit = (
            constants.MEMORY_COMPACT_RECENT_LIMIT if compact else constants.MEMORY_RECENT_LIMIT
        )
        message_limit = (
            constants.MEMORY_COMPACT_MESSAGE_MAX_CHARS
            if compact
            else constants.MEMORY_MESSAGE_MAX_CHARS
        )

        parts: list[str] = []
        if memory and memory.objective:
            objective = memory.objective.strip()
            if len(objective) > message_limit:
                objective = objective[:message_limit].rstrip() + "..."
            parts.append(f"Objective: {objective}")
        if memory and memory.summary:
            summary = memory.summary.strip()
            if len(summary) > summary_limit:
                summary = summary[:summary_limit].rstrip() + "..."
            parts.append(f"Summary: {summary}")

        recent = list(reversed(self.session_manager.get_recent_messages(recent_limit)))
        if recent:
            lines = []
            for msg in recent:
                content = (msg.content or "").strip().replace("\n", " ")
                if len(content) > message_limit:
                    content = content[:message_limit].rstrip() + "..."
                lines.append(f"{msg.role}: {content}")
            parts.append("Recent messages:\n" + "\n".join(lines))

        context = "\n".join(parts).strip()
        if compact and len(context) > constants.MEMORY_COMPACT_CONTEXT_MAX_CHARS:
            context = context[: constants.MEMORY_COMPACT_CONTEXT_MAX_CHARS].rstrip() + "..."
        return context
