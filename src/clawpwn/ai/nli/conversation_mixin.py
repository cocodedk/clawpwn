"""Conversation memory recording and summarization for NLI."""

from typing import Any

from clawpwn.ai.nli import constants


class ConversationMixin:
    """Persists recent interactions and compresses memory when needed."""

    def _record_interaction(self, user_text: str, assistant_text: str) -> None:
        if self.session_manager is None:
            return
        try:
            self.session_manager.add_message("user", user_text)
            if assistant_text:
                self.session_manager.add_message("assistant", assistant_text)
            self._maybe_compress_memory()
        except Exception:
            return

    def _maybe_compress_memory(self) -> None:
        if self.session_manager is None:
            return
        total = self.session_manager.get_message_count()
        if total <= constants.MEMORY_MAX_MESSAGES:
            return

        to_summarize = max(0, total - constants.MEMORY_KEEP_RECENT)
        if to_summarize <= 0:
            return

        old_messages = self.session_manager.get_oldest_messages(to_summarize)
        if not old_messages:
            return

        summary = self._summarize_messages(old_messages)
        if summary:
            self.session_manager.update_summary(summary)
        self.session_manager.delete_messages([m.id for m in old_messages if m.id])

    def _summarize_messages(self, messages: list[Any]) -> str:
        if self.session_manager is None:
            return ""

        memory = self.session_manager.get_memory()
        previous = memory.summary.strip() if memory and memory.summary else ""
        lines = []
        for msg in messages:
            content = (msg.content or "").strip().replace("\n", " ")
            if len(content) > constants.MEMORY_MESSAGE_MAX_CHARS:
                content = content[: constants.MEMORY_MESSAGE_MAX_CHARS].rstrip() + "..."
            lines.append(f"{msg.role}: {content}")
        transcript = "\n".join(lines)
        if not transcript:
            return previous

        system_prompt = (
            "Summarize the conversation into a concise, durable memory. "
            "Keep: target scope, key decisions, constraints, findings, and next steps. "
            "Output plain text, 5-10 short bullet points."
        )
        prompt = (
            f"Previous summary:\n{previous or '(none)'}\n\n"
            f"New messages:\n{transcript}\n\n"
            "Return an updated summary."
        )
        try:
            summary = self.llm.chat(prompt, system_prompt)
        except Exception:
            summary = (previous + "\n" if previous else "") + transcript

        summary = summary.strip()
        if len(summary) > constants.MEMORY_SUMMARY_MAX_CHARS:
            summary = summary[: constants.MEMORY_SUMMARY_MAX_CHARS].rstrip() + "..."
        return summary
