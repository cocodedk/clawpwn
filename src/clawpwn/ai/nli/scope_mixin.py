"""Scope enforcement helpers for NLI."""


class ScopeMixin:
    """Prevents out-of-scope actions in NLI flows."""

    def _enforce_target_scope(
        self, intent: str, parsed: dict[str, str], command: str
    ) -> dict[str, object] | None:
        if intent in {"help", "check_status", "set_target", "unknown"}:
            return None

        current = self._get_current_target()
        if not current:
            return None

        requested = self._resolve_requested_target(intent, parsed, command)
        if not requested:
            return None
        if self._targets_match(current, requested):
            return None

        return {
            "success": False,
            "action": "blocked",
            "response": (
                f"Out of scope. Current target is: {current}. "
                f"You asked about: {requested}. "
                "Use 'set target <target>' to change scope or start a new project."
            ),
        }

    def _resolve_requested_target(
        self, intent: str, parsed: dict[str, str], command: str
    ) -> str | None:
        target = parsed.get("target", "").strip()
        if intent == "discover":
            return target or self._extract_network(command)
        if target:
            return target
        return self._extract_url(command)

    def _targets_match(self, current: str, requested: str) -> bool:
        current_norm = self._normalize_target(current)
        requested_norm = self._normalize_target(requested)
        if not current_norm or not requested_norm:
            return False

        current_kind, current_value = current_norm
        requested_kind, requested_value = requested_norm

        if requested_kind == "network":
            if current_kind != "ip":
                return False
            return current_value in requested_value
        if current_kind == "network":
            if requested_kind != "ip":
                return False
            return requested_value in current_value
        if current_kind == requested_kind:
            return current_value == requested_value
        return False
