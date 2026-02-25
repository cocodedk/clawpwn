"""Extraction and help-topic helpers for NLI."""

import re
from urllib.parse import urlparse

from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager


class ExtractHelpMixin:
    """Helpers for text extraction and help topic resolution."""

    def _extract_help_topic(self, command: str) -> str | None:
        cleaned = re.sub(r"[^a-z0-9]+", " ", command.lower()).strip()
        stop = {"help", "with", "about", "on", "me", "please", "a", "an", "the", "to", "for"}
        tokens = [t for t in cleaned.split() if t not in stop]
        if not tokens:
            return None
        if len(tokens) >= 2:
            key = self._resolve_help_topic(" ".join(tokens[:2]))
            if key:
                return key
        for token in tokens:
            key = self._resolve_help_topic(token)
            if key:
                return key
        return None

    def _resolve_help_topic(self, topic: str) -> str | None:
        cleaned = re.sub(r"[^a-z0-9]+", " ", topic.lower()).strip()
        if not cleaned:
            return None
        if cleaned in self.HELP_TOPIC_ALIASES:
            cleaned = self.HELP_TOPIC_ALIASES[cleaned]
        compact = cleaned.replace(" ", "")
        if compact in self.HELP_TOPICS:
            return compact
        if cleaned in self.HELP_TOPICS:
            return cleaned
        return None

    def _is_help_query(self, command: str) -> bool:
        cleaned = re.sub(r"[^a-z0-9?]+", " ", command.lower()).strip()
        if not cleaned:
            return False
        if cleaned.startswith("help ") or cleaned == "help":
            return True
        return any(
            phrase in cleaned
            for phrase in (
                "how do i",
                "how to",
                "how can i",
                "explain",
                "usage",
                "options",
                "restart",
            )
        )

    def _extract_url(self, text: str) -> str | None:
        pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        match = re.search(pattern, text)
        return match.group(0) if match else None

    def _extract_network(self, text: str) -> str | None:
        pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
        match = re.search(pattern, text)
        return match.group(0) if match else None

    def _extract_service_info(self, text: str) -> dict[str, str]:
        patterns = [
            r"(\w+)\s+(\d+\.?\d*\.?\d*)",
            r"(\w+)\s+version\s+(\d+\.?\d*\.?\d*)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return {"service": match.group(1).lower(), "version": match.group(2)}

        words = text.lower().split()
        common = {
            "apache",
            "nginx",
            "mysql",
            "ssh",
            "ftp",
            "wordpress",
            "joomla",
            "drupal",
            "php",
            "tomcat",
            "iis",
        }
        for word in words:
            if word in common:
                return {"service": word, "version": ""}
        return {"service": "", "version": ""}

    def _get_current_target(self) -> str | None:
        try:
            session = self.session_manager
            if session is None:
                db_path = get_project_db_path(self.project_dir)
                if db_path is None:
                    raise ValueError("Project storage not found. Run 'clawpwn init' first.")
                session = SessionManager(db_path)
            state = session.get_state()
            return state.target if state else None
        except Exception:
            return None

    def _normalize_target(self, value: str) -> tuple[str, object] | None:
        cleaned = value.strip()
        if not cleaned:
            return None

        network = self._extract_network(cleaned)
        if network:
            import ipaddress

            try:
                return ("network", ipaddress.ip_network(network, strict=False))
            except ValueError:
                return None

        host = cleaned
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            if parsed.hostname:
                host = parsed.hostname
        else:
            host = cleaned.split("/", 1)[0]

        if ":" in host and host.count(":") == 1:
            host = host.split(":", 1)[0]

        import ipaddress

        try:
            return ("ip", ipaddress.ip_address(host))
        except ValueError:
            return ("host", host.lower())
