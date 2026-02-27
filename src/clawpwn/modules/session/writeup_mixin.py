"""Writeup persistence helpers for SessionManager."""

from __future__ import annotations

from .db_models import Writeup


class WriteupMixin:
    """Provide writeup CRUD operations."""

    def save_writeup(
        self,
        title: str,
        content: str,
        fmt: str = "markdown",
    ) -> Writeup:
        """Persist a writeup to the database."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        writeup = Writeup(
            project_id=project.id,
            title=title,
            content=content,
            format=fmt,
        )
        self.session.add(writeup)
        self.session.commit()
        return writeup

    def get_writeups(self, limit: int = 10) -> list[Writeup]:
        """Return writeups ordered by creation date (newest first)."""
        project = self.get_project()
        if not project:
            return []

        return (
            self.session.query(Writeup)
            .filter_by(project_id=project.id)
            .order_by(Writeup.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_latest_writeup(self) -> Writeup | None:
        """Return the most recent writeup, or None."""
        writeups = self.get_writeups(limit=1)
        return writeups[0] if writeups else None
