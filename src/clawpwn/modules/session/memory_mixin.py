"""Memory and conversation helpers for SessionManager."""

from .db_models import ConversationMessage, ProjectMemory


class MemoryMixin:
    """Provide project memory and conversation message operations."""

    def get_memory(self) -> ProjectMemory | None:
        """Get (and lazily create) the project memory record."""
        project = self.get_project()
        if not project:
            return None

        memory = self.session.query(ProjectMemory).filter_by(project_id=project.id).first()
        if memory is None:
            memory = ProjectMemory(project_id=project.id, objective="", summary="")
            self.session.add(memory)
            self.session.commit()
        return memory

    def set_objective(self, text: str) -> None:
        """Set the current objective for the project."""
        memory = self.get_memory()
        if memory is None:
            raise ValueError("No project found")
        memory.objective = text.strip()
        self.session.commit()

    def update_summary(self, summary: str) -> None:
        """Update the project summary memory."""
        memory = self.get_memory()
        if memory is None:
            raise ValueError("No project found")
        memory.summary = summary.strip()
        self.session.commit()

    def clear_memory(self) -> None:
        """Clear summary, objective, and conversation messages."""
        memory = self.get_memory()
        if memory is None:
            raise ValueError("No project found")
        memory.objective = ""
        memory.summary = ""

        project = self.get_project()
        if project:
            self.session.query(ConversationMessage).filter_by(project_id=project.id).delete()
        self.session.commit()

    def add_message(self, role: str, content: str) -> ConversationMessage:
        """Add a conversation message to project memory."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        message = ConversationMessage(project_id=project.id, role=role, content=content)
        self.session.add(message)
        self.session.commit()
        return message

    def get_recent_messages(self, limit: int = 20) -> list[ConversationMessage]:
        """Get recent conversation messages (most recent first)."""
        project = self.get_project()
        if not project:
            return []
        return (
            self.session.query(ConversationMessage)
            .filter_by(project_id=project.id)
            .order_by(ConversationMessage.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_message_count(self) -> int:
        """Count total conversation messages."""
        project = self.get_project()
        if not project:
            return 0
        return self.session.query(ConversationMessage).filter_by(project_id=project.id).count()

    def get_oldest_messages(self, limit: int) -> list[ConversationMessage]:
        """Get oldest conversation messages (oldest first)."""
        project = self.get_project()
        if not project or limit <= 0:
            return []
        return (
            self.session.query(ConversationMessage)
            .filter_by(project_id=project.id)
            .order_by(ConversationMessage.created_at.asc())
            .limit(limit)
            .all()
        )

    def delete_messages(self, message_ids: list[int]) -> None:
        """Delete conversation messages by id."""
        if not message_ids:
            return
        self.session.query(ConversationMessage).filter(
            ConversationMessage.id.in_(message_ids)
        ).delete(synchronize_session=False)
        self.session.commit()
