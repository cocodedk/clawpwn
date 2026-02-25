"""Project lifecycle and phase helpers for SessionManager."""

from datetime import UTC, datetime

from .db_models import Project


class ProjectMixin:
    """Provide project creation and project-level state mutation methods."""

    def create_project(self, project_path: str) -> Project:
        """Create a new project record."""
        project = Project(path=project_path, current_phase="Initialized")
        self.session.add(project)
        self.session.commit()
        return project

    def get_project(self) -> Project | None:
        """Get the current project."""
        return self.session.query(Project).first()

    def set_target(self, target: str) -> None:
        """Set the target for the current project."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        project.target = target
        project.updated_at = datetime.now(UTC)
        self.session.commit()

    def update_phase(self, phase: str) -> None:
        """Update the current phase of the project."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        project.current_phase = phase
        project.updated_at = datetime.now(UTC)
        self.session.commit()
        self.add_log(f"Phase changed to: {phase}", phase=phase)
