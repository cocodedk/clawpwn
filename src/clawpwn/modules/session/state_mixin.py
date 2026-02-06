"""Project state aggregation helpers."""

from .db_models import Finding, ProjectState


class StateMixin:
    """Provide aggregate project state queries."""

    def get_state(self) -> ProjectState | None:
        """Get the current project state as a ProjectState object."""
        project = self.get_project()
        if not project:
            return None

        findings_count = self.session.query(Finding).filter_by(project_id=project.id).count()
        critical_count = (
            self.session.query(Finding)
            .filter_by(project_id=project.id, severity="critical")
            .count()
        )
        high_count = (
            self.session.query(Finding).filter_by(project_id=project.id, severity="high").count()
        )

        return ProjectState(
            project_path=project.path,
            target=project.target,
            current_phase=project.current_phase,
            created_at=project.created_at,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
        )
