"""Findings and logging helpers for SessionManager."""

from .db_models import Finding, Log


class FindingLogMixin:
    """Provide finding creation and project log operations."""

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str = "",
        evidence: str = "",
        attack_type: str = "",
    ) -> Finding:
        """Add a new finding to the project."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        finding = Finding(
            project_id=project.id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            attack_type=attack_type,
        )
        self.session.add(finding)
        self.session.commit()

        self.add_log(
            f"New finding: {title} ({severity})",
            level="WARNING",
            phase=project.current_phase,
        )
        return finding

    def add_log(
        self,
        message: str,
        level: str = "INFO",
        phase: str | None = None,
        details: str = "",
    ) -> Log:
        """Add a log entry."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        log = Log(
            project_id=project.id,
            level=level,
            phase=phase or project.current_phase,
            message=message,
            details=details,
        )
        self.session.add(log)
        self.session.commit()
        return log

    def get_logs(self, limit: int = 100) -> list[Log]:
        """Get recent logs for the project."""
        project = self.get_project()
        if not project:
            return []

        return (
            self.session.query(Log)
            .filter_by(project_id=project.id)
            .order_by(Log.created_at.desc())
            .limit(limit)
            .all()
        )
