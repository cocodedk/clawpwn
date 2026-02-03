"""Session management for ClawPwn projects."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

from clawpwn.db.models import Project, Finding, Log, ProjectState


class SessionManager:
    """Manages project sessions and state."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def create_project(self, project_path: str) -> Project:
        """Create a new project record."""
        project = Project(path=project_path, current_phase="Initialized")
        self.session.add(project)
        self.session.commit()
        return project

    def get_project(self) -> Optional[Project]:
        """Get the current project."""
        return self.session.query(Project).first()

    def set_target(self, target: str) -> None:
        """Set the target for the current project."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        project.target = target
        project.updated_at = datetime.utcnow()
        self.session.commit()

    def update_phase(self, phase: str) -> None:
        """Update the current phase of the project."""
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        project.current_phase = phase
        project.updated_at = datetime.utcnow()
        self.session.commit()

        # Log the phase change
        self.add_log(f"Phase changed to: {phase}", phase=phase)

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

        # Log the finding
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
        phase: Optional[str] = None,
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

    def get_state(self) -> Optional[ProjectState]:
        """Get the current project state as a ProjectState object."""
        project = self.get_project()
        if not project:
            return None

        # Count findings by severity
        findings_count = (
            self.session.query(Finding).filter_by(project_id=project.id).count()
        )
        critical_count = (
            self.session.query(Finding)
            .filter_by(project_id=project.id, severity="critical")
            .count()
        )
        high_count = (
            self.session.query(Finding)
            .filter_by(project_id=project.id, severity="high")
            .count()
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
