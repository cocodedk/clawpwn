"""Database models for ClawPwn using SQLAlchemy."""

from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship


def _utc_now() -> datetime:
    return datetime.now(UTC)


Base = declarative_base()


class Project(Base):
    """Represents a pentest project."""

    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    path = Column(String, nullable=False, unique=True)
    target = Column(String, nullable=True)
    current_phase = Column(String, default="Not Started")
    created_at = Column(DateTime(timezone=True), default=_utc_now)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    # Relationships
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="project", cascade="all, delete-orphan")
    memory = relationship(
        "ProjectMemory", back_populates="project", cascade="all, delete-orphan", uselist=False
    )
    messages = relationship(
        "ConversationMessage", back_populates="project", cascade="all, delete-orphan"
    )
    plan_steps = relationship("PlanStep", back_populates="project", cascade="all, delete-orphan")


class Finding(Base):
    """Represents a security finding/vulnerability."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    description = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)

    # Attack details
    attack_type = Column(String)  # SQLi, XSS, RCE, etc.
    target_url = Column(String)
    payload = Column(Text)

    created_at = Column(DateTime(timezone=True), default=_utc_now)

    # Relationship
    project = relationship("Project", back_populates="findings")


class Log(Base):
    """Activity logs for the project."""

    __tablename__ = "logs"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    level = Column(String, default="INFO")  # DEBUG, INFO, WARNING, ERROR
    phase = Column(String)
    message = Column(Text, nullable=False)
    details = Column(Text)

    created_at = Column(DateTime(timezone=True), default=_utc_now)

    # Relationship
    project = relationship("Project", back_populates="logs")


class ProjectMemory(Base):
    """Persistent memory for a project (summary + objective)."""

    __tablename__ = "project_memory"

    project_id = Column(Integer, ForeignKey("projects.id"), primary_key=True)
    objective = Column(Text, default="")
    summary = Column(Text, default="")
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    project = relationship("Project", back_populates="memory")


class ConversationMessage(Base):
    """Conversation messages stored for project memory."""

    __tablename__ = "conversation_messages"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    role = Column(String, default="user")  # user | assistant | system
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utc_now)

    project = relationship("Project", back_populates="messages")


class PlanStep(Base):
    """A single step in a persisted attack plan."""

    __tablename__ = "plan_steps"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)

    step_number = Column(Integer, nullable=False)
    tool = Column(String, default="")  # tool name for speed-tier lookup
    description = Column(Text, nullable=False)
    status = Column(String, default="pending")  # pending, in_progress, done, skipped
    result_summary = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=_utc_now)
    updated_at = Column(DateTime(timezone=True), default=_utc_now, onupdate=_utc_now)

    project = relationship("Project", back_populates="plan_steps")


class ProjectState:
    """Convenience class to hold project state."""

    def __init__(
        self,
        project_path: str,
        target: str | None = None,
        current_phase: str = "Not Started",
        created_at: datetime | None = None,
        findings_count: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
    ):
        self.project_path = project_path
        self.target = target
        self.current_phase = current_phase
        self.created_at = created_at or datetime.now(UTC)
        self.findings_count = findings_count
        self.critical_count = critical_count
        self.high_count = high_count
