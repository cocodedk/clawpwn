"""Database models for ClawPwn using SQLAlchemy."""

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class Project(Base):
    """Represents a pentest project."""

    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    path = Column(String, nullable=False, unique=True)
    target = Column(String, nullable=True)
    current_phase = Column(String, default="Not Started")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    findings = relationship(
        "Finding", back_populates="project", cascade="all, delete-orphan"
    )
    logs = relationship("Log", back_populates="project", cascade="all, delete-orphan")


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

    created_at = Column(DateTime, default=datetime.utcnow)

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

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    project = relationship("Project", back_populates="logs")


class ProjectState:
    """Convenience class to hold project state."""

    def __init__(
        self,
        project_path: str,
        target: Optional[str] = None,
        current_phase: str = "Not Started",
        created_at: Optional[datetime] = None,
        findings_count: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
    ):
        self.project_path = project_path
        self.target = target
        self.current_phase = current_phase
        self.created_at = created_at or datetime.utcnow()
        self.findings_count = findings_count
        self.critical_count = critical_count
        self.high_count = high_count
