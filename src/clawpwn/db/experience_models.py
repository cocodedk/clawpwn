"""Experience database models — global cross-project learning store."""

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import declarative_base

ExperienceBase = declarative_base()


class Experience(ExperienceBase):
    """A learned experience from scanning a target."""

    __tablename__ = "experiences"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    check_type = Column(String, nullable=False)
    target_domain = Column(String, nullable=False)
    target_tech = Column(String, nullable=True)
    result = Column(String, nullable=False)  # vulnerable, not_vulnerable
    confidence = Column(String, default="medium")
    effective_payload = Column(Text, nullable=True)
    evidence_summary = Column(Text, nullable=True)
    hit_count = Column(Integer, default=1)
