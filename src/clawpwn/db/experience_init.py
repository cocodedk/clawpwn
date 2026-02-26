"""Experience database initialization — ~/.clawpwn/experience.db."""

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clawpwn.db.experience_models import ExperienceBase

EXPERIENCE_DB_PATH = Path.home() / ".clawpwn" / "experience.db"


def _get_engine(db_path: Path = EXPERIENCE_DB_PATH):
    """Build a SQLAlchemy engine, preferring CLAWPWN_EXPERIENCE_DB_URL if set."""
    url = os.environ.get("CLAWPWN_EXPERIENCE_DB_URL", "")
    if url:
        return create_engine(url, echo=False)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}", echo=False)


def init_experience_db(db_path: Path = EXPERIENCE_DB_PATH) -> None:
    """Create the experience database and tables."""
    engine = _get_engine(db_path)
    ExperienceBase.metadata.create_all(engine)


def get_experience_session(db_path: Path = EXPERIENCE_DB_PATH):
    """Return a new SQLAlchemy session for the experience database."""
    engine = _get_engine(db_path)
    Session = sessionmaker(bind=engine)
    return Session()
