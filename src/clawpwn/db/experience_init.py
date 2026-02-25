"""Experience database initialization — ~/.clawpwn/experience.db."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clawpwn.db.experience_models import ExperienceBase

EXPERIENCE_DB_PATH = Path.home() / ".clawpwn" / "experience.db"


def init_experience_db(db_path: Path = EXPERIENCE_DB_PATH) -> None:
    """Create the experience database and tables."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    ExperienceBase.metadata.create_all(engine)


def get_experience_session(db_path: Path = EXPERIENCE_DB_PATH):
    """Return a new SQLAlchemy session for the experience database."""
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Session = sessionmaker(bind=engine)
    return Session()
