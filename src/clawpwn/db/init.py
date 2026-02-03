"""Database initialization for ClawPwn."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clawpwn.db.models import Base


def init_db(db_path: Path) -> None:
    """Initialize the SQLite database with all tables."""
    # Ensure parent directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Create engine
    engine = create_engine(f"sqlite:///{db_path}", echo=False)

    # Create all tables
    Base.metadata.create_all(engine)


def get_session(db_path: Path):
    """Get a database session."""
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Session = sessionmaker(bind=engine)
    return Session()
