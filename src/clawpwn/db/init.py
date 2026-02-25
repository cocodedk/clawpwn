"""Database initialization for ClawPwn."""

from pathlib import Path

from sqlalchemy import create_engine, inspect, text
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

    # Run lightweight migrations for schema changes
    _migrate(engine)


def _migrate(engine) -> None:
    """Add missing columns to existing tables (lightweight migration)."""
    insp = inspect(engine)
    if "plan_steps" in insp.get_table_names():
        columns = {col["name"] for col in insp.get_columns("plan_steps")}
        if "tool" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE plan_steps ADD COLUMN tool TEXT DEFAULT ''"))


def get_session(db_path: Path):
    """Get a database session."""
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Session = sessionmaker(bind=engine)
    return Session()
