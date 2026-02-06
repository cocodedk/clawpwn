"""Main SessionManager class."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clawpwn.db.init import init_db

from .finding_log_mixin import FindingLogMixin
from .memory_mixin import MemoryMixin
from .project_mixin import ProjectMixin
from .state_mixin import StateMixin


class SessionManager(ProjectMixin, MemoryMixin, FindingLogMixin, StateMixin):
    """Manages project sessions and state."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        init_db(self.db_path)
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        session_factory = sessionmaker(bind=self.engine)
        self.session = session_factory()
