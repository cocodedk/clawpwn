"""Main AI orchestrator class."""

from pathlib import Path

from clawpwn.ai.llm import LLMClient
from clawpwn.config import get_project_db_path
from clawpwn.modules.exploit import ExploitManager
from clawpwn.modules.network import NetworkDiscovery
from clawpwn.modules.scanner import Scanner
from clawpwn.modules.session import SessionManager
from clawpwn.modules.vulndb import VulnDB

from .analysis_mixin import AnalysisMixin
from .decision_mixin import DecisionMixin
from .execute_mixin import ExecuteMixin
from .models import KillChainState
from .run_mixin import RunMixin


class AIOrchestrator(RunMixin, DecisionMixin, ExecuteMixin, AnalysisMixin):
    """Orchestrates AI decisions and actions during penetration testing."""

    def __init__(self, project_dir: Path, llm_client: LLMClient | None = None):
        self.project_dir = project_dir
        db_path = get_project_db_path(project_dir)
        if db_path is None:
            raise ValueError("Project storage not found. Run 'clawpwn init' first.")

        self.db_path = db_path
        self.session = SessionManager(self.db_path)
        self._llm_owned = llm_client is None
        self.llm = llm_client or LLMClient(project_dir=project_dir)

        self.scanner = Scanner(project_dir)
        self.network = NetworkDiscovery(project_dir)
        self.vulndb = VulnDB()
        self.exploit_manager = ExploitManager(project_dir)

        self.kill_chain_state: KillChainState | None = None
        self.require_approval_for = ["critical", "exploitation", "exfiltration"]
        self.auto_mode = False

    def close(self) -> None:
        """Release resources and close owned LLM client."""
        if self._llm_owned and getattr(self, "llm", None) is not None:
            self.llm.close()

    def set_auto_mode(self, enabled: bool) -> None:
        """Enable or disable automatic mode."""
        self.auto_mode = enabled
        if self.kill_chain_state:
            self.kill_chain_state.auto_mode = enabled
