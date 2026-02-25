"""Report generator orchestration."""

from pathlib import Path
from typing import Any

from clawpwn.ai.llm import LLMClient
from clawpwn.config import get_project_db_path
from clawpwn.modules.session import SessionManager

from .html_report import generate_html_report, render_finding_html
from .json_report import generate_json_report
from .markdown_report import generate_markdown_report, render_finding_markdown
from .models import ReportConfig
from .pdf_report import generate_pdf_note
from .summary import generate_executive_summary


class ReportGenerator:
    """Generates penetration testing reports."""

    def __init__(self, project_dir: Path, llm_client: LLMClient | None = None):
        self.project_dir = project_dir
        db_path = get_project_db_path(project_dir)
        if db_path is None:
            raise ValueError("Project storage not found. Run 'clawpwn init' first.")

        self.db_path = db_path
        self.session = SessionManager(self.db_path)
        self._llm_owned = llm_client is None
        self.llm = llm_client or LLMClient(project_dir=project_dir)
        self.report_dir = project_dir / "report"
        self.report_dir.mkdir(exist_ok=True)

    def close(self) -> None:
        """Release resources and close owned LLM client."""
        if self._llm_owned and getattr(self, "llm", None) is not None:
            self.llm.close()

    def generate(self, config: ReportConfig | None = None) -> Path:
        """Generate a report based on configuration."""
        config = config or ReportConfig()
        state, findings = self._load_report_data()

        if config.format == "html":
            return self._generate_html(state, findings, config)
        if config.format == "json":
            return self._generate_json(state, findings, config)
        if config.format == "md":
            return self._generate_markdown(state, findings, config)
        if config.format == "pdf":
            return self._generate_pdf(state, findings, config)
        raise ValueError(f"Unsupported format: {config.format}")

    def _load_report_data(self) -> tuple[Any, list[Any]]:
        state = self.session.get_state()
        if not state:
            raise ValueError("No project data available")

        project = self.session.get_project()
        if not project:
            raise ValueError("No project found in database")

        from clawpwn.db.models import Finding

        findings = self.session.session.query(Finding).filter_by(project_id=project.id).all()
        return state, findings

    def _generate_html(self, state: Any, findings: list[Any], config: ReportConfig) -> Path:
        executive_summary = self._safe_executive_summary(state, findings, config)
        return generate_html_report(self.report_dir, state, findings, config, executive_summary)

    def _render_finding_html(self, finding: Any, config: ReportConfig) -> str:
        return render_finding_html(finding, config)

    def _generate_json(self, state: Any, findings: list[Any], config: ReportConfig) -> Path:
        return generate_json_report(self.report_dir, state, findings, config)

    def _generate_markdown(self, state: Any, findings: list[Any], config: ReportConfig) -> Path:
        executive_summary = self._safe_executive_summary(state, findings, config)
        return generate_markdown_report(self.report_dir, state, findings, config, executive_summary)

    def _render_finding_markdown(self, finding: Any, config: ReportConfig) -> str:
        return render_finding_markdown(finding, config)

    def _generate_pdf(self, state: Any, findings: list[Any], config: ReportConfig) -> Path:
        html_file = self._generate_html(state, findings, config)
        return generate_pdf_note(self.report_dir, html_file)

    def _generate_executive_summary(self, state: Any, findings: list[Any]) -> str:
        return generate_executive_summary(self.llm, state, findings)

    def _safe_executive_summary(
        self,
        state: Any,
        findings: list[Any],
        config: ReportConfig,
    ) -> str:
        if not config.executive_summary:
            return ""
        try:
            return self._generate_executive_summary(state, findings)
        except Exception:
            return "Executive summary unavailable."


def generate_report(project_dir: Path, format: str = "html", include_evidence: bool = True) -> Path:
    """Convenience function to generate a report for a project."""
    generator = ReportGenerator(project_dir)
    try:
        return generator.generate(ReportConfig(format=format, include_evidence=include_evidence))
    finally:
        generator.close()
