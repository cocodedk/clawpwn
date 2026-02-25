"""Attack plan persistence helpers for SessionManager."""

from __future__ import annotations

from .db_models import PlanStep


class PlanMixin:
    """Provide attack plan CRUD operations."""

    def save_plan(self, steps: list[str] | list[dict[str, str]]) -> list[PlanStep]:
        """Replace the current plan with new steps.

        Accepts either:
        - list[str]: plain descriptions (legacy / tests)
        - list[dict]: structured steps with 'description' and 'tool' keys

        Any existing plan for the project is deleted first.
        """
        project = self.get_project()
        if not project:
            raise ValueError("No project found")

        # Clear old plan
        self.session.query(PlanStep).filter_by(project_id=project.id).delete()

        # Normalise input
        normalised: list[dict[str, str]] = []
        for item in steps:
            if isinstance(item, str):
                normalised.append({"description": item.strip(), "tool": ""})
            else:
                normalised.append(
                    {
                        "description": item.get("description", "").strip(),
                        "tool": item.get("tool", ""),
                    }
                )

        created: list[PlanStep] = []
        for idx, step_data in enumerate(normalised, start=1):
            step = PlanStep(
                project_id=project.id,
                step_number=idx,
                tool=step_data["tool"],
                description=step_data["description"],
                status="pending",
            )
            self.session.add(step)
            created.append(step)

        self.session.commit()
        return created

    def get_plan(self) -> list[PlanStep]:
        """Return all plan steps ordered by step_number."""
        project = self.get_project()
        if not project:
            return []

        return (
            self.session.query(PlanStep)
            .filter_by(project_id=project.id)
            .order_by(PlanStep.step_number.asc())
            .all()
        )

    def update_step_status(
        self,
        step_number: int,
        status: str,
        result_summary: str = "",
    ) -> PlanStep | None:
        """Update a single step's status and optional result summary."""
        project = self.get_project()
        if not project:
            return None

        step = (
            self.session.query(PlanStep)
            .filter_by(project_id=project.id, step_number=step_number)
            .first()
        )
        if step is None:
            return None

        step.status = status
        if result_summary:
            step.result_summary = result_summary
        self.session.commit()
        return step

    def get_next_pending_step(self) -> PlanStep | None:
        """Return the first pending step, or None if plan is complete."""
        project = self.get_project()
        if not project:
            return None

        return (
            self.session.query(PlanStep)
            .filter_by(project_id=project.id, status="pending")
            .order_by(PlanStep.step_number.asc())
            .first()
        )

    def clear_plan(self) -> None:
        """Delete all plan steps for the current project."""
        project = self.get_project()
        if not project:
            return
        self.session.query(PlanStep).filter_by(project_id=project.id).delete()
        self.session.commit()

    def format_plan_status(self) -> str:
        """Return a human-readable plan summary for agent context."""
        steps = self.get_plan()
        if not steps:
            return ""

        status_icons = {
            "pending": "[ ]",
            "in_progress": "[~]",
            "done": "[x]",
            "skipped": "[-]",
        }
        lines: list[str] = []
        for s in steps:
            icon = status_icons.get(s.status, "[ ]")
            line = f"{icon} {s.step_number}. {s.description}"
            if s.result_summary:
                line += f" -> {s.result_summary}"
            lines.append(line)

        done = sum(1 for s in steps if s.status in ("done", "skipped"))
        total = len(steps)
        lines.insert(0, f"Attack plan ({done}/{total} complete):")
        return "\n".join(lines)
