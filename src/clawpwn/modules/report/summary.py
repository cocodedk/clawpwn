"""Executive summary generation."""

from typing import Any


def generate_executive_summary(llm: Any, state: Any, findings: list[Any]) -> str:
    """Generate an executive summary with LLM and safe fallback."""
    system_prompt = (
        "You are a senior security consultant writing an executive summary for a penetration "
        "test report. Write 2-3 paragraphs summarizing key findings and business impact. "
        "Be professional and concise. Focus on risk and business impact."
    )

    findings_summary = (
        f"Target: {state.target}\n"
        f"Total Findings: {len(findings)}\n"
        f"Critical: {state.critical_count}\n"
        f"High: {state.high_count}\n"
        f"Phase: {state.current_phase}\n"
    )

    try:
        return llm.chat(findings_summary, system_prompt)
    except Exception:
        return (
            f"A penetration test was conducted against {state.target or 'the target'}. "
            f"{len(findings)} security issues were identified, including "
            f"{state.critical_count} critical and {state.high_count} high severity findings. "
            "Immediate attention is recommended for critical and high severity issues."
        )
