"""Analysis and recommendation functions for LLM client."""

from typing import Any


def analyze_finding(client, finding_data: dict[str, Any]) -> str:
    """Analyze a finding and provide AI insights."""
    system_prompt = """You are a penetration testing expert. Analyze the finding and provide:
1. A clear explanation of the vulnerability
2. Potential impact and risk
3. Remediation steps
Be concise and technical."""

    message = f"Analyze this finding:\n\n{str(finding_data)}"
    return client.chat(message, system_prompt)


def suggest_next_steps(client, current_phase: str, findings: list[dict[str, Any]]) -> str:
    """Suggest next steps in the pentest based on current state."""
    system_prompt = """You are a penetration testing strategist. Based on the current phase and findings, suggest the next logical steps in the kill chain. Be specific and actionable."""

    message = f"Current phase: {current_phase}\n\nFindings so far:\n{str(findings)}\n\nWhat should I do next?"
    return client.chat(message, system_prompt)
