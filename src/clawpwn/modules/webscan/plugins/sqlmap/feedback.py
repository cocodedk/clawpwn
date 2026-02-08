"""Attack feedback extraction/annotation for sqlmap findings."""

from __future__ import annotations

from clawpwn.modules.attack_feedback import (
    AttackSignal,
    decide_attack_policy,
    extract_attack_signals,
    summarize_signals,
)

from ...models import WebScanFinding


def extract_signals(stdout: str, stderr: str) -> list[AttackSignal]:
    """Extract feedback signals from sqlmap output streams."""
    return extract_attack_signals(f"{stdout}\n{stderr}")


def annotate_findings_with_feedback(
    findings: list[WebScanFinding], signals: list[AttackSignal]
) -> list[WebScanFinding]:
    """Attach hint/block metadata to SQL injection findings."""
    if not findings or not signals:
        return findings

    hints = summarize_signals(signals, "hint", limit=3)
    blocks = summarize_signals(signals, "block", limit=3)
    policy = decide_attack_policy(signals)
    for finding in findings:
        raw = dict(finding.raw or {})
        if hints:
            raw["feedback_hints"] = hints
        if blocks:
            raw["feedback_blocks"] = blocks
        raw["feedback_policy"] = policy.action
        raw["feedback_reason"] = policy.reason
        finding.raw = raw

        feedback_parts: list[str] = []
        if hints:
            feedback_parts.append(f"hints={'; '.join(hints[:2])}")
        if blocks:
            feedback_parts.append(f"blocks={'; '.join(blocks[:2])}")
        if feedback_parts:
            if finding.evidence:
                finding.evidence += "\n"
            finding.evidence += f"Response feedback: {' | '.join(feedback_parts)}"
    return findings


def build_feedback_findings(
    signals: list[AttackSignal],
    target: str,
    tool_name: str,
) -> list[WebScanFinding]:
    """Create informational findings when only feedback signals are available."""
    if not signals:
        return []

    hints = summarize_signals(signals, "hint", limit=3)
    blocks = summarize_signals(signals, "block", limit=3)
    if not hints and not blocks:
        return []

    policy = decide_attack_policy(signals)
    evidence_parts: list[str] = []
    if hints:
        evidence_parts.append(f"hints={'; '.join(hints)}")
    if blocks:
        evidence_parts.append(f"blocks={'; '.join(blocks)}")

    title = (
        "sqlmap observed defensive response signals"
        if blocks
        else "sqlmap observed SQL response hints"
    )
    severity = "info" if blocks else "low"
    description = (
        "sqlmap output indicates target-side blocking/throttling behavior."
        if blocks
        else "sqlmap output includes SQL/backend hints that can refine attack vectors."
    )
    return [
        WebScanFinding(
            tool=tool_name,
            title=title,
            severity=severity,
            description=description,
            url=target,
            attack_type="Attack Feedback",
            evidence=" | ".join(evidence_parts),
            raw={
                "feedback_hints": hints,
                "feedback_blocks": blocks,
                "feedback_policy": policy.action,
                "feedback_reason": policy.reason,
            },
        )
    ]
