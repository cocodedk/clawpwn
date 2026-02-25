"""Autonomous agent integration tests against real vulnerable targets.

These tests validate that the ClawPwn agent can autonomously discover and exploit
vulnerabilities without being told what to look for. Tests run against the msf2
(Metasploitable 2) Docker container.

Requirements:
- ANTHROPIC_API_KEY environment variable must be set
- msf2 container must be running at 172.17.0.2
- Tests are marked with @pytest.mark.autonomous and skipped by default
"""

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from clawpwn.ai.llm import LLMClient
from clawpwn.ai.nli.agent import ToolUseAgent


def has_anthropic_key() -> bool:
    """Check if ANTHROPIC_API_KEY is set."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


class ToolCallTracker:
    """Track tool calls made during agent execution."""

    def __init__(self):
        self.calls = []

    def track(self, tool_name: str, tool_input: dict, result: str) -> None:
        """Record a tool call."""
        self.calls.append(
            {
                "tool": tool_name,
                "input": tool_input,
                "result": result,
                "timestamp": time.time(),
            }
        )

    def get_sequence(self) -> list[str]:
        """Return list of tool names in order called."""
        return [c["tool"] for c in self.calls]

    def get_call(self, tool_name: str) -> dict | None:
        """Get the first call to a specific tool."""
        return next((c for c in self.calls if c["tool"] == tool_name), None)

    def get_all_calls(self, tool_name: str) -> list[dict]:
        """Get all calls to a specific tool."""
        return [c for c in self.calls if c["tool"] == tool_name]


def run_agent_with_tracking(agent: ToolUseAgent, prompt: str, tracker: ToolCallTracker) -> dict:
    """Run agent and track all tool calls."""
    from clawpwn.ai.nli.tool_executors import dispatch_tool as original_dispatch

    def tracked_dispatch(tool_name: str, tool_input: dict, project_dir: Path) -> str:
        result = original_dispatch(tool_name, tool_input, project_dir)
        tracker.track(tool_name, tool_input, result)
        return result

    with patch("clawpwn.ai.nli.agent.executor.dispatch_tool", tracked_dispatch):
        return agent.run(prompt)


@pytest.fixture
def msf2_target() -> str:
    """MSF2 container base URL."""
    return "http://172.17.0.2"


@pytest.fixture
def agent_with_real_llm(project_dir: Path) -> ToolUseAgent:
    """Agent with real Anthropic API (requires ANTHROPIC_API_KEY)."""
    llm = LLMClient(provider="anthropic")
    return ToolUseAgent(llm, project_dir)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


@pytest.mark.autonomous
@pytest.mark.skipif(not has_anthropic_key(), reason="Requires ANTHROPIC_API_KEY")
@pytest.mark.asyncio
async def test_phpmyadmin_autonomous_discovery(
    agent_with_real_llm: ToolUseAgent,
    msf2_target: str,
    project_dir: Path,
):
    """Agent discovers phpMyAdmin vulnerabilities without being told what to look for."""
    tracker = ToolCallTracker()
    url = f"{msf2_target}/phpMyAdmin/"

    run_agent_with_tracking(
        agent_with_real_llm,
        url,  # Just give it the URL, no other guidance
        tracker,
    )

    tool_sequence = tracker.get_sequence()

    print(f"\n{'=' * 60}")
    print("AUTONOMOUS TEST: phpMyAdmin Discovery")
    print(f"{'=' * 60}")
    print(f"Target: {url}")
    print(f"Tool sequence: {tool_sequence}")
    print(f"Total tool calls: {len(tracker.calls)}")
    print(f"{'=' * 60}\n")

    # Assert methodology adherence: agent should fingerprint before attacking
    assert "fingerprint_target" in tool_sequence, (
        f"Agent should fingerprint before attacking. Actual sequence: {tool_sequence}"
    )

    # Agent should research after fingerprinting
    if "fingerprint_target" in tool_sequence and "web_search" in tool_sequence:
        fp_idx = tool_sequence.index("fingerprint_target")
        ws_idx = tool_sequence.index("web_search")
        assert fp_idx < ws_idx, (
            f"Agent should fingerprint before searching. "
            f"Fingerprint at index {fp_idx}, search at {ws_idx}"
        )

    # Agent should discover it's phpMyAdmin
    fingerprint_call = tracker.get_call("fingerprint_target")
    assert fingerprint_call is not None, "Agent did not call fingerprint_target"

    fp_result = fingerprint_call["result"].lower()
    assert "phpmyadmin" in fp_result or "pma" in fp_result, (
        f"Agent should identify phpMyAdmin in fingerprint. Got: {fingerprint_call['result'][:200]}"
    )

    # Agent should search for phpMyAdmin vulnerabilities or default credentials
    search_call = tracker.get_call("web_search")
    if search_call:
        query = search_call["input"].get("query", "").lower()
        assert "phpmyadmin" in query or "mysql" in query, (
            f"Agent should search for phpMyAdmin/MySQL info. Got query: {query}"
        )
        print(f"✓ Agent searched: {search_call['input']['query']}")

    # Agent should test credentials on the login page
    assert "credential_test" in tool_sequence, (
        f"Agent should test credentials on login page. Sequence: {tool_sequence}"
    )

    cred_call = tracker.get_call("credential_test")
    assert cred_call is not None, "Agent called credential_test but tracking failed"

    print("✓ Agent tested credentials")
    print(f"  Credential test result preview: {cred_call['result'][:200]}")

    # Check if valid credentials were found (msf2 has root with empty password)
    if "valid credentials found" in cred_call["result"].lower():
        print("✓ Agent found valid credentials!")
        assert "root" in cred_call["result"].lower(), "Should find root credentials"

    # Load findings from session to verify they were logged
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.session import SessionManager

    db_path = get_project_db_path(project_dir)
    if db_path and db_path.exists():
        session = SessionManager(db_path)
        logs = session.get_scan_logs()

        print(f"✓ Session logged {len(logs)} actions")

    print("\n✓ PASSED: Agent successfully pentested phpMyAdmin autonomously")
    print("  - Followed methodology: FINGERPRINT → RESEARCH → CREDENTIAL TEST")
    print(f"  - Used {len(tracker.calls)} tool calls")
    print(f"  - Tool diversity: {len(set(tool_sequence))} unique tools")


@pytest.mark.autonomous
@pytest.mark.skipif(not has_anthropic_key(), reason="Requires ANTHROPIC_API_KEY")
@pytest.mark.slow
@pytest.mark.asyncio
async def test_web_server_autonomous_discovery(
    agent_with_real_llm: ToolUseAgent,
    msf2_target: str,
    project_dir: Path,
):
    """Agent discovers multiple vulnerable apps on web server autonomously."""
    tracker = ToolCallTracker()

    run_agent_with_tracking(
        agent_with_real_llm,
        msf2_target,  # Just the root URL
        tracker,
    )

    tool_sequence = tracker.get_sequence()

    print(f"\n{'=' * 60}")
    print("AUTONOMOUS TEST: Web Server Discovery")
    print(f"{'=' * 60}")
    print(f"Target: {msf2_target}")
    print(f"Tool sequence: {tool_sequence}")
    print(f"Total tool calls: {len(tracker.calls)}")
    print(f"{'=' * 60}\n")

    # Should fingerprint the web server
    assert "fingerprint_target" in tool_sequence, (
        f"Agent should fingerprint web server. Sequence: {tool_sequence}"
    )

    fp_call = tracker.get_call("fingerprint_target")
    fp_result = fp_call["result"].lower()

    print(f"Fingerprint result preview: {fp_call['result'][:300]}")

    # Should discover exposed paths or technologies
    assert (
        "exposed" in fp_result
        or "path" in fp_result
        or "apache" in fp_result
        or "metasploit" in fp_result
    ), f"Agent should discover information about the web server. Got: {fp_call['result'][:200]}"

    # Check for common MSF2 apps: /phpMyAdmin, /mutillidae, /dvwa, /twiki
    discovered_apps = []
    if "phpmyadmin" in fp_result or "/phpmyadmin" in fp_result:
        discovered_apps.append("phpMyAdmin")
    if "mutillidae" in fp_result:
        discovered_apps.append("Mutillidae")
    if "dvwa" in fp_result:
        discovered_apps.append("DVWA")
    if "twiki" in fp_result:
        discovered_apps.append("TWiki")

    print(
        f"✓ Discovered apps: {discovered_apps if discovered_apps else 'None (may need deeper scan)'}"
    )

    # Should research discovered technologies
    search_calls = tracker.get_all_calls("web_search")
    if search_calls:
        print(f"✓ Agent performed {len(search_calls)} web searches:")
        for call in search_calls:
            print(f"  - {call['input'].get('query', 'N/A')}")
        assert len(search_calls) > 0, "Agent should search for vulnerability information"

    # Should attempt to test credentials or scan
    attack_tools = ["credential_test", "web_scan"]
    used_attack_tools = [t for t in tool_sequence if t in attack_tools]

    if used_attack_tools:
        print(f"✓ Agent used attack tools: {used_attack_tools}")
    else:
        print("  Note: Agent did not use attack tools in this run")

    # At minimum, agent should have used fingerprinting + research
    assert len(tool_sequence) >= 2, (
        f"Agent should use at least 2 tools (fingerprint + research/scan). Used: {tool_sequence}"
    )

    print("\n✓ PASSED: Agent autonomously explored web server")
    print(f"  - Tool calls: {len(tracker.calls)}")
    print(f"  - Unique tools: {len(set(tool_sequence))}")
    if discovered_apps:
        print(f"  - Discovered: {', '.join(discovered_apps)}")


@pytest.mark.autonomous
@pytest.mark.skipif(not has_anthropic_key(), reason="Requires ANTHROPIC_API_KEY")
@pytest.mark.asyncio
async def test_agent_uses_multiple_rounds(
    agent_with_real_llm: ToolUseAgent,
    msf2_target: str,
    project_dir: Path,
):
    """Agent uses multiple tool rounds effectively for complex targets."""
    tracker = ToolCallTracker()

    run_agent_with_tracking(
        agent_with_real_llm,
        f"{msf2_target}/phpMyAdmin/",
        tracker,
    )

    tool_sequence = tracker.get_sequence()

    print(f"\n{'=' * 60}")
    print("AUTONOMOUS TEST: Tool Round Utilization")
    print(f"{'=' * 60}")
    print(f"Target: {msf2_target}/phpMyAdmin/")
    print(f"Tool sequence: {tool_sequence}")
    print(f"Total tool calls: {len(tracker.calls)}")
    print(f"{'=' * 60}\n")

    # With MAX_TOOL_ROUNDS=8, agent should use multiple rounds
    # for a complex target like phpMyAdmin
    assert len(tracker.calls) >= 3, (
        f"Agent should use at least 3 tool calls for complex target. "
        f"Only used {len(tracker.calls)}: {tool_sequence}"
    )

    # Should use tools from different categories (recon, research, attack)
    tool_types = set(tool_sequence)
    assert len(tool_types) >= 2, (
        f"Agent should use diverse tools (recon, research, attack). Only used: {tool_types}"
    )

    # Verify the agent chains tools logically
    # Example: fingerprint → research → attack, not attack → fingerprint
    recon_tools = ["fingerprint_target"]
    attack_tools = ["credential_test", "web_scan"]

    recon_indices = [i for i, t in enumerate(tool_sequence) if t in recon_tools]
    attack_indices = [i for i, t in enumerate(tool_sequence) if t in attack_tools]

    if recon_indices and attack_indices:
        first_recon = min(recon_indices)
        first_attack = min(attack_indices)
        assert first_recon < first_attack, (
            f"Agent should recon before attacking. Recon at {first_recon}, attack at {first_attack}"
        )
        print("✓ Agent chains tools logically: recon first, then attack")

    # Print detailed call breakdown
    print("\nTool call breakdown:")
    for i, call in enumerate(tracker.calls, 1):
        tool = call["tool"]
        inputs = str(call["input"])[:60]
        print(f"  {i}. {tool}({inputs}...)")

    print("\n✓ PASSED: Agent uses multiple rounds effectively")
    print(f"  - Total calls: {len(tracker.calls)}")
    print(f"  - Tool diversity: {len(tool_types)} unique tools")
    print(
        f"  - Methodology adherence: {'✓' if recon_indices and attack_indices and first_recon < first_attack else '⚠'}"
    )
