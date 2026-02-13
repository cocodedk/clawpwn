"""Context enrichment and plan revision helpers."""

from __future__ import annotations

import re
from typing import Any

# Matches lines like "  21/tcp: vsftpd 2.3.4" from network scan output.
_SVC_LINE_RE = re.compile(r"(\d+)/\w+:\s+(.+)")


def _extract_services(context: dict[str, Any], text: str) -> None:
    services = context.setdefault("services", [])
    seen = {(s["port"], s["product"]) for s in services}
    for match in _SVC_LINE_RE.finditer(text):
        port = int(match.group(1))
        product_version = match.group(2).strip()
        if (port, product_version) in seen:
            continue
        seen.add((port, product_version))
        services.append({"port": port, "product": product_version})


def enrich_context(context: dict[str, Any], tier_results: list[dict[str, Any]]) -> None:
    """Extract context from tier results (app hints, technologies, services)."""
    for result in tier_results:
        text = result.get("result_text", "").lower()
        if result.get("tool") == "fingerprint_target":
            for app in ("phpmyadmin", "wordpress", "joomla", "jenkins", "grafana"):
                if app in text:
                    context["app_hint"] = app
                    break
            for tech in ("php", "apache", "nginx", "mysql", "postgresql", "python", "node"):
                if tech in text and tech not in context.get("techs", []):
                    context.setdefault("techs", []).append(tech)
        if "network_scan" in (result.get("tool_name", ""), result.get("tool", "")):
            _extract_services(context, text)


def revision_reason(tier_results: list[dict[str, Any]]) -> str:
    """Build a reason string for plan revision."""
    n_fail = sum(1 for r in tier_results if r.get("failed"))
    if n_fail:
        return f"{n_fail}/{len(tier_results)} steps failed"
    if any(r.get("policy_action") in ("stop_and_replan", "stop") for r in tier_results):
        return "Attack feedback signals indicate blocking/WAF"
    return "Results suggest plan adjustment needed"
