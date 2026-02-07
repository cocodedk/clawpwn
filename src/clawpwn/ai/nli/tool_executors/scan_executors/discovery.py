"""Host discovery executor for NLI tool agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clawpwn.utils.async_utils import safe_async_run


def execute_discover_hosts(params: dict[str, Any], project_dir: Path) -> str:
    """Discover live hosts on a CIDR range."""
    from clawpwn.config import get_project_db_path
    from clawpwn.modules.network import NetworkDiscovery
    from clawpwn.modules.session import SessionManager

    network = params["network"]
    discovery = NetworkDiscovery(project_dir)
    try:
        hosts = safe_async_run(discovery.discover_hosts(network))
        max_hosts = params.get("max_hosts", 256)
        if max_hosts and len(hosts) > max_hosts:
            hosts = hosts[:max_hosts]

        # Log the discovery action
        try:
            db_path = get_project_db_path(project_dir)
            if db_path:
                session = SessionManager(db_path)
                session.add_log(
                    message=f"discover_hosts: {network} -> {len(hosts)} hosts",
                    level="INFO",
                    phase="scan",
                    details=json.dumps(
                        {
                            "tool": "discover_hosts",
                            "network": network,
                            "hosts_count": len(hosts),
                            "hosts": hosts[:10],  # Limit for size
                        }
                    ),
                )
        except Exception:
            pass

        preview = ", ".join(hosts[:10])
        suffix = f" ... ({len(hosts)} total)" if len(hosts) > 10 else ""
        return f"Found {len(hosts)} live hosts on {network}: {preview}{suffix}"
    except Exception as exc:
        return f"Discovery failed: {exc}"
