"""Operational help topics for NLI and console guidance."""

HELP_TOPICS_OPS: dict[str, str] = {
    "objective": """Objective:
Set or view the current objective for this project.

Commands:
  objective show
  objective set "focus text"
  objective clear

Tips:
  - Keep it short and specific
  - Used by NLI as context""",
    "memory": """Memory:
Show or clear the project memory summary and recent messages.

Commands:
  memory show
  memory show --limit 8
  memory clear

Notes:
  - Old messages are summarized automatically
  - NLI uses memory context only when the request depends on prior conversation""",
    "status": """Status:
Show current project phase, target, and findings summary:
  status

Use it to:
  - Confirm target and phase
  - See finding counts by severity
  - Check overall progress

Tips:
  - Run after scan to verify results were saved
  - Pair with logs for recent actions""",
    "logs": """Logs:
Show recent actions and errors:
  logs

Filters:
  logs --limit 100
  logs --level INFO|WARNING|ERROR

Use it to:
  - Trace what happened in a run
  - Investigate failures or timeouts
  - Keep a quick audit trail""",
    "config": """Config:
Edit or view configuration:
  config show
  config edit

Notes:
  - Project config lives under the project data folder
  - Global config is stored in ~/.clawpwn
  - LLM settings are stored in the project config

Tip:
  - Use config show before running NLI""",
    "init": """Initialize a project:
Create a new project structure in the current folder:
  clawpwn init

Creates:
  - .clawpwn marker
  - evidence/, exploits/, report/
  - Project database and config template

Next steps:
  target https://example.com
  scan --depth normal""",
    "evidence": """Evidence handling:
Store artifacts that support findings:
  - Screenshots, logs, captured requests
  - Command output and proof-of-exploit

Where:
  evidence/ in the project directory

Tips:
  - Name files with the finding ID or service
  - Keep originals; include sanitized copies if needed
  - Use report --include-evidence to embed""",
    "lan": """LAN discovery:
Discover live hosts on a local network range.

Basic:
  lan --range 192.168.1.0/24

Scan discovered hosts:
  lan --range 192.168.1.0/24 --scan-hosts

Options:
  --depth quick|normal|deep
  --scanner rustscan|masscan|nmap|naabu
  --concurrency 5
  --max-hosts 50
  --verify-tcp (service detection)
  --udp or --udp-full

Notes:
  - In the console, use lan or discover
  - CLI alias: clawpwn discover
  - If permissions are missing, see help permissions
  - NLI: ?discover hosts on 192.168.1.0/24""",
    "recon": """Reconnaissance:
Recon builds the target map before deeper testing.

Common steps:
  1) Identify hosts and services
  2) Enumerate open ports and versions
  3) Detect web services and entry points

Suggested flow:
  lan --range 192.168.1.0/24
  scan --depth quick
  scan --depth normal
  Review findings in status""",
}
