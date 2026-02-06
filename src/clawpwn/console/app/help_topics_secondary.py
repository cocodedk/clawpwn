"""Secondary console help topic content."""

HELP_TOPICS_SECONDARY: dict[str, str] = {
    "objective": """[bold]Objective[/bold]
Set or view the current objective for this project.

Commands:
  [cyan]objective show[/cyan]
  [cyan]objective set "focus text"[/cyan]
  [cyan]objective clear[/cyan]

Tips:
  - Keep it short and specific
  - Used by NLI as context""",
    "memory": """[bold]Memory[/bold]
Show or clear the project memory summary and recent messages.

Commands:
  [cyan]memory show[/cyan]
  [cyan]memory show --limit 8[/cyan]
  [cyan]memory clear[/cyan]

Notes:
  - Old messages are summarized automatically
  - NLI uses memory context only when the request depends on prior conversation""",
    "status": """[bold]Status[/bold]
Show current project phase, target, and findings summary:
  [cyan]status[/cyan]

Use it to:
  - Confirm target and phase
  - See finding counts by severity
  - Check overall progress

Tips:
  - Run after [cyan]scan[/cyan] to verify results were saved
  - Pair with [cyan]logs[/cyan] for recent actions""",
    "logs": """[bold]Logs[/bold]
Show recent actions and errors:
  [cyan]logs[/cyan]

Filters:
  [cyan]logs --limit 100[/cyan]
  [cyan]logs --level INFO|WARNING|ERROR[/cyan]

Use it to:
  - Trace what happened in a run
  - Investigate failures or timeouts
  - Keep a quick audit trail""",
    "config": """[bold]Config[/bold]
Edit or view configuration:
  [cyan]config show[/cyan]
  [cyan]config edit[/cyan]

Notes:
  - Project config lives under the project data folder
  - Global config is stored in [cyan]~/.clawpwn[/cyan]
  - LLM settings are stored in the project config

Tip:
  - Use [cyan]config show[/cyan] before running NLI""",
    "init": """[bold]Initialize a project[/bold]
Create a new project structure in the current folder:
  [cyan]clawpwn init[/cyan]

Creates:
  - [cyan].clawpwn[/cyan] marker
  - [cyan]evidence/[/cyan], [cyan]exploits/[/cyan], [cyan]report/[/cyan]
  - Project database and config template

Next steps:
  [cyan]target https://example.com[/cyan]
  [cyan]scan --depth normal[/cyan]""",
    "evidence": """[bold]Evidence handling[/bold]
Store artifacts that support findings:
  - Screenshots, logs, captured requests
  - Command output and proof-of-exploit

Where:
  [cyan]evidence/[/cyan] in the project directory

Tips:
  - Name files with the finding ID or service
  - Keep originals; include sanitized copies if needed
  - Use [cyan]report --include-evidence[/cyan] to embed""",
    "lan": """[bold]LAN discovery[/bold]
Discover live hosts on a local network range.

Basic:
  [cyan]lan --range 192.168.1.0/24[/cyan]

Scan discovered hosts:
  [cyan]lan --range 192.168.1.0/24 --scan-hosts[/cyan]

Options:
  [cyan]--depth[/cyan] quick|normal|deep
  [cyan]--scanner[/cyan] rustscan|masscan|nmap
  [cyan]--concurrency[/cyan] 5
  [cyan]--max-hosts[/cyan] 50
  [cyan]--verify-tcp[/cyan] (service detection)
  [cyan]--udp[/cyan] or [cyan]--udp-full[/cyan]

Notes:
  - In the console, use [cyan]lan[/cyan] or [cyan]discover[/cyan]
  - For CLI outside the console, [cyan]clawpwn discover[/cyan] is an alias
  - If permissions are missing, see [cyan]help permissions[/cyan]
  - NLI: [cyan]?discover hosts on 192.168.1.0/24[/cyan]""",
    "recon": """[bold]Reconnaissance[/bold]
Recon builds the target map before deeper testing.

Common steps:
  1) Identify hosts and services
  2) Enumerate open ports and versions
  3) Detect web services and entry points

Suggested flow:
  [cyan]lan --range 192.168.1.0/24[/cyan]
  [cyan]scan --depth quick[/cyan]
  [cyan]scan --depth normal[/cyan]
  Review findings in [cyan]status[/cyan]""",
}
