"""Primary console help topic content."""

HELP_TOPICS_PRIMARY: dict[str, str] = {
    "workflow": """[bold]Authorized pentest workflow[/bold]
  1. Confirm written authorization and scope
  2. Initialize a project: [cyan]clawpwn init[/cyan]
  3. Set target: [cyan]target https://example.com[/cyan]
  4. Discover and scan: [cyan]scan --depth normal[/cyan]
  5. Validate findings: [cyan]killchain[/cyan] or manual verification
  6. Collect evidence in [cyan]evidence/[/cyan]
  7. Generate report: [cyan]report --format html[/cyan]
  8. Review remediation notes before delivery

Good practice:
  - Use one project per target or scope
  - Start with quick/normal depth before deep scans
  - Keep an audit trail with [cyan]status[/cyan] and [cyan]logs[/cyan]
  - Save screenshots and logs in [cyan]evidence/[/cyan]
  - NLI enforces target scope; change target explicitly if needed

See also:
  [cyan]help scan[/cyan], [cyan]help report[/cyan], [cyan]help permissions[/cyan]""",
    "scan": """[bold]Scanning[/bold]
Prerequisites:
  - Target set: [cyan]target https://example.com[/cyan]
  - Scanner permissions (see [cyan]help permissions[/cyan])

Examples:
  [cyan]scan --depth quick[/cyan]        Fast pass
  [cyan]scan --depth normal[/cyan]       Default
  [cyan]scan --depth deep[/cyan]         Full scan (slower)
  [cyan]scan --scanner nmap[/cyan]       Use a different scanner
  [cyan]scan --udp-full[/cyan]           Full UDP range (slow)
  [cyan]scan --auto[/cyan]               AI-guided scan
  [cyan]scan --verbose[/cyan]            More output

Tips:
  - Use URLs for web targets, IPs for infra targets
  - Start shallow, then go deeper on confirmed services
  - Results show in [cyan]status[/cyan]; details in reports
  - In NLI host/IP scans, default profile is robust:
    [cyan]nmap + deep + verify_tcp + verbose[/cyan]
  - NLI prints an action line and [cyan]CLI equivalent[/cyan]

Full options: [cyan]!scan --help[/cyan]""",
    "target": """[bold]Targeting[/bold]
Set the target for this project:
  [cyan]target https://example.com[/cyan]

Notes:
  - Include a scheme (http/https) for web targets
  - For IP targets, use the raw IP or hostname
  - One target per project is recommended

Override for a single run:
  [cyan]killchain --target https://example.com[/cyan]

Verify:
  [cyan]status[/cyan] shows the current target""",
    "killchain": """[bold]Kill chain[/bold]
End-to-end AI-guided workflow across phases:
  Recon -> Enumeration -> Vulnerability Research -> Exploitation -> Post

Start:
  [cyan]killchain[/cyan]

Modes:
  - Default: AI-assisted (asks before high-risk actions)
  - Auto: [cyan]killchain --auto[/cyan] (AI decides)

Tips:
  - Run [cyan]scan[/cyan] first to seed findings
  - Keep approvals in scope and documented
  - Use [cyan]logs[/cyan] for an activity trail""",
    "report": """[bold]Reporting[/bold]
Generate a report from findings:
  [cyan]report --format html[/cyan]

Other formats:
  [cyan]report --format pdf|json|md[/cyan]

Options:
  [cyan]--include-evidence[/cyan] (default) or [cyan]--no-evidence[/cyan]

Tips:
  - If the report is thin, run [cyan]scan[/cyan] and re-check findings
  - Evidence files live in [cyan]evidence/[/cyan]
  - Report location is printed after generation""",
    "permissions": """[bold]Scanner permissions[/bold]
Port scanners may need raw socket access.

Options:
  1. Run installer: [cyan]./install.sh[/cyan]
  2. Or run scans with sudo: [cyan]sudo clawpwn scan[/cyan]

Notes:
  - Capabilities are Linux-only
  - The installer asks before changing permissions
  - When permissions are missing, the tool prints fixes""",
    "nli": """[bold]Natural language mode[/bold]
Ask questions in plain English:
  [cyan]?scan the target deeply[/cyan]
  [cyan]?show findings[/cyan]
  [cyan]?how do I generate a report[/cyan]
  [cyan]?how do I restart console[/cyan]

Modes:
  - [cyan]mode nli[/cyan] forces natural language
  - [cyan]mode cli[/cyan] forces commands
  - [cyan]mode auto[/cyan] (default) detects intent

Notes:
  - NLI requires a project and LLM config
  - Help can be searched in natural language (no "help" keyword required)
  - If NLI is unavailable, use CLI commands""",
    "console": """[bold]Console command[/bold]
The interactive console cannot be started from inside itself.

Why:
  - Prevents nested sessions that require multiple exits
  - Avoids confusing input routing

If you need a new console:
  - Open a new terminal and run [cyan]clawpwn[/cyan]
  - Or use [cyan]restart[/cyan] in the current console""",
}
