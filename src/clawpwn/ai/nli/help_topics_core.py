"""Core help topics for NLI and console guidance."""

HELP_TOPICS_CORE: dict[str, str] = {
    "workflow": """Authorized pentest workflow:
  1. Confirm written authorization and scope
  2. Initialize a project: clawpwn init
  3. Set target: target https://example.com
  4. Discover and scan: scan --depth normal
  5. Validate findings: killchain or manual verification
  6. Collect evidence in evidence/
  7. Generate report: report --format html
  8. Review remediation notes before delivery

Good practice:
  - Use one project per target or scope
  - Start with quick/normal depth before deep scans
  - Keep an audit trail with status and logs
  - Save screenshots and logs in evidence/
  - NLI enforces target scope; change target explicitly if needed

See also:
  help scan, help report, help permissions""",
    "scan": """Scanning:
Prerequisites:
  - Target set: target https://example.com
  - Scanner permissions (see help permissions)

Examples:
  scan --depth quick        Fast pass
  scan --depth normal       Default
  scan --depth deep         Full scan (slower)
  scan --scanner nmap       Use a different scanner
  scan --udp-full           Full UDP range (slow)
  scan --web-tools all      Run builtin+nuclei+feroxbuster+ffuf+nikto+searchsploit+zap
  scan --web-timeout 90     Increase timeout for slower web tools
  scan --web-concurrency 20 Increase web worker threads
  scan --auto               AI-guided scan
  scan --verbose            More output

Tips:
  - Use URLs for web targets, IPs for infra targets
  - Start shallow, then go deeper on confirmed services
  - For web targets, start with --web-tools builtin,nuclei,feroxbuster
  - Results show in status; details in reports
  - --verbose shows live tool progress and external commands
  - For host/IP scans from NLI, default profile is robust:
    scanner=nmap, depth=deep, verify_tcp=true, verbose=true
  - NLI prints what it runs plus a CLI equivalent line

Full options: !scan --help""",
    "target": """Targeting:
Set the target for this project:
  target https://example.com

Notes:
  - Include a scheme (http/https) for web targets
  - For IP targets, use the raw IP or hostname
  - One target per project is recommended

Override for a single run:
  killchain --target https://example.com

Verify:
  status shows the current target""",
    "killchain": """Kill chain:
End-to-end AI-guided workflow across phases:
  Recon -> Enumeration -> Vulnerability Research -> Exploitation -> Post

Start:
  killchain

Modes:
  - Default: AI-assisted (asks before high-risk actions)
  - Auto: killchain --auto (AI decides)

Tips:
  - Run scan first to seed findings
  - Keep approvals in scope and documented
  - Use logs for an activity trail""",
    "report": """Reporting:
Generate a report from findings:
  report --format html

Other formats:
  report --format pdf|json|md

Options:
  --include-evidence (default) or --no-evidence

Tips:
  - If the report is thin, run scan and re-check findings
  - Evidence files live in evidence/
  - Report location is printed after generation""",
    "permissions": """Scanner permissions:
Port scanners may need raw socket access.

Options:
  1) Run installer: ./install.sh
  2) Or run scans with sudo: sudo clawpwn scan

Notes:
  - Capabilities are Linux-only
  - The installer asks before changing permissions
  - When permissions are missing, the tool prints fixes""",
    "nli": """Natural language mode:
Ask questions in plain English:
  ?scan the target deeply
  ?show findings
  ?how do I generate a report

Modes:
  - mode nli forces natural language
  - mode cli forces commands
  - mode auto (default) detects intent

Notes:
  - NLI requires a project and LLM config
  - If NLI is unavailable, use CLI commands
  - For troubleshooting: enable debug (see help debug)
  - For scan progress: enable verbose (see help verbose)""",
    "verbose": """Verbose mode:
Show live scan progress (discovered ports, scanner output) in your current console session.

Commands:
  enable verbose    Turn on verbose output
  disable verbose   Turn off verbose output

When enabled, port scanners stream results as they run:
  [naabu] found 10.0.0.1:22
  [naabu] found 10.0.0.1:80
  [verbose] Naabu exit code: 0 (5.32s)

Also settable via environment variable:
  CLAWPWN_VERBOSE=1 clawpwn console""",
    "debug": """Debug mode:
Enable detailed visibility into NLI agent decisions in your current console session.

Commands:
  enable debug    Turn on debug logging
  disable debug   Turn off debug logging

What debug mode shows:
  - LLM requests: model used, system prompt size, tools available, user message
  - LLM responses: stop reason, content types (text/tool_use), token usage (input/output)
  - Agent decisions: round number, project context, fast-path choices
  - Tool execution: tool name, parameters, execution time, result size

Example session:
  clawpwn> enable debug
  ✓ Debug mode enabled

  clawpwn> scan http://example.com

  [DEBUG:llm] → claude-3-5-sonnet-20241022 (max_tokens=1024)
    System: 485 chars
    Tools: web_scan, network_scan, check_status, +6 more

  [DEBUG:llm] ← stop_reason=tool_use
    Content: tool_use
    Tokens: 1245↓/87↑/1332 total

  → web_scan(target='http://example.com', depth='normal')

  [DEBUG:tool] dispatch_tool(web_scan) +0.0s
    Params: {target: 'http://example.com', ...}

  [DEBUG:tool] dispatch_tool(web_scan) completed +12.3s
    Result: 234 chars

  clawpwn> disable debug
  ✓ Debug mode disabled

Tips:
  - Debug mode is per-session (doesn't persist across restarts)
  - Use when commands aren't behaving as expected
  - Helpful for understanding which tools the agent chooses and why""",
    "console": """Console command:
The interactive console cannot be started from inside itself.

Why:
  - Prevents nested sessions that require multiple exits
  - Avoids confusing input routing

If you need a new console:
  - Open a new terminal and run clawpwn
  - Or use restart in the current console""",
}
