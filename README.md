# ClawPwn

AI-assisted penetration testing toolkit with a natural language interface and an operator-first workflow.

GitHub Pages: https://cocodedk.github.io/pentest-tool/

## What It Is

ClawPwn is designed for structured offensive security work. It keeps human intent in the loop, maps tasks to modules, and produces a clear audit trail.

## Key Features

- Natural language + CLI control
- Modular pipeline (scanner, proxy, exploit, vuln-db, reporting)
- Project-local SQLite storage
- Rich terminal UI with reproducible findings

## Quick Start

```bash
# Create and enter a project folder
mkdir ~/pentest/target-site
cd ~/pentest/target-site

# Initialize project
clawpwn init

# Set target
clawpwn target https://example.com

# Interactive mode
clawpwn
```

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Build
uv build
```

## Pre-commit

```bash
uv sync
uv run pre-commit install
```

The pre-commit hook runs `uv run pytest` before each commit.

## Safety

ClawPwn is intended for authorized security testing only. Always obtain written permission and follow local laws.

## License

MIT. See `LICENSE`.
