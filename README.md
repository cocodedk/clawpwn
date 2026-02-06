# ClawPwn

AI-assisted penetration testing toolkit with a natural language interface and an operator-first workflow.

GitHub Pages: https://cocodedk.github.io/clawpwn/

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

## Installation (End Users)

For a global install and optional scanner setup:

```bash
./install.sh
```

Installer behavior:
- Installs ClawPwn via `uv tool install .`
- Installs network scanners: `nmap`, `masscan`, `rustscan`
- Attempts web scanner installs: `nuclei`, `feroxbuster`, `ffuf`, `nikto`, and ZAP support (`zap-baseline.py`/`docker`)
- Configures Linux scanner permissions via sudoers (see below)

## Permissions

On Linux, `install.sh` creates `/etc/sudoers.d/clawpwn-scanners` so `nmap`, `masscan`, and `rustscan` can run with passwordless sudo when needed.

To remove this later:

```bash
sudo rm -f /etc/sudoers.d/clawpwn-scanners
sudo visudo -c
```

## Setup Script

```bash
./setup.sh
```

This installs `uv`, syncs dev dependencies, and installs pre-commit hooks.

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
uv sync --extra dev
uv run pre-commit install
```

The pre-commit hook runs `uv run pytest` before each commit.

## Environment

Copy `.env.example` to `.env` and fill in the values you need.

## Commit Messages

Use Conventional Commits so releases are automated correctly.

- `feat:` new feature (minor bump)
- `fix:` bug fix (patch bump)
- `feat!:` or `fix!:` breaking change (major bump)
- `chore:` or `docs:` for non-release changes

Example:

```text
feat: add target validation
```

## Safety

ClawPwn is intended for authorized security testing only. Always obtain written permission and follow local laws.

## License

MIT. See `LICENSE`.
