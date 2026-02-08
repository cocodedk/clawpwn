# ClawPwn

AI-assisted penetration testing toolkit with a CLI-first workflow and an optional natural language console.

GitHub Pages: https://cocodedk.github.io/clawpwn/

## What It Does

ClawPwn helps you run structured, auditable security assessments by combining:

- Project-scoped state and findings storage
- Network and web scanning workflows
- AI-assisted orchestration and natural language control
- Report generation and operator logs

## Core Capabilities

- CLI commands for recon, scanning, reporting, and project management
- Interactive console with `CLI`, `NLI`, and `AUTO` input routing
- AI tool-use workflow (Anthropic path) with methodology guidance:
  fingerprint -> research -> scan -> credential test -> escalate
- Modular web scanner orchestration with plugin-based external tool support
- Per-project SQLite storage for operational state
- Automated provisioning of a centralized Postgres experience database

## Installation (Automated)

Run:

```bash
./install.sh
```

`install.sh` automates all required setup steps:

1. Installs `uv` and Rust toolchain (`cargo`) when missing
2. Installs ClawPwn (`uv tool install . --force --reinstall --refresh`)
3. Installs network scanners (`nmap`, `masscan`, `rustscan`)
4. Installs web scanners and helpers (`nuclei`, `feroxbuster`, `ffuf`, `hydra`, `nikto`, `searchsploit`, `sqlmap`, `wpscan`, `testssl`, `zap` support) and provisions credential wordlists
5. Configures Linux scanner sudoers (`/etc/sudoers.d/clawpwn-scanners`) for passwordless scanner execution
6. Provisions centralized Postgres (`pgvector/pgvector:pg16`) via Docker Compose
7. Creates persistent external Docker volume `clawpwn_pgdata` and applies schema + seed SQL

Installer outputs and writes:

- `.env.experience`
- `CLAWPWN_EXPERIENCE_DB_URL` into both `.env.experience` and `.env`

## Quick Start

```bash
# 1) Create a project folder
mkdir -p ~/pentest/target-site
cd ~/pentest/target-site

# 2) Initialize ClawPwn project
clawpwn init

# 3) Set target
clawpwn target https://example.com

# 4) Run scan
clawpwn scan --depth normal

# 5) Open interactive console
clawpwn console
```

## Command Overview

Use `clawpwn --help` for full command help.

| Command | Purpose | Example |
|---|---|---|
| `init` | Initialize project in current directory | `clawpwn init` |
| `target` | Set active target URL/IP | `clawpwn target http://10.0.0.5` |
| `status` | Show target, phase, findings summary | `clawpwn status` |
| `scan` | Network + web scanning phase | `clawpwn scan --depth deep --web-tools all` |
| `discover` / `lan` | Discover live hosts in CIDR range | `clawpwn discover --range 192.168.1.0/24` |
| `killchain` | Run AI-guided end-to-end phases | `clawpwn killchain --auto` |
| `report` | Generate report (html/pdf/json/md) | `clawpwn report --format html` |
| `logs` | Show project logs | `clawpwn logs --limit 100` |
| `config` | Show/edit/init config | `clawpwn config show` |
| `list-projects` | Discover local ClawPwn projects | `clawpwn list-projects` |
| `objective` | Set/show/clear objective | `clawpwn objective set "Validate auth bypass"` |
| `memory` | Show/clear project memory | `clawpwn memory show --limit 8` |
| `version` | Print installed version | `clawpwn version` |
| `console` | Start interactive console | `clawpwn console` |

## Interactive Console

Start with:

```bash
clawpwn console
```

Console behavior:

- Default mode is `auto` routing (CLI vs natural language by content)
- `mode cli`, `mode nli`, `mode auto` switch routing modes
- Prefix with `!` to force CLI parsing
- Prefix with `?` to force NLI parsing
- Built-ins: `help`, `restart`, `history`, `clear`, `exit`

## Scanner Support

Network scanners:

- `nmap`, `masscan`, `rustscan`

Web scanner plugins in runtime:

- `builtin`, `nuclei`, `feroxbuster`, `ffuf`, `nikto`, `searchsploit`, `zap`, `sqlmap`, `wpscan`, `testssl`

Credential testing backends:

- `credential_test` uses built-in form testing by default and supports `tool=hydra` when installed.

CLI `scan --web-tools` currently accepts:

- `builtin,nuclei,feroxbuster,ffuf,nikto,searchsploit,zap` or `all`

NLI/agent tool-use can select specialized plugins (`sqlmap`, `wpscan`, `testssl`) when available.

## Configuration

Copy template and set values:

```bash
cp .env.example .env
```

Primary env keys:

- `CLAWPWN_LLM_PROVIDER` (default fallback: `anthropic`)
- `CLAWPWN_LLM_API_KEY`
- `CLAWPWN_LLM_MODEL`
- `CLAWPWN_LLM_BASE_URL`
- `CLAWPWN_DATA_DIR`
- `CLAWPWN_VERBOSE`
- `CLAWPWN_EXPERIENCE_DB_URL` (provisioned by `install.sh`)
- `CLAWPWN_CRED_WORDLIST` (provisioned by `install.sh`)

Backward-compatible keys are also supported:

- `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`

Configuration precedence:

1. Process environment variables
2. Project `.clawpwn/.env`
3. Global `~/.clawpwn/config.yml`
4. Code defaults

## Centralized Experience DB

The repository includes Docker Compose + SQL bootstrap for a centralized cross-project Postgres knowledge store:

- Compose file: `docker-compose.experience-db.yml`
- Init SQL: `docker/postgres/init/`
- External persistent volume: `clawpwn_pgdata`
- Default service: `experience-db` on host port `54329`

Notes:

- Volume is external, so data survives container recreation/removal
- Installer re-applies extension/schema/seed SQL idempotently
- Current project runtime state (targets/findings/logs) remains per-project SQLite

## Testing

Run default suite:

```bash
uv run pytest
```

Run autonomous tests only:

```bash
uv run pytest -m autonomous -v -s
```

Autonomous test prerequisites:

- `ANTHROPIC_API_KEY` set in environment
- Metasploitable2 container reachable (default test target: `172.17.0.2`)
- Host network access to target container

Helper script:

```bash
./start-msf2.sh
```

## Development

```bash
# Bootstrap local dev environment (installs uv if missing, syncs deps, installs hooks)
./setup.sh

# Install dependencies
uv sync

# Install pre-commit hook
uv run pre-commit install

# Run tests
uv run pytest

# Build package
uv build
```

## Commit Convention

Use Conventional Commits:

- `feat:` feature
- `fix:` bug fix
- `chore:` maintenance
- `docs:` documentation
- `feat!:` / `fix!:` breaking change

## Safety

ClawPwn is for authorized security testing only. Use only with explicit written permission and within legal scope.

## License

MIT. See `LICENSE`.
