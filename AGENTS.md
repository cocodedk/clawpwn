# Repository Guidelines

## Project Structure & Module Organization
- `src/clawpwn/`: core package (CLI, config, AI, scanners, storage, reporting).
- `tests/`: pytest suite.
- `docs/`: documentation and guides.
- `exploits/`, `evidence/`, `report/`: operator artifacts and outputs.
- `install.sh`, `setup.sh`, `update.sh`: installer and dev tooling scripts.

## Build, Test, and Development Commands
- `./setup.sh`: installs `uv`, syncs dev dependencies, and installs pre-commit hooks.
- `uv sync`: install project dependencies into the local env.
- `uv run pytest`: run the full test suite.
- `uv run pre-commit install`: install the git hook for lint/test checks.
- `uv build`: build the package for distribution.
- `./install.sh`: end-user install; may prompt for scanner permissions.

## Coding Style & Naming Conventions
- Python 3.12+; 4-space indentation.
- Linting/formatting via `ruff` (line length 100, `src/` and `tests/`).
- Module names are lowercase; classes use `CamelCase`; functions/vars use `snake_case`.

## Testing Guidelines
- Framework: `pytest` with `pytest-asyncio` for async tests.
- Tests live in `tests/` and follow `test_*.py` naming.
- Run locally with `uv run pytest` before opening a PR.

## Commit & Pull Request Guidelines
- Use Conventional Commits:
  - `feat:` new feature, `fix:` bug fix, `chore:`/`docs:` non-release changes.
  - Breaking changes use `feat!:` or `fix!:`.
- PRs should include a concise description, testing notes, and linked issues when applicable.

## Security & Configuration Tips
- Copy `.env.example` to `.env` and set required values.
- Scanners may need raw socket access; `./install.sh` will ask before setting capabilities.

## Agent Communication Style
- Use short phrases and avoid flooding the user with text.
