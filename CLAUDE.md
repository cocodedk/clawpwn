# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
./setup.sh                          # Bootstrap: installs uv, syncs deps, installs pre-commit hooks
uv sync --extra dev                 # Install all dependencies including dev
uv run pytest                       # Run full test suite
uv run pytest tests/test_nli.py -v  # Run a single test file
uv run pytest -k "test_name" -v     # Run a specific test by name
uv run pytest -m autonomous -v -s   # Run autonomous tests (needs ANTHROPIC_API_KEY + Metasploitable2)
uv run ruff check src/ tests/       # Lint
uv run ruff format src/ tests/      # Format
uv run pre-commit run --all-files   # Run all pre-commit hooks (ruff, ruff-format, pytest, file-size check)
uv build                            # Build package
```

## Pre-Commit Rules

Four hooks run on commit:
1. **ruff** with `--fix`
2. **ruff-format**
3. **pytest** (all tests must pass)
4. **200-line limit** on source files in `src/` (tests are exempt)

When a source file exceeds 200 lines, split it into a subfolder module with `__init__.py` re-exporting public APIs so existing imports don't break. Target ~150 lines per file.

## Architecture

### Dual NLI Execution Paths

The Natural Language Interface routes through two paths based on LLM provider:

- **Anthropic (tool-use agent)**: `classify_intent()` in `plan_helpers.py` routes to either:
  - **Plan executor** (`plan_executor.py`): code-driven, 3 LLM calls, tiered parallel execution (fast tools first, slow tools last)
  - **Agent loop** (`executor.py`): conversational, up to 16 tool-use round-trips with streaming
- **OpenAI/OpenRouter (legacy text-parse)**: handler dispatch via string parsing in `interface/legacy.py`

Selection happens in `interface/core.py`: `_process_via_agent()` vs `_process_via_text_parse()` based on `self._use_tool_agent`.

### Mixin Composition

Both `NaturalLanguageInterface` (14 mixins) and `SessionManager` (5 mixins: ProjectMixin, MemoryMixin, FindingLogMixin, StateMixin, PlanMixin) use mixin-based composition. Each mixin has a single responsibility.

### Tool Definition & Execution

Tools are defined in `ai/nli/tools/` (schemas + metadata) and executed by matching handlers in `ai/nli/tool_executors/`. The `dispatch_tool(name, params)` function routes to the appropriate executor.

### LLM Client

`LLMClient` in `ai/llm/client.py` supports multiple providers. The `chat_with_tools()` method is monkey-patched onto the client via `ai/llm/__init__.py` from `tool_support.py`.

### Input Routing (Console)

`InputRouter` in `console/router.py` auto-detects CLI vs NLI input. Prefix `!` forces CLI, `?` forces NLI.

### Storage

- **Per-project SQLite** at `.clawpwn/clawpwn.db` (projects, findings, logs, conversation history, plan steps)
- **Optional cross-project Postgres** via `CLAWPWN_EXPERIENCE_DB_URL` (centralized knowledge store with pgvector)

## Testing Patterns

- Fixtures in `tests/conftest.py`: `project_dir`, `mock_env_vars`, `initialized_db`, `session_manager`, `sample_project`, `sample_finding`
- `mock_env_vars` forces `provider=openai` so tests use the text-parse path and `llm.chat()` can be safely mocked
- `Mock()` from unittest returns Mock objects (not strings), so `isinstance(result, str)` guards work as type checks for LLM responses
- Lazy imports inside functions must be patched at the **source module**, not the calling module
- Session method is `set_target()` (not `update_target()`)

## Capability Sync Rules

When adding/removing CLI commands, update all three layers:
1. NLI intent list + handlers in `src/clawpwn/ai/nli/`
2. Console routing/completions in `console/router.py` and `console/completer.py`
3. LLM system prompt in `ai/nli/agent/prompt.py` if user-visible behavior changes

## Ruff Configuration

- Target: Python 3.12, line length 100
- Rules: E, W, F, I, B, C4, UP (ignoring E501, UP038)
- Tests allow: S101 (assert), B011

## Commit Convention

Conventional Commits: `feat:`, `fix:`, `chore:`, `docs:`, `feat!:`/`fix!:` for breaking changes.
