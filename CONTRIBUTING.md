# Contributing to ClawPwn

Thanks for your interest in contributing. Please open issues or PRs as usual; for code style and tests, see the project’s existing tooling (e.g. ruff, pytest).

## Pentest artifacts and secure storage

**Do not commit** pentest outputs or security tooling data from this repo. The directories `.clawpwn/` and `pentests/` are ignored for that reason.

- Store reports, scan results, and other artifacts in your organization’s **secure external store or internal security platform**, not in the repository.
- For the full workflow (including untracking if needed, purging history if credentials were committed, and who may access artifacts), see **[SECURITY.md](SECURITY.md)**.

Keeping these artifacts out of the repo and in designated secure storage protects sensitive findings and credentials and keeps the repository safe to share and fork.
