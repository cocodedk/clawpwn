# Security and pentest artifact handling

## Pentest outputs and tooling data

The directories **`.clawpwn/`** and **`pentests/`** are used for local pentest outputs, databases, and security tooling data. They are listed in `.gitignore` and **must not be committed** to this repository.

### Secure storage workflow

- **Do not commit** anything from `.clawpwn/` or `pentests/` into the repo.
- Store pentest artifacts (reports, scan results, session data) in your organization’s **secure external store** or **internal security platform** (e.g. evidence vault, SIEM, or approved file share with access controls), not in the ClawPwn repo workspace.
- If any of these directories were ever added to git, untrack them without deleting local files:
  ```bash
  git rm -r --cached .clawpwn/ pentests/ 2>/dev/null; git commit -m "Stop tracking pentest artifact directories"
  ```
- If **credentials or sensitive findings** were ever committed to the repository history, purge them using [git-filter-repo](https://github.com/newren/git-filter-repo) or [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/), then rotate any exposed secrets and notify relevant stakeholders.

### Who may access these artifacts

Access to pentest outputs and findings should follow your organization’s policy. Typically:

- **Authorized security/red team and engagement owners** may access artifacts for active assessments.
- Distribution and retention should follow your **classification and data handling** rules (e.g. need-to-know, retention limits, secure deletion).

Define exact roles and access in your internal runbooks or security policy; this repo does not grant access by itself.

---

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).
