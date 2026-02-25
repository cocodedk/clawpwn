# ClawPwn CLI Help

This document mirrors the current `clawpwn --help` output.

```
Usage: clawpwn [OPTIONS] COMMAND [ARGS]...

AI-powered penetration testing tool

Options:
  --install-completion    Install completion for the current shell.
  --show-completion       Show completion for the current shell, to copy it
                          or customize the installation.
  --help                  Show this message and exit.

Commands:
  version        Show the installed ClawPwn version.
  init           Initialize a new pentest project in the current directory.
  target         Set the primary target for this project.
  status         Show current project status and phase.
  list-projects  List all ClawPwn projects.
  scan           Start the scanning phase.
  killchain      Run the full attack kill chain with AI guidance.
  report         Generate a penetration testing report.
  logs           Show project logs.
  interactive    Start interactive natural language mode.
  config         Manage ClawPwn configuration and API keys.
```

If you add new commands, refresh this file by running:

```bash
uv run clawpwn --help
```

## Troubleshooting

### "Scanner requires elevated privileges for raw network access"

Network scans need raw socket access. Options:

1. **Set capabilities (one-time):**
   ```bash
   sudo setcap cap_net_raw+ep $(which rustscan)
   sudo setcap cap_net_raw+ep $(which masscan)
   ```

2. **Run with sudo:**
   ```bash
   sudo clawpwn scan
   ```

3. **Re-run the installer** and choose **y** when asked to set capabilities on scanner binaries.
