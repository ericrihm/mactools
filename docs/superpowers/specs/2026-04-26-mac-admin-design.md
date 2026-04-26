# mac-admin: Privileged macOS Operations for AI Agents

## Problem

Claude Code (and other AI agents) cannot run `sudo`, toggle System Settings, or perform interactive auth flows. Every privileged operation requires the user to leave the AI session, run commands manually, and paste results back. This session alone hit this wall on: enabling Remote Login, swapping Tailscale builds, enabling Tailscale SSH, and checking sudoers config.

## Solution

Two components that work together:

### 1. sudo-askpass bridge (`~/.local/bin/sudo-askpass`)

A macOS-native askpass helper that shows a GUI password dialog when sudo needs authentication. Combined with `timestamp_type=global` in sudoers, one password entry lasts 30 minutes across all Claude Code tool calls.

**Already built and working** in this session.

### 2. `macadmin` CLI tool (new entry point in mactools)

A Click CLI that wraps the privileged operations AI agents commonly need, using sudo-askpass for authentication. Every command prints what it will do before doing it, and returns structured JSON for programmatic consumption.

## Architecture

```
mactools/
  mactools_macadmin/       — new package
    __init__.py
    cli.py                 — Click CLI
    engine.py              — privileged operations (all use sudo-askpass)
    setup.py               — first-run setup (install askpass, sudoers.d, verify)
  mactools_core/
    admin.py               — new core module: sudo helpers, askpass verification
```

## Commands

```
macadmin setup              # Install askpass, configure sudoers.d, verify SSH
macadmin ssh enable         # Enable Remote Login
macadmin ssh status         # Check SSH/Remote Login state
macadmin ssh authorize-key  # Add a key to authorized_keys
macadmin tailscale status   # Tailscale node status
macadmin tailscale ssh      # Enable Tailscale SSH (if supported)
macadmin fleet identity     # Write/update fleet identity.toml
macadmin fleet peers        # List known fleet peers
macadmin sharing status     # Check all sharing services (SSH, ARD, file sharing)
macadmin sharing enable X   # Enable a sharing service
macadmin sudo test          # Verify sudo-askpass works
macadmin sudo cache         # Prime sudo credential cache (one dialog)
```

## Core module: `mactools_core/admin.py`

```python
def has_askpass() -> bool
def askpass_path() -> str
def sudo_run(cmd: list[str]) -> RunResult  # wraps run() with SUDO_ASKPASS
def is_ssh_enabled() -> bool
def get_sharing_status() -> dict
```

## Setup flow (`macadmin setup`)

1. Check if `~/.local/bin/sudo-askpass` exists — create if not
2. Check if `SUDO_ASKPASS` is in shell profile — add if not
3. Check if `/etc/sudoers.d/claude-dev` exists with correct config — create via sudo-askpass if not
4. Test sudo works without TTY
5. Check SSH is enabled
6. Report status as JSON

## Integration with interop

- Register `macadmin` as entry point in `pyproject.toml`
- Add to ctools catalog as a new shipped tool
- `macadmin fleet identity` writes the same `~/.interop/fleet/identity.toml` the fleet script creates
- interop's `DarwinPlatform` can call `macadmin` commands for privileged ops

## Design Decisions

- **Never store passwords** — askpass prompts every time (with 30-min sudo cache, this means once per session)
- **Print before execute** �� every privileged command shows what it will run before running it
- **JSON output** — `--json` flag on all commands for machine consumption
- **Idempotent** — running `macadmin setup` twice is safe
- **No NOPASSWD** — we use `timestamp_type=global` + `timestamp_timeout=30` instead. The user always authenticates at least once per session.
