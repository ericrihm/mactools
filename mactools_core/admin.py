"""macOS privileged operations — sudo-askpass bridge for AI agents."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from mactools_core.runner import run, RunResult


ASKPASS_PATH = Path.home() / ".local" / "bin" / "sudo-askpass"
SUDOERS_FILE = Path("/etc/sudoers.d/claude-dev")
ASKPASS_SCRIPT = '''#!/bin/bash
exec osascript -e '
set dialogResult to display dialog "sudo requires your password:" default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with title "sudo authentication" with icon caution
return text returned of dialogResult
' 2>/dev/null
'''


def has_askpass() -> bool:
    return ASKPASS_PATH.exists() and os.access(ASKPASS_PATH, os.X_OK)


def askpass_path() -> str:
    return str(ASKPASS_PATH)


def install_askpass() -> bool:
    ASKPASS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ASKPASS_PATH.write_text(ASKPASS_SCRIPT)
    ASKPASS_PATH.chmod(0o755)
    return has_askpass()


def sudo_run(cmd: list[str], **kwargs) -> RunResult:
    env = os.environ.copy()
    env["SUDO_ASKPASS"] = str(ASKPASS_PATH)
    full_cmd = ["sudo", "-A"] + cmd
    return run(full_cmd, env=env, **kwargs)


def is_ssh_enabled() -> bool:
    r = run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=3",
             "-o", "BatchMode=yes", "localhost", "echo", "ok"])
    return r.ok and "ok" in r.stdout


def get_sharing_status() -> dict:
    status = {}
    ssh_r = run(["ssh", "-o", "ConnectTimeout=2", "-o", "BatchMode=yes",
                 "localhost", "echo", "ok"])
    status["remote_login"] = ssh_r.ok

    ps_r = run(["ps", "aux"])
    if ps_r.ok:
        status["ard_agent"] = "ARDAgent" in ps_r.stdout
        status["screen_sharing"] = "screensharingd" in ps_r.stdout
        status["file_sharing"] = "smbd" in ps_r.stdout
    else:
        status["ard_agent"] = False
        status["screen_sharing"] = False
        status["file_sharing"] = False

    return status


def has_sudoers_config() -> bool:
    r = sudo_run(["cat", "/etc/sudoers.d/claude-dev"])
    return r.ok and "timestamp_type=global" in r.stdout


def install_sudoers_config(username: str = "") -> bool:
    if not username:
        username = os.environ.get("USER", "")
    if not username:
        return False
    config = (
        f"Defaults:{username} timestamp_type=global\n"
        f"Defaults:{username} timestamp_timeout=30\n"
    )
    r = sudo_run(["tee", "/etc/sudoers.d/claude-dev"], input_data=config)
    if r.ok:
        sudo_run(["chmod", "0440", "/etc/sudoers.d/claude-dev"])
    return r.ok


def prime_sudo_cache() -> bool:
    r = sudo_run(["-v"])
    return r.ok
