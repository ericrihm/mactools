"""Safe subprocess runner for macOS CLI tools."""

from __future__ import annotations

import json
import plistlib
import subprocess
from dataclasses import dataclass


@dataclass
class RunResult:
    stdout: str
    stderr: str
    returncode: int
    ok: bool


def run(cmd: list[str], timeout: int = 30, sudo: bool = False) -> RunResult:
    if sudo:
        cmd = ["sudo", "-n", *cmd]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return RunResult(
            stdout=r.stdout, stderr=r.stderr,
            returncode=r.returncode, ok=r.returncode == 0,
        )
    except subprocess.TimeoutExpired:
        return RunResult(stdout="", stderr="timeout", returncode=-1, ok=False)
    except FileNotFoundError:
        return RunResult(
            stdout="", stderr=f"command not found: {cmd[0]}",
            returncode=-1, ok=False,
        )


def run_json(cmd: list[str], timeout: int = 30) -> dict | list | None:
    r = run(cmd, timeout=timeout)
    if not r.ok:
        return None
    try:
        return json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return None


def run_plist(cmd: list[str], timeout: int = 30) -> dict | None:
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
        )
        if r.returncode != 0:
            return None
        return plistlib.loads(r.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, plistlib.InvalidFileException):
        return None
