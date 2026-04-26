"""macOS Shortcuts.app CLI wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mactools_core.runner import run


@dataclass
class Shortcut:
    name: str
    folder: str = ""


def list_shortcuts() -> list[Shortcut]:
    r = run(["shortcuts", "list"])
    if not r.ok:
        return []
    return [Shortcut(name=line.strip()) for line in r.stdout.splitlines() if line.strip()]


def run_shortcut(name: str, input_text: Optional[str] = None) -> str:
    cmd = ["shortcuts", "run", name]
    if input_text:
        cmd.extend(["--input-path", "-"])
    r = run(cmd, timeout=30)
    return r.stdout if r.ok else r.stderr
