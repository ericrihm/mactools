"""Shared output formatting — markdown tables, JSON, severity coloring."""

from __future__ import annotations

import json
import sys


SEVERITY_COLORS = {
    "critical": "\033[91m",
    "warning": "\033[93m",
    "info": "\033[94m",
    "ok": "\033[92m",
    "dim": "\033[90m",
    "reset": "\033[0m",
}


def color(text: str, level: str) -> str:
    if not sys.stdout.isatty():
        return text
    c = SEVERITY_COLORS.get(level, "")
    return f"{c}{text}{SEVERITY_COLORS['reset']}" if c else text


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    lines = []
    hdr = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(hdr)
    lines.append(" | ".join("-" * w for w in widths))
    for row in rows:
        cells = [str(row[i]).ljust(widths[i]) if i < len(row) else " " * widths[i]
                 for i in range(len(headers))]
        lines.append(" | ".join(cells))
    return "\n".join(lines)


def print_json(data: dict | list) -> None:
    print(json.dumps(data, indent=2, default=str))


def severity_icon(level: str) -> str:
    return {"critical": "!!!", "warning": "!!", "info": "--", "ok": "OK"}.get(level, "??")


def print_findings(findings: list[dict], as_json: bool = False) -> None:
    if as_json:
        print_json(findings)
        return
    for f in findings:
        level = f.get("severity", "info")
        icon = severity_icon(level)
        title = f.get("title", "")
        detail = f.get("detail", "")
        print(f"  [{color(icon, level)}] {title}")
        if detail:
            print(f"      {color(detail, 'dim')}")
