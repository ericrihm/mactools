"""opslog CLI — wraps macOS Unified Log with AI interpretation."""

from __future__ import annotations

import sys

import click

from mactools_core.output import color, md_table, print_json, print_findings, severity_icon
from mactools_core.unified_log import log_show, log_stats, LogEntry, LogStats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_to_dict(entry: LogEntry) -> dict:
    return {
        "timestamp": entry.timestamp,
        "level": entry.level,
        "process": entry.process,
        "pid": entry.pid,
        "subsystem": entry.subsystem,
        "category": entry.category,
        "message": entry.message,
    }


def _level_color(level: str) -> str:
    mapping = {
        "fault": "critical",
        "error": "warning",
        "warning": "warning",
        "info": "info",
        "debug": "dim",
        "default": "dim",
    }
    return mapping.get(level.lower(), "info")


def _print_entries(entries: list[LogEntry], as_json: bool) -> None:
    if as_json:
        print_json([_entry_to_dict(e) for e in entries])
        return
    for e in entries:
        lvl = e.level.upper()
        lvl_color = _level_color(e.level)
        proc = e.process or "(unknown)"
        sub = f" ({e.subsystem})" if e.subsystem else ""
        ts = e.timestamp
        msg = e.message.strip()
        print(
            f"  {color(lvl, lvl_color):12s} {color(ts, 'dim')} "
            f"{color(proc + sub, 'info')}\n"
            f"             {msg}"
        )


def _run_analysis(entries: list[LogEntry], analysis_type: str, stats: LogStats | None = None) -> None:
    from mactools_opslog.ai import analyze_logs
    click.echo(color(f"\nRunning AI {analysis_type} analysis ({len(entries)} entries)...", "dim"))
    result = analyze_logs(entries, analysis_type=analysis_type, stats=stats)
    if result.ok:
        click.echo(f"\n{color('AI Analysis', 'info')} ({result.model}):\n")
        click.echo(result.text)
    else:
        click.echo(color(f"Analysis failed: {result.text}", "warning"), err=True)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """opslog — macOS Unified Log inspector with AI interpretation."""


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--last", default="5m", show_default=True,
              help="Time window (e.g. 5m, 1h, 30s).")
@click.option("--process", default=None, metavar="NAME",
              help="Filter by process name.")
@click.option("--limit", default=100, show_default=True,
              help="Maximum number of entries to show.")
@click.option("--json", "as_json", is_flag=True,
              help="Output as JSON.")
@click.option("--analyze", is_flag=True,
              help="Send results to AI for analysis.")
def errors(last: str, process: str | None, limit: int, as_json: bool, analyze: bool) -> None:
    """Show errors and faults from the Unified Log."""
    predicate = 'level >= error'
    if process:
        predicate += f' AND process == "{process}"'

    entries = log_show(last=last, predicate=predicate, level="error", limit=limit)

    if not entries:
        if not as_json:
            click.echo(color("No errors found in the specified window.", "ok"))
        else:
            print_json([])
        return

    if not as_json:
        click.echo(
            color(f"Found {len(entries)} error(s) in the last {last}", "warning")
            + (f" for process '{process}'" if process else "")
        )
        click.echo()

    _print_entries(entries, as_json)

    if analyze and not as_json:
        stats = log_stats()
        _run_analysis(entries, "triage", stats=stats)


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

@cli.command()
def stats() -> None:
    """Show Unified Log statistics (total events, errors, faults)."""
    s = log_stats()
    findings = [
        {
            "severity": "info",
            "title": f"Total events:  {s.total_events:,}",
            "detail": "",
        },
        {
            "severity": "warning" if s.error_count > 0 else "ok",
            "title": f"Errors:        {s.error_count:,}",
            "detail": "",
        },
        {
            "severity": "critical" if s.fault_count > 0 else "ok",
            "title": f"Faults:        {s.fault_count:,}",
            "detail": "",
        },
    ]
    click.echo(color("Unified Log Statistics", "info"))
    click.echo()
    print_findings(findings)


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("query")
@click.option("--last", default="1h", show_default=True,
              help="Time window (e.g. 1h, 30m).")
@click.option("--level", default="error", show_default=True,
              type=click.Choice(["error", "info", "debug", "fault"], case_sensitive=False),
              help="Minimum log level.")
@click.option("--json", "as_json", is_flag=True,
              help="Output as JSON.")
def search(query: str, last: str, level: str, as_json: bool) -> None:
    """Search Unified Log entries matching QUERY (used as predicate substring)."""
    predicate = f'eventMessage CONTAINS[c] "{query}"'
    if level in ("error", "fault"):
        predicate += " AND level >= error"

    entries = log_show(last=last, predicate=predicate, level=level, limit=500)

    if not entries:
        if not as_json:
            click.echo(color(f"No entries matching '{query}' in the last {last}.", "ok"))
        else:
            print_json([])
        return

    if not as_json:
        click.echo(
            color(f"Found {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
                  f"matching '{query}' in the last {last}", "info")
        )
        click.echo()

    _print_entries(entries, as_json)


# ---------------------------------------------------------------------------
# stream
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--process", default=None, metavar="NAME",
              help="Filter by process name.")
@click.option("--level", default="error", show_default=True,
              type=click.Choice(["error", "info", "debug", "fault"], case_sensitive=False),
              help="Minimum log level.")
def stream(process: str | None, level: str) -> None:
    """Live-stream Unified Log entries (Ctrl-C to stop)."""
    import subprocess

    cmd = ["log", "stream", "--style", "compact", "--level", level]
    if process:
        cmd.extend(["--predicate", f'process == "{process}"'])

    click.echo(
        color(
            f"Streaming {level}+ logs"
            + (f" for '{process}'" if process else "")
            + " (Ctrl-C to stop)...",
            "info",
        )
    )

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if not line or line.startswith("Timestamp") or line.startswith("---"):
                continue
            # Colorize fault/error lines
            lower = line.lower()
            if "fault" in lower:
                print(color(line, "critical"))
            elif "error" in lower:
                print(color(line, "warning"))
            else:
                print(line)
    except KeyboardInterrupt:
        click.echo(color("\nStream stopped.", "dim"))
    except FileNotFoundError:
        click.echo(color("Error: 'log' command not found.", "critical"), err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--last", default="15m", show_default=True,
              help="Time window (e.g. 15m, 1h).")
@click.option("--json", "as_json", is_flag=True,
              help="Output as JSON.")
@click.option("--analyze", is_flag=True,
              help="Send triage results to AI for interpretation.")
def triage(last: str, as_json: bool, analyze: bool) -> None:
    """Auto-triage: group errors by subsystem/process, rank by severity."""
    from mactools_opslog.engine import triage_errors, build_triage_report

    entries = log_show(last=last, predicate="level >= error", level="error", limit=1000)

    if not entries:
        if not as_json:
            click.echo(color(f"No errors found in the last {last}.", "ok"))
        else:
            print_json({"total_entries": 0, "groups": []})
        return

    groups = triage_errors(entries)
    report = build_triage_report(groups)

    if as_json:
        print_json({
            "total_entries": report.total_entries,
            "total_groups": report.total_groups,
            "critical_count": report.critical_count,
            "warning_count": report.warning_count,
            "info_count": report.info_count,
            "groups": [
                {
                    "process": g.process,
                    "subsystem": g.subsystem,
                    "severity": g.severity,
                    "count": g.count,
                    "levels": g.levels,
                    "sample_messages": g.sample_messages,
                }
                for g in report.groups
            ],
        })
        if analyze:
            _run_analysis(entries, "triage")
        return

    # --- Terminal output ---
    click.echo(color(f"Triage Report — last {last}", "info"))
    click.echo(
        f"  {color(str(report.total_entries), 'warning')} total errors across "
        f"{report.total_groups} group(s)  |  "
        f"{color(str(report.critical_count), 'critical')} critical  "
        f"{color(str(report.warning_count), 'warning')} warning  "
        f"{color(str(report.info_count), 'dim')} info"
    )
    click.echo()

    headers = ["Severity", "Count", "Process", "Subsystem", "Sample"]
    rows = []
    for g in report.groups:
        sample = g.sample_messages[0][:60] + ("..." if g.sample_messages and len(g.sample_messages[0]) > 60 else "") if g.sample_messages else ""
        rows.append([
            g.severity.upper(),
            str(g.count),
            g.process or "(unknown)",
            g.subsystem or "",
            sample,
        ])

    click.echo(md_table(headers, rows))

    if analyze:
        _run_analysis(entries, "triage")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()
