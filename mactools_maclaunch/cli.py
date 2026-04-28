"""maclaunch — audit macOS LaunchAgents and LaunchDaemons."""

from __future__ import annotations

import sys

import click

from mactools_core.launchctl import (
    LaunchService,
    enrich_from_plists,
    get_service_detail,
    list_services,
)
from mactools_core.output import color, print_json, print_findings
from mactools_maclaunch.engine import (
    AuditFinding,
    audit_services,
    build_stats,
    classify_risk,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_services(enrich: bool = True) -> list[LaunchService]:
    services = list_services()
    if enrich:
        services = enrich_from_plists(services)
    return services


def _pid_str(svc: LaunchService) -> str:
    return str(svc.pid) if svc.pid > 0 else "-"


def _status_str(svc: LaunchService) -> str:
    return "running" if svc.running else "stopped"


def _status_colored(svc: LaunchService) -> str:
    s = _status_str(svc)
    return color(s, "ok") if svc.running else color(s, "dim")


def _risk_colored(risk: str) -> str:
    mapping = {"safe": "ok", "low": "info", "medium": "warning", "high": "critical"}
    return color(risk, mapping.get(risk, "dim"))


def _col(text: str, width: int) -> str:
    return str(text)[:width].ljust(width)


def _print_service_table(services: list[LaunchService]) -> None:
    if not services:
        click.echo("  No services found.")
        return

    header = (
        f"  {'Label':<42} {'PID':<6} {'Status':<8} {'Vendor':<14} {'Source'}"
    )
    click.echo(header)
    click.echo("  " + "-" * 85)

    for svc in services:
        pid_s   = _pid_str(svc)
        status_s = _status_colored(svc)
        # Pad status accounting for ANSI escape codes
        raw_status = _status_str(svc)
        status_pad = " " * max(0, 8 - len(raw_status))
        vendor  = svc.vendor[:14]
        source  = svc.source

        label_display = svc.label
        if len(label_display) > 42:
            label_display = label_display[:39] + "..."

        click.echo(
            f"  {label_display:<42} {pid_s:<6} {status_s}{status_pad} {vendor:<14} {source}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# CLI group
# ──────────────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Audit macOS LaunchAgents and LaunchDaemons."""


# ──────────────────────────────────────────────────────────────────────────────
# list
# ──────────────────────────────────────────────────────────────────────────────

@cli.command("list")
@click.option("--vendor", default=None, metavar="VENDOR",
              help="Filter by vendor name (case-insensitive substring).")
@click.option("--running", is_flag=True, default=False,
              help="Show only running services.")
@click.option("--third-party", "third_party", is_flag=True, default=False,
              help="Show only non-Apple third-party services.")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output as JSON.")
def list_cmd(vendor: str | None, running: bool, third_party: bool, as_json: bool) -> None:
    """List all launch services with optional filters."""
    services = _load_services(enrich=True)

    if third_party:
        services = [s for s in services if not s.is_apple]
    if running:
        services = [s for s in services if s.running]
    if vendor:
        services = [s for s in services if vendor.lower() in s.vendor.lower()]

    if as_json:
        data = [
            {
                "label": s.label,
                "pid": s.pid,
                "running": s.running,
                "status": s.status,
                "vendor": s.vendor,
                "source": s.source,
                "program": s.program,
                "program_args": s.program_args,
                "plist_path": s.plist_path,
                "run_at_load": s.run_at_load,
                "keep_alive": s.keep_alive,
                "is_apple": s.is_apple,
            }
            for s in services
        ]
        print_json(data)
        return

    total = len(services)
    click.echo(f"\n  {total} service(s) found\n")
    _print_service_table(services)
    click.echo()


# ──────────────────────────────────────────────────────────────────────────────
# audit
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output as JSON.")
@click.option("--analyze", is_flag=True, default=False,
              help="Use AI to summarize findings (requires Anthropic API key or codex CLI).")
def audit(as_json: bool, analyze: bool) -> None:
    """Security audit: flag suspicious, unsigned, and persistence-heavy services."""
    services = _load_services(enrich=True)
    findings = audit_services(services)

    if as_json:
        data = [
            {
                "label": f.label,
                "risk": f.risk,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "program": f.program,
            }
            for f in findings
        ]
        print_json(data)
        return

    if not findings:
        click.echo(color("  No issues found — all third-party services look normal.", "ok"))
        return

    # Group by risk level
    high    = [f for f in findings if f.risk == "high"]
    medium  = [f for f in findings if f.risk == "medium"]
    low     = [f for f in findings if f.risk == "low"]

    click.echo(f"\n  Audit complete — {len(findings)} finding(s)\n")

    for group, label in [(high, "HIGH"), (medium, "MEDIUM"), (low, "LOW")]:
        if not group:
            continue
        click.echo(f"  {_risk_colored(label.lower())} ({len(group)})")
        for f in group:
            click.echo(f"    [{color('!!!', 'critical') if f.risk == 'high' else color('!!', 'warning')}] {f.title}")
            click.echo(f"        {color(f.detail, 'dim')}")
            if f.program:
                click.echo(f"        {color('program: ' + f.program, 'dim')}")
        click.echo()

    if analyze:
        _run_audit_analysis(findings, services)


def _run_audit_analysis(findings: list[AuditFinding], services: list[LaunchService]) -> None:
    from mactools_core.ai import analyze
    from mactools_maclaunch.ai import AUDIT_EXPLAINER_PROMPT

    context_lines = [f"Total services: {len(services)}", "Findings:"]
    for f in findings:
        context_lines.append(f"  [{f.risk.upper()}] {f.title}: {f.detail}")
    context = "\n".join(context_lines)

    click.echo("  Analyzing findings with AI...\n")
    result = analyze(AUDIT_EXPLAINER_PROMPT, context)
    if result.ok:
        for line in result.text.splitlines():
            click.echo(f"  {line}")
    else:
        click.echo(color(f"  {result.text}", "warning"))
    click.echo()


# ──────────────────────────────────────────────────────────────────────────────
# info
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("label")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output as JSON.")
def info(label: str, as_json: bool) -> None:
    """Show detailed info about a specific service by LABEL."""
    services = _load_services(enrich=True)
    match = next((s for s in services if s.label == label), None)

    if match is None:
        click.echo(color(f"  Service '{label}' not found in launchctl list.", "warning"), err=True)
        sys.exit(1)

    detail = get_service_detail(label)
    risk = classify_risk(match)
    program = match.program or (match.program_args[0] if match.program_args else None)

    if as_json:
        print_json({
            "label": match.label,
            "pid": match.pid,
            "running": match.running,
            "status": match.status,
            "vendor": match.vendor,
            "source": match.source,
            "program": match.program,
            "program_args": match.program_args,
            "plist_path": match.plist_path,
            "run_at_load": match.run_at_load,
            "keep_alive": match.keep_alive,
            "is_apple": match.is_apple,
            "risk": risk,
            "launchctl_detail": detail,
        })
        return

    def row(key: str, val: str) -> None:
        click.echo(f"  {color(key + ':', 'info'):<28} {val}")

    click.echo()
    row("Label",        match.label)
    row("Vendor",       match.vendor)
    row("Source",       match.source)
    row("Status",       _status_colored(match))
    row("PID",          _pid_str(match))
    row("Risk",         _risk_colored(risk))
    row("Program",      program or "-")
    if len(match.program_args) > 1:
        row("Args",     " ".join(match.program_args[1:]))
    row("Plist",        match.plist_path or "-")
    row("RunAtLoad",    str(match.run_at_load))
    row("KeepAlive",    str(match.keep_alive))

    if detail.get("raw"):
        click.echo()
        click.echo(f"  {color('launchctl print output:', 'dim')}")
        for line in detail["raw"].splitlines()[:30]:
            click.echo(f"    {color(line, 'dim')}")
        if len(detail["raw"].splitlines()) > 30:
            click.echo(f"    {color('... (truncated)', 'dim')}")
    click.echo()


# ──────────────────────────────────────────────────────────────────────────────
# stats
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output as JSON.")
def stats(as_json: bool) -> None:
    """Show summary statistics — totals by vendor, source, and run state."""
    services = _load_services(enrich=True)
    data = build_stats(services)

    if as_json:
        print_json(data)
        return

    click.echo()
    click.echo(f"  {color('Total services:', 'info'):<30} {data['total']}")
    click.echo(f"  {color('Running:', 'info'):<30} {color(str(data['running']), 'ok')}")
    click.echo(f"  {color('Stopped:', 'info'):<30} {data['stopped']}")
    click.echo(f"  {color('Apple services:', 'info'):<30} {data['apple']}")
    click.echo(f"  {color('Third-party services:', 'info'):<30} {data['third_party']}")
    click.echo(f"  {color('Persistence agents:', 'info'):<30} {color(str(data['persistence_agents']), 'warning')}")

    click.echo()
    click.echo(f"  {color('By vendor:', 'info')}")
    for vendor, count in data["by_vendor"].items():
        if vendor == "Apple":
            continue
        click.echo(f"    {vendor:<20} {count}")

    click.echo()
    click.echo(f"  {color('By source:', 'info')}")
    for source, count in data["by_source"].items():
        click.echo(f"    {source:<20} {count}")
    click.echo()


# ──────────────────────────────────────────────────────────────────────────────
# disable
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("label")
def disable(label: str) -> None:
    """Print the launchctl command to disable a service (does not execute it)."""
    services = _load_services(enrich=True)
    match = next((s for s in services if s.label == label), None)

    if match is None:
        click.echo(color(f"  Service '{label}' not found in launchctl list.", "warning"), err=True)
        sys.exit(1)

    import os
    uid = os.getuid()

    click.echo()
    click.echo(f"  To disable '{label}', run one of the following:\n")

    # Unload (immediate, session-only)
    click.echo(f"  {color('Unload (current session only):', 'info')}")
    click.echo(f"    launchctl unload -w {match.plist_path or '<plist_path>'}")

    # Disable via bootout (macOS 10.10+)
    if match.source == "system":
        domain = f"system/{label}"
        sudo_prefix = "sudo "
    else:
        domain = f"gui/{uid}/{label}"
        sudo_prefix = ""

    click.echo()
    click.echo(f"  {color('Disable persistently (launchctl disable):', 'info')}")
    click.echo(f"    {sudo_prefix}launchctl disable {domain}")

    if match.plist_path:
        click.echo()
        click.echo(f"  {color('Or move/remove the plist:', 'info')}")
        if match.source in ("global", "system"):
            click.echo(f"    sudo mv {match.plist_path} {match.plist_path}.disabled")
        else:
            click.echo(f"    mv {match.plist_path} {match.plist_path}.disabled")

    click.echo()
    click.echo(color("  Note: The above commands are printed only — nothing has been executed.", "warning"))
    click.echo()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    cli()
