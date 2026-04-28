"""macdisk CLI — Disk & APFS Intelligence."""

from __future__ import annotations

import click

from mactools_core.output import color, md_table, print_json


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """macdisk — Disk & APFS Intelligence powered by AI."""


def main() -> None:
    cli()


# ---------------------------------------------------------------------------
# status — APFS containers, volumes, capacity, SMART
# ---------------------------------------------------------------------------

@cli.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", "do_analyze", is_flag=True, help="Ask AI to explain the disk layout.")
def cmd_status(as_json: bool, do_analyze: bool) -> None:
    """Show disk status: APFS containers, volumes, capacity, and SMART health."""
    from mactools_macdisk.engine import build_disk_report, identify_disk_issues

    report = build_disk_report()
    issues = identify_disk_issues(report)
    data = report.to_dict()
    data["issues"] = [
        {"severity": i.severity, "title": i.title, "detail": i.detail}
        for i in issues
    ]

    if as_json:
        print_json(data)
        if do_analyze:
            _run_explain_analysis(data)
        return

    _print_status(report, issues)

    if do_analyze:
        _run_explain_analysis(data)


def _print_status(report, issues) -> None:
    from mactools_macdisk.engine import format_size

    click.echo(color("Disks", "info"))
    click.echo("─" * 60)
    disk_rows = []
    for d in report.disks:
        smart = d.smart_status or report.smart_statuses.get(d.identifier, "unknown")
        smart_colored = (
            color(smart, "ok") if smart.upper() in ("VERIFIED", "PASSED", "OK")
            else color(smart, "critical") if smart.upper() == "FAILED"
            else color(smart, "dim")
        )
        disk_rows.append([d.identifier, d.name or "(unnamed)", format_size(d.size_bytes), smart_colored])
    click.echo(md_table(["Identifier", "Name", "Size", "SMART"], disk_rows))
    click.echo()

    click.echo(color("APFS Containers & Volumes", "info"))
    click.echo("─" * 60)
    for c in report.containers:
        used_bytes = c.capacity_bytes - c.free_bytes
        used_pct = (used_bytes / c.capacity_bytes * 100) if c.capacity_bytes > 0 else 0
        free_str = format_size(c.free_bytes)
        cap_str = format_size(c.capacity_bytes)
        pct_color = "critical" if used_pct > 95 else "warning" if used_pct > 90 else "ok"
        click.echo(
            f"\n  Container {color(c.identifier, 'dim')}  "
            f"{cap_str} total  {free_str} free  "
            f"{color(f'{used_pct:.1f}% used', pct_color)}"
        )
        vol_rows = []
        for v in c.volumes:
            enc = color("yes", "ok") if v.encrypted else color("no", "warning")
            mount = v.mount_point or "(not mounted)"
            vol_rows.append([v.name, v.identifier, v.role or "—", format_size(v.used_bytes), enc, mount])
        click.echo(md_table(
            ["Volume", "ID", "Role", "Used", "Encrypted", "Mount"],
            vol_rows,
        ))

    click.echo()
    click.echo(color("Summary", "info"))
    click.echo("─" * 60)
    click.echo(f"  Total capacity : {format_size(report.total_capacity_bytes)}")
    click.echo(f"  Total free     : {format_size(report.total_free_bytes)}")

    if issues:
        click.echo()
        click.echo(color("Issues:", "warning"))
        for issue in issues:
            icon = "!!!" if issue.severity == "critical" else "!!"
            click.echo(f"  [{color(icon, issue.severity)}] {issue.title}")
            click.echo(f"      {color(issue.detail, 'dim')}")


def _run_explain_analysis(data: dict) -> None:
    import json as _json
    from mactools_macdisk.ai import explain_disk_layout
    summary = _json.dumps(data, indent=2, default=str)
    click.echo()
    click.echo(color("AI Analysis", "info"))
    click.echo("─" * 60)
    result = explain_disk_layout(summary)
    click.echo(result.text)


# ---------------------------------------------------------------------------
# volumes — detailed volume listing
# ---------------------------------------------------------------------------

@cli.command("volumes")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_volumes(as_json: bool) -> None:
    """Show detailed APFS volume listing."""
    from mactools_macdisk.engine import build_disk_report, format_size

    report = build_disk_report()

    if as_json:
        volumes_data = []
        for c in report.containers:
            for v in c.volumes:
                volumes_data.append({
                    "container": c.identifier,
                    "name": v.name,
                    "identifier": v.identifier,
                    "role": v.role,
                    "used": format_size(v.used_bytes),
                    "used_bytes": v.used_bytes,
                    "encrypted": v.encrypted,
                    "mounted": v.mounted,
                    "mount_point": v.mount_point,
                })
        print_json({"volumes": volumes_data, "total": len(volumes_data)})
        return

    for c in report.containers:
        click.echo(f"Container: {color(c.identifier, 'info')}  "
                   f"({format_size(c.capacity_bytes)} total, {format_size(c.free_bytes)} free)")
        click.echo("─" * 60)
        rows = []
        for v in c.volumes:
            enc = color("FileVault ON", "ok") if v.encrypted else color("unencrypted", "warning")
            mount = v.mount_point or "(not mounted)"
            rows.append([v.name, v.identifier, v.role or "—", format_size(v.used_bytes), enc, mount])
        click.echo(md_table(
            ["Volume", "ID", "Role", "Used", "Encryption", "Mount"],
            rows,
        ))
        click.echo()


# ---------------------------------------------------------------------------
# smart — SMART health status
# ---------------------------------------------------------------------------

@cli.command("smart")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_smart(as_json: bool) -> None:
    """Show SMART health status for all internal disks."""
    from mactools_macdisk.engine import build_disk_report

    report = build_disk_report()

    if as_json:
        smart_data = []
        for d in report.disks:
            if d.internal:
                smart = d.smart_status or report.smart_statuses.get(d.identifier, "unknown")
                smart_data.append({
                    "identifier": d.identifier,
                    "name": d.name,
                    "smart_status": smart,
                    "healthy": smart.upper() in ("VERIFIED", "PASSED", "OK"),
                })
        print_json({"smart": smart_data})
        return

    rows = []
    for d in report.disks:
        if not d.internal:
            continue
        smart = d.smart_status or report.smart_statuses.get(d.identifier, "unknown")
        is_ok = smart.upper() in ("VERIFIED", "PASSED", "OK")
        status_str = color(smart, "ok") if is_ok else color(smart, "critical")
        rows.append([d.identifier, d.name or "(unnamed)", status_str])

    if not rows:
        click.echo("No internal disks found.")
        return

    click.echo(md_table(["Disk", "Name", "SMART Status"], rows))


# ---------------------------------------------------------------------------
# explain — AI explains your disk layout in plain English
# ---------------------------------------------------------------------------

@cli.command("explain")
@click.option("--json", "as_json", is_flag=True, help="Output raw AI text as JSON.")
@click.option("--analyze", "do_analyze", is_flag=True, default=True, hidden=True)
def cmd_explain(as_json: bool, do_analyze: bool) -> None:
    """Ask AI to explain your disk layout in plain English."""
    import json as _json
    from mactools_macdisk.engine import build_disk_report, identify_disk_issues
    from mactools_macdisk.ai import explain_disk_layout

    report = build_disk_report()
    issues = identify_disk_issues(report)
    data = report.to_dict()
    data["issues"] = [
        {"severity": i.severity, "title": i.title, "detail": i.detail}
        for i in issues
    ]
    summary = _json.dumps(data, indent=2, default=str)
    result = explain_disk_layout(summary)

    if as_json:
        print_json({"analysis": result.text, "model": result.model, "ok": result.ok})
        return

    click.echo(color("AI Disk Explanation", "info"))
    click.echo("─" * 60)
    click.echo(result.text)
