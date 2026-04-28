"""macenergy CLI — macOS energy and thermal intelligence."""

from __future__ import annotations

import click

from mactools_core.output import color, md_table, print_json, print_findings
from mactools_core.power import (
    get_power_settings,
    get_scheduled_events,
    get_sleep_preventers,
    get_thermal_state,
)

from mactools_macenergy.engine import audit_energy, identify_energy_issues
from mactools_macenergy.ai import ENERGY_AUDIT_PROMPT, WAKE_EXPLAINER_PROMPT, THERMAL_EXPLAINER_PROMPT


@click.group()
def cli() -> None:
    """macOS energy and thermal intelligence."""


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def status(as_json: bool) -> None:
    """Show power settings, sleep preventers, and thermal state."""
    settings = get_power_settings()
    preventers = get_sleep_preventers()
    thermal = get_thermal_state()

    if as_json:
        print_json({
            "power_settings": {
                "sleep_timer": settings.sleep_timer,
                "display_sleep": settings.display_sleep,
                "disk_sleep": settings.disk_sleep,
                "wake_on_lan": settings.wake_on_lan,
                "power_nap": settings.power_nap,
            },
            "thermal": {
                "level": thermal.level,
                "cpu_speed_limit": thermal.cpu_speed_limit,
            },
            "sleep_preventer_count": len(preventers),
        })
        return

    click.echo("\n  Energy Status\n")

    # Power settings
    click.echo(f"  System sleep:   {_fmt_timer(settings.sleep_timer)}")
    click.echo(f"  Display sleep:  {_fmt_timer(settings.display_sleep)}")
    click.echo(f"  Disk sleep:     {_fmt_timer(settings.disk_sleep)}")
    click.echo(f"  Wake on LAN:    {_fmt_bool(settings.wake_on_lan)}")
    click.echo(f"  Power Nap:      {_fmt_bool(settings.power_nap)}")

    # Thermal
    thermal_color = {"nominal": "ok", "throttled": "warning", "critical": "critical"}.get(
        thermal.level, "info"
    )
    click.echo(
        f"\n  Thermal state:  {color(thermal.level.upper(), thermal_color)}"
        + (f"  (CPU @ {thermal.cpu_speed_limit}%)" if thermal.cpu_speed_limit < 100 else "")
    )

    # Sleep preventers summary
    if preventers:
        click.echo(f"\n  Sleep preventers: {color(str(len(preventers)), 'warning')} active")
        for p in preventers[:5]:
            click.echo(f"    {color('--', 'dim')} {p.name} (pid {p.pid}): {p.assertion_type}")
        if len(preventers) > 5:
            click.echo(color(f"    … and {len(preventers) - 5} more", "dim"))
    else:
        click.echo(f"\n  Sleep preventers: {color('none', 'ok')}")


# ---------------------------------------------------------------------------
# wake
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def wake(as_json: bool) -> None:
    """Show what is keeping the Mac awake."""
    preventers = get_sleep_preventers()

    if as_json:
        print_json([
            {
                "name": p.name,
                "pid": p.pid,
                "assertion_type": p.assertion_type,
                "detail": p.detail,
            }
            for p in preventers
        ])
        return

    if not preventers:
        click.echo(f"\n  {color('No sleep preventers active.', 'ok')}  The Mac can sleep freely.\n")
        return

    click.echo(f"\n  Sleep Preventers ({color(str(len(preventers)), 'warning')} active)\n")
    headers = ["Process", "PID", "Assertion Type", "Detail"]
    rows = [
        [p.name, str(p.pid), p.assertion_type, p.detail[:60] + ("…" if len(p.detail) > 60 else "")]
        for p in preventers
    ]
    click.echo(md_table(headers, rows))


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def schedule(as_json: bool) -> None:
    """Show scheduled wake and sleep events."""
    events = get_scheduled_events()

    if as_json:
        print_json([
            {"event_type": e.event_type, "time": e.time, "owner": e.owner}
            for e in events
        ])
        return

    if not events:
        click.echo(f"\n  {color('No scheduled power events.', 'dim')}\n")
        return

    click.echo(f"\n  Scheduled Power Events ({len(events)})\n")
    headers = ["Event", "Time", "Owner"]
    rows = [[e.event_type, e.time, e.owner or color("(system)", "dim")] for e in events]
    click.echo(md_table(headers, rows))


# ---------------------------------------------------------------------------
# thermal
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def thermal(as_json: bool) -> None:
    """Show thermal throttling state."""
    state = get_thermal_state()

    if as_json:
        print_json({
            "level": state.level,
            "cpu_speed_limit": state.cpu_speed_limit,
            "details": state.details,
        })
        return

    thermal_color = {"nominal": "ok", "throttled": "warning", "critical": "critical"}.get(
        state.level, "info"
    )
    click.echo(f"\n  Thermal State: {color(state.level.upper(), thermal_color)}")
    if state.cpu_speed_limit < 100:
        click.echo(f"  CPU Speed Limit: {color(f'{state.cpu_speed_limit}%', 'warning')}")
    else:
        click.echo(f"  CPU Speed Limit: {color('100% (no throttling)', 'ok')}")

    if state.details:
        click.echo(f"\n  Raw output:\n")
        for line in state.details.splitlines():
            click.echo(f"    {color(line, 'dim')}")


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask AI for energy recommendations.")
def audit(as_json: bool, analyze: bool) -> None:
    """Full energy audit with issue detection and recommendations."""
    result = audit_energy()

    if as_json:
        print_json(result.to_dict())
        return

    click.echo("\n  Energy Audit\n")

    # Power settings summary
    click.echo(f"  System sleep:   {_fmt_timer(result.power_settings.sleep_timer)}")
    click.echo(f"  Display sleep:  {_fmt_timer(result.power_settings.display_sleep)}")
    click.echo(f"  Wake on LAN:    {_fmt_bool(result.power_settings.wake_on_lan)}")
    click.echo(f"  Power Nap:      {_fmt_bool(result.power_settings.power_nap)}")

    # Thermal
    thermal_color = {"nominal": "ok", "throttled": "warning", "critical": "critical"}.get(
        result.thermal.level, "info"
    )
    click.echo(f"  Thermal:        {color(result.thermal.level.upper(), thermal_color)}", nl=False)
    if result.thermal.cpu_speed_limit < 100:
        click.echo(f"  (CPU @ {result.thermal.cpu_speed_limit}%)")
    else:
        click.echo()

    # Preventers
    if result.preventers:
        click.echo(f"  Sleep blocks:   {color(str(len(result.preventers)), 'warning')} process(es)")
    else:
        click.echo(f"  Sleep blocks:   {color('none', 'ok')}")

    # Schedule
    if result.schedule:
        click.echo(f"  Scheduled:      {len(result.schedule)} event(s)")

    # Issues
    click.echo(f"\n  Issues ({len(result.issues)} finding(s))\n")
    findings = [
        {"severity": i.severity, "title": f"[{i.category}] {i.title}", "detail": i.detail}
        for i in result.issues
    ]
    print_findings(findings)

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        context_parts = [
            f"Power settings: sleep={result.power_settings.sleep_timer}min, "
            f"display_sleep={result.power_settings.display_sleep}min, "
            f"wake_on_lan={result.power_settings.wake_on_lan}, "
            f"power_nap={result.power_settings.power_nap}",
            f"Thermal: level={result.thermal.level}, cpu_speed_limit={result.thermal.cpu_speed_limit}%",
            f"Sleep preventers ({len(result.preventers)}): "
            + ", ".join(f"{p.name}({p.assertion_type})" for p in result.preventers[:10]),
            f"Scheduled events: {len(result.schedule)}",
            "Issues detected:",
        ]
        for i in result.issues:
            context_parts.append(f"  [{i.severity.upper()}] [{i.category}] {i.title}: {i.detail}")
        ai_result = ai_analyze(
            system_prompt=ENERGY_AUDIT_PROMPT,
            context="\n".join(context_parts),
        )
        click.echo(f"\n  {color('Analysis', 'info')}\n")
        click.echo(ai_result.text)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_timer(minutes: int) -> str:
    if minutes == 0:
        return color("disabled", "warning")
    return color(f"{minutes} min", "info")


def _fmt_bool(value: bool) -> str:
    return color("enabled", "warning") if value else color("disabled", "ok")


def main() -> None:
    cli()
