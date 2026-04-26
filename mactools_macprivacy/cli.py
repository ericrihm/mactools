"""macprivacy — macOS privacy permissions audit CLI."""

from __future__ import annotations

import click

from mactools_core.output import color, print_findings, print_json, severity_icon, md_table
from mactools_core.ai import analyze

from mactools_macprivacy.engine import (
    audit_permissions,
    categorize_permissions,
    identify_stale_permissions,
    TCC_SERVICE_NAMES,
)
from mactools_macprivacy.ai import (
    PRIVACY_AUDIT_PROMPT,
    PERMISSION_CATEGORY_PROMPT,
    STALE_PERMISSIONS_PROMPT,
    RISK_ASSESSMENT_PROMPT,
)


@click.group()
def cli() -> None:
    """macOS privacy permissions audit — TCC database, stale grants, risk assessment."""


@cli.command("audit")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.option("--analyze", is_flag=True, help="Send audit to Claude for AI risk assessment.")
def cmd_audit(as_json: bool, analyze: bool) -> None:
    """Audit all TCC privacy permissions on this Mac."""
    click.echo(color("  Reading TCC database ...", "dim"), err=True)
    entries = audit_permissions()

    if as_json:
        print_json([e.as_dict() for e in entries])
        if analyze:
            context = _build_audit_context(entries)
            result = analyze(RISK_ASSESSMENT_PROMPT, context)
            click.echo("\n--- AI Analysis ---")
            click.echo(result.text)
        return

    if not entries:
        click.echo(color(
            "  No TCC entries found. Full Disk Access may be required to read the system TCC database.",
            "warning"
        ))
        return

    allowed = [e for e in entries if e.allowed]
    high_risk = [e for e in allowed if e.risk_level == "high"]
    medium_risk = [e for e in allowed if e.risk_level == "medium"]
    stale = identify_stale_permissions(entries)

    click.echo()
    click.echo(color("  macOS Privacy Permissions Audit", "info"))
    click.echo(color(
        f"  Total entries: {len(entries)}  Allowed: {len(allowed)}  "
        f"High-risk: {len(high_risk)}  Medium-risk: {len(medium_risk)}  "
        f"Stale: {len(stale)}",
        "dim",
    ))
    click.echo()

    # Print high-risk allowed entries
    if high_risk:
        click.echo(color("  High-Risk Permissions:", "critical"))
        for e in high_risk:
            click.echo(f"    [{color('!!!', 'critical')}] {e.category}: {e.client}")
        click.echo()

    # Print medium-risk allowed entries
    if medium_risk:
        click.echo(color("  Medium-Risk Permissions:", "warning"))
        for e in medium_risk:
            click.echo(f"    [{color('!!', 'warning')}] {e.category}: {e.client}")
        click.echo()

    # Stale permissions
    if stale:
        click.echo(color("  Stale Permissions (app no longer exists):", "warning"))
        for e in stale:
            click.echo(f"    [{color('!!', 'warning')}] {e.category}: {e.client}")
            click.echo(f"         $ tccutil reset {e.service} {e.client}")
        click.echo()

    if analyze:
        context = _build_audit_context(entries)
        click.echo(color("  AI Analysis", "info"))
        click.echo()
        result = analyze(RISK_ASSESSMENT_PROMPT, context)
        click.echo(result.text)


@cli.command("list")
@click.option("--category", "category_filter", default=None,
              help="Filter by category name (e.g. Camera, Microphone).")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cmd_list(category_filter: str | None, as_json: bool) -> None:
    """List privacy permissions, optionally filtered by category."""
    entries = audit_permissions()
    grouped = categorize_permissions(entries)

    if category_filter:
        # Case-insensitive match on category name
        matched = {
            k: v for k, v in grouped.items()
            if category_filter.lower() in k.lower()
        }
        if not matched:
            click.echo(color(
                f"  No entries found for category '{category_filter}'. "
                f"Try: {', '.join(list(grouped.keys())[:5])}",
                "warning",
            ))
            return
        grouped = matched

    if as_json:
        print_json({
            cat: [e.as_dict() for e in entries]
            for cat, entries in grouped.items()
        })
        return

    for category, cat_entries in grouped.items():
        allowed = [e for e in cat_entries if e.allowed]
        denied = [e for e in cat_entries if not e.allowed]
        click.echo()
        click.echo(color(f"  {category} ({len(allowed)} allowed, {len(denied)} denied)", "info"))
        for e in cat_entries:
            status_str = color("ALLOW", "ok") if e.allowed else color("DENY", "dim")
            risk_str = color(e.risk_level.upper(), {
                "high": "critical", "medium": "warning", "low": "dim"
            }.get(e.risk_level, "dim"))
            exists_str = ""
            if e.app_exists is False:
                exists_str = color(" [APP MISSING]", "warning")
            click.echo(f"    [{status_str}] [{risk_str}] {e.client}{exists_str}")


@cli.command("revoke")
@click.argument("category")
@click.argument("app")
def cmd_revoke(category: str, app: str) -> None:
    """Print the tccutil command to revoke a permission (does not execute it).

    CATEGORY is the TCC service name (e.g. kTCCServiceCamera or Camera).
    APP is the bundle ID or path.
    """
    # Accept friendly names or raw service names
    service = _resolve_service(category)

    click.echo()
    click.echo(color("  Revoke Command (DRY RUN — not executed):", "warning"))
    click.echo()

    if app:
        click.echo(f"  $ tccutil reset {service} {app}")
        click.echo()
        click.echo(color(
            f"  This will revoke {service} permission for {app}.\n"
            "  The app will prompt for permission again on next use.",
            "dim",
        ))
    else:
        click.echo(f"  $ tccutil reset {service}")
        click.echo()
        click.echo(color(
            f"  This will revoke {service} permission for ALL apps.\n"
            "  Apps will prompt for permission again on next use.",
            "dim",
        ))


def _resolve_service(name: str) -> str:
    """Resolve a friendly category name to a kTCCService* identifier."""
    if name.startswith("kTCCService"):
        return name
    # Reverse lookup in TCC_SERVICE_NAMES
    for service_key, friendly in TCC_SERVICE_NAMES.items():
        if friendly.lower() == name.lower():
            return service_key
    # Return as-is (user may have passed the raw service key)
    return name


def _build_audit_context(entries: list) -> str:
    lines = []
    for e in entries:
        lines.append(
            f"service={e.service} category={e.category} "
            f"client={e.client} status={e.status} "
            f"risk={e.risk_level} app_exists={e.app_exists}"
        )
    return "\n".join(lines)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
