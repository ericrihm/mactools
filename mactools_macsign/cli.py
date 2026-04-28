"""macsign — code signing intelligence CLI."""

from __future__ import annotations

import click

from mactools_core.output import color, print_json, severity_icon, md_table
from mactools_core.ai import analyze as ai_analyze

from mactools_macsign.engine import (
    scan_applications,
    audit_entitlements,
    list_packages,
)
from mactools_macsign.ai import (
    SIGNING_EXPLAINER_PROMPT,
    ENTITLEMENT_AUDIT_PROMPT,
    SCAN_SUMMARY_PROMPT,
    PACKAGE_AUDIT_PROMPT,
)


@click.group()
def cli() -> None:
    """macOS code signing intelligence — verify apps, scan directories, inspect entitlements."""


@cli.command("check")
@click.argument("path")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cmd_check(path: str, as_json: bool) -> None:
    """Check the code signature of an app or binary at PATH."""
    from mactools_core.security import check_codesign
    from mactools_macsign.engine import audit_entitlements, AppSignatureResult
    import os

    sig = check_codesign(path)
    dangerous, notable = audit_entitlements(sig)
    result = AppSignatureResult(
        path=path,
        name=os.path.basename(path),
        signature=sig,
        dangerous_entitlements=dangerous,
        notable_entitlements=notable,
    )

    if as_json:
        print_json(result.as_dict())
        return

    click.echo()
    click.echo(color(f"  Code Signature: {result.name}", "info"))
    click.echo()

    signed_str = color("YES", "ok") if sig.signed else color("NO", "critical")
    valid_str = color("YES", "ok") if sig.valid else color("NO", "critical")
    notarized_str = color("YES", "ok") if sig.notarized else color("--", "dim")

    click.echo(f"  Signed:     {signed_str}")
    click.echo(f"  Valid:      {valid_str}")
    click.echo(f"  Notarized:  {notarized_str}")
    if sig.identifier:
        click.echo(f"  Identifier: {sig.identifier}")
    if sig.team_id:
        click.echo(f"  Team ID:    {sig.team_id}")
    if sig.format:
        click.echo(f"  Format:     {sig.format}")
    if sig.flags:
        click.echo(f"  Flags:      {sig.flags}")
    if sig.authority_chain:
        click.echo(f"  Authority chain:")
        for auth in sig.authority_chain:
            click.echo(f"    - {auth}")
    if sig.error:
        click.echo(f"  Error:      {color(sig.error, 'critical')}")

    if dangerous:
        click.echo()
        click.echo(color("  Dangerous Entitlements:", "critical"))
        for e in dangerous:
            click.echo(f"    [{color('!!!', 'critical')}] {e['key']}")
            click.echo(f"         {color(e['reason'], 'dim')}")

    if notable:
        click.echo()
        click.echo(color("  Notable Entitlements:", "warning"))
        for k in notable:
            click.echo(f"    [--] {k}")


@cli.command("scan")
@click.option("--dir", "directory", default="/Applications", show_default=True,
              help="Directory to scan for .app bundles.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.option("--analyze", is_flag=True, help="Send scan results to AI for analysis.")
def cmd_scan(directory: str, as_json: bool, analyze: bool) -> None:
    """Scan all .app bundles for code signing status."""
    click.echo(color(f"  Scanning {directory} ...", "dim"), err=True)
    results = scan_applications(directory)

    if as_json:
        print_json([r.as_dict() for r in results])
        if analyze:
            summary = _build_scan_summary(results)
            ai_result = ai_analyze(SCAN_SUMMARY_PROMPT, summary)
            click.echo("\n--- AI Analysis ---")
            click.echo(ai_result.text)
        return

    if not results:
        click.echo(color(f"  No .app bundles found in {directory}", "warning"))
        return

    # Summary counts
    signed = sum(1 for r in results if r.signature.signed)
    valid = sum(1 for r in results if r.signature.valid)
    notarized = sum(1 for r in results if r.signature.notarized)
    unsigned = len(results) - signed

    click.echo()
    click.echo(color(f"  Code Signing Scan: {directory}", "info"))
    click.echo(color(
        f"  Total: {len(results)}  Signed: {signed}  Valid: {valid}  "
        f"Notarized: {notarized}  Unsigned: {unsigned}", "dim"
    ))
    click.echo()

    headers = ["App", "Signed", "Valid", "Notarized", "Team ID", "Dangerous Ent."]
    rows = []
    for r in results:
        sig = r.signature
        s = color("YES", "ok") if sig.signed else color("NO", "critical")
        v = color("YES", "ok") if sig.valid else (color("NO", "critical") if sig.signed else color("--", "dim"))
        n = color("YES", "ok") if sig.notarized else color("--", "dim")
        d = color(str(len(r.dangerous_entitlements)), "critical") if r.dangerous_entitlements else color("0", "ok")
        rows.append([r.name[:35], s, v, n, sig.team_id[:20] or color("--", "dim"), d])

    click.echo(md_table(headers, rows))

    if analyze:
        summary = _build_scan_summary(results)
        click.echo()
        click.echo(color("  AI Analysis", "info"))
        click.echo()
        ai_result = ai_analyze(SCAN_SUMMARY_PROMPT, summary)
        click.echo(ai_result.text)


@cli.command("entitlements")
@click.argument("path")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cmd_entitlements(path: str, as_json: bool) -> None:
    """Show all entitlements for an app or binary at PATH."""
    from mactools_core.security import check_codesign

    sig = check_codesign(path)
    dangerous, notable = audit_entitlements(sig)

    if as_json:
        print_json({
            "path": path,
            "entitlements": sig.entitlements,
            "dangerous": dangerous,
            "notable": notable,
        })
        return

    click.echo()
    click.echo(color(f"  Entitlements: {path}", "info"))
    click.echo()

    if not sig.signed:
        click.echo(color("  App is not signed — no entitlements.", "warning"))
        return

    if not sig.entitlements:
        click.echo(color("  No entitlements found (or could not extract).", "dim"))
        return

    for key, value in sig.entitlements.items():
        if key in {e["key"] for e in dangerous}:
            click.echo(f"  [{color('!!!', 'critical')}] {key} = {value}")
        elif key in notable:
            click.echo(f"  [{color('!!', 'warning')}] {key} = {value}")
        else:
            click.echo(f"  [--] {color(key, 'dim')} = {value}")

    if dangerous:
        click.echo()
        click.echo(color("  Dangerous entitlement details:", "critical"))
        for e in dangerous:
            click.echo(f"    {e['key']}")
            click.echo(f"      {color(e['reason'], 'dim')}")


@cli.command("packages")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cmd_packages(as_json: bool) -> None:
    """List all installed packages (via pkgutil)."""
    click.echo(color("  Listing installed packages ...", "dim"), err=True)
    packages = list_packages()

    if as_json:
        print_json([p.as_dict() for p in packages])
        return

    click.echo()
    click.echo(color(f"  Installed Packages ({len(packages)} total)", "info"))
    click.echo()

    headers = ["Package ID", "Version", "Location"]
    rows = [
        [p.pkg_id[:60], p.version[:20] or "—", p.location[:30] or "—"]
        for p in packages
    ]
    click.echo(md_table(headers, rows))


def _build_scan_summary(results: list) -> str:
    lines = []
    for r in results:
        sig = r.signature
        line = (
            f"{r.name}: signed={sig.signed}, valid={sig.valid}, "
            f"notarized={sig.notarized}, team={sig.team_id or 'none'}, "
            f"authorities={';'.join(sig.authority_chain[:2])}, "
            f"dangerous_entitlements={[e['key'] for e in r.dangerous_entitlements]}"
        )
        lines.append(line)
    return "\n".join(lines)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
