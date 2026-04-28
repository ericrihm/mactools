"""macsec — macOS security posture audit CLI."""

from __future__ import annotations

import click

from mactools_core.output import color, print_findings, print_json, severity_icon, md_table
from mactools_core.ai import analyze as ai_analyze

from mactools_macsec.engine import audit_security, compute_security_score
from mactools_macsec.ai import SECURITY_POSTURE_PROMPT, SECURITY_SCORE_PROMPT, REMEDIATION_PROMPT


@click.group()
def cli() -> None:
    """macOS security posture audit — SIP, Gatekeeper, FileVault, firewall, and more."""


@cli.command("audit")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.option("--analyze", is_flag=True, help="Send findings to AI for analysis.")
def cmd_audit(as_json: bool, analyze: bool) -> None:
    """Run a full security posture audit."""
    findings = audit_security()

    if as_json:
        print_json([f.as_dict() for f in findings])
        if analyze:
            context = "\n".join(
                f"[{f.severity.upper()}] {f.title}: {f.detail}"
                for f in findings
            )
            result = ai_analyze(SECURITY_POSTURE_PROMPT, context)
            click.echo("\n--- AI Analysis ---")
            click.echo(result.text)
        return

    # Group by severity for summary header
    counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    click.echo()
    click.echo(color("  macOS Security Posture Audit", "info"))
    click.echo(color(f"  Critical: {counts['critical']}  "
                     f"Warning: {counts['warning']}  "
                     f"OK: {counts['ok']}", "dim"))
    click.echo()

    print_findings([f.as_dict() for f in findings])

    if analyze:
        context = "\n".join(
            f"[{f.severity.upper()}] {f.title}: {f.detail}"
            for f in findings
        )
        click.echo()
        click.echo(color("  AI Analysis", "info"))
        click.echo()
        result = ai_analyze(SECURITY_POSTURE_PROMPT, context)
        click.echo(result.text)


@cli.command("score")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cmd_score(as_json: bool) -> None:
    """Compute a CIS-style security score (0-100)."""
    findings = audit_security()
    score_data = compute_security_score(findings)

    if as_json:
        print_json(score_data)
        return

    score = score_data["score"]
    if score >= 80:
        level = "ok"
    elif score >= 50:
        level = "warning"
    else:
        level = "critical"

    click.echo()
    click.echo(color(f"  Security Score: {score}/100", level))
    click.echo()

    headers = ["Category", "Weight", "Severity", "Earned"]
    rows = []
    for cat, info in score_data["breakdown"].items():
        sev = info["severity"]
        sev_col = color(sev, sev)
        rows.append([cat, str(info["weight"]), sev, f"{info['earned']:.1f}/{info['weight']}"])

    click.echo(md_table(headers, rows))
    click.echo()


@cli.command("fix")
@click.option("--dry-run", is_flag=True, default=True, show_default=True,
              help="Print fix commands without executing them (always dry-run).")
def cmd_fix(dry_run: bool) -> None:
    """Print remediation commands for each finding (never executed)."""
    findings = audit_security()

    fixable = [f for f in findings if f.fix_command and f.severity in ("critical", "warning")]

    if not fixable:
        click.echo(color("  No fixable issues found — all checks passed.", "ok"))
        return

    click.echo()
    click.echo(color("  Remediation Commands (DRY RUN — not executed)", "warning"))
    click.echo()

    for f in fixable:
        icon = severity_icon(f.severity)
        click.echo(f"  [{color(icon, f.severity)}] {f.title}")
        click.echo(f"      {color(f.detail, 'dim')}")
        click.echo(f"      $ {color(f.fix_command, 'info')}")
        click.echo()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
