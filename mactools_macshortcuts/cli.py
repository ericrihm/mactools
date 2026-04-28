"""macshortcuts CLI — Shortcuts Intelligence."""

from __future__ import annotations

import click

from mactools_core.output import color, md_table, print_json


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """macshortcuts — Shortcuts Intelligence powered by AI."""


def main() -> None:
    cli()


# ---------------------------------------------------------------------------
# list — list all installed shortcuts
# ---------------------------------------------------------------------------

@cli.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_list(as_json: bool) -> None:
    """List all installed Shortcuts."""
    from mactools_macshortcuts.engine import list_all_shortcuts

    shortcuts = list_all_shortcuts()

    if as_json:
        print_json({
            "total": len(shortcuts),
            "shortcuts": [{"name": s.name, "folder": s.folder} for s in shortcuts],
        })
        return

    if not shortcuts:
        click.echo("No shortcuts found.")
        return

    rows = [[s.name, s.folder or "—"] for s in shortcuts]
    click.echo(md_table(["Name", "Folder"], rows))
    click.echo(f"\nTotal: {len(shortcuts)}")


# ---------------------------------------------------------------------------
# run — run a shortcut by name
# ---------------------------------------------------------------------------

@cli.command("run")
@click.argument("name")
@click.option("--input", "input_text", default=None, help="Text to pass as input to the shortcut.")
def cmd_run(name: str, input_text: str | None) -> None:
    """Run a shortcut by NAME."""
    from mactools_core.shortcuts import run_shortcut

    click.echo(f"Running shortcut: {color(name, 'info')}")
    output = run_shortcut(name, input_text=input_text)
    if output:
        click.echo(output)


# ---------------------------------------------------------------------------
# suggest — AI suggests what shortcut to build
# ---------------------------------------------------------------------------

@cli.command("suggest")
@click.argument("description")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", "do_analyze", is_flag=True, default=True, hidden=True)
def cmd_suggest(description: str, as_json: bool, do_analyze: bool) -> None:
    """Ask AI to suggest a shortcut for DESCRIPTION.

    DESCRIPTION is a natural-language description of the automation you want,
    e.g. "send today's calendar events to myself as a text message".
    """
    from mactools_macshortcuts.engine import suggest_shortcut as build_context
    from mactools_macshortcuts.ai import suggest_shortcut as ai_suggest

    ctx = build_context(description)
    result = ai_suggest(ctx.context_text)

    if as_json:
        print_json({
            "description": description,
            "installed_count": len(ctx.installed_names),
            "suggestion": result.text,
            "model": result.model,
            "ok": result.ok,
        })
        return

    click.echo(color("Shortcut Suggestion", "info"))
    click.echo("─" * 60)
    click.echo(result.text)
    click.echo()
    click.echo(color(f"(You have {len(ctx.installed_names)} shortcuts installed)", "dim"))


# ---------------------------------------------------------------------------
# audit — audit installed shortcuts
# ---------------------------------------------------------------------------

@cli.command("audit")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_audit(as_json: bool) -> None:
    """Audit your installed shortcuts — find duplicates and get AI insights."""
    from mactools_macshortcuts.engine import audit_shortcuts as run_audit
    from mactools_macshortcuts.ai import audit_shortcuts as ai_audit

    audit = run_audit()

    if as_json:
        ai_result = ai_audit([s.name for s in audit.shortcuts])
        print_json({
            "total": audit.total,
            "duplicates": audit.duplicates,
            "empty_names": audit.empty_names,
            "shortcuts": [{"name": s.name, "folder": s.folder} for s in audit.shortcuts],
            "ai_analysis": ai_result.text,
            "ok": ai_result.ok,
        })
        return

    click.echo(color("Shortcut Audit", "info"))
    click.echo("─" * 60)
    click.echo(f"  Total shortcuts : {audit.total}")
    click.echo(f"  Unnamed         : {audit.empty_names}")

    if audit.duplicates:
        click.echo()
        click.echo(color(f"  Duplicate names ({len(audit.duplicates)}):", "warning"))
        for name in audit.duplicates:
            click.echo(f"    {color('!!', 'warning')} {name}")
    else:
        click.echo(f"  Duplicates      : {color('none', 'ok')}")

    click.echo()
    click.echo(color("AI Analysis", "info"))
    click.echo("─" * 60)
    ai_result = ai_audit([s.name for s in audit.shortcuts])
    click.echo(ai_result.text)
