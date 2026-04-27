"""macspot CLI — Spotlight Intelligence."""

from __future__ import annotations

import click

from mactools_core.output import color, md_table, print_json, severity_icon
from mactools_core.spotlight import get_metadata, search


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@click.group()
def cli() -> None:
    """macspot — Spotlight Intelligence powered by Claude."""


def main() -> None:
    cli()


# ---------------------------------------------------------------------------
# search — natural-language Spotlight search (AI translates to predicate)
# ---------------------------------------------------------------------------

@cli.command("search")
@click.argument("query")
@click.option("--dir", "directory", default=None, help="Limit search to this directory.")
@click.option("--limit", default=20, show_default=True, help="Maximum results to return.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_search(query: str, directory: str | None, limit: int, as_json: bool) -> None:
    """Search using natural language — Claude translates to an mdfind predicate.

    QUERY is a natural-language description, e.g. "PDFs modified this week".
    """
    from mactools_core.ai import DEFAULT_MODEL
    from mactools_macspot.ai import translate_query
    from mactools_macspot.engine import natural_language_to_predicate
    from mactools_core.spotlight import search_predicate

    # Try AI translation first; fall back to heuristic engine if unavailable
    ai_result = translate_query(query)
    if ai_result.ok:
        predicate = ai_result.text.strip()
    else:
        predicate = natural_language_to_predicate(query)

    results = search_predicate(predicate, directory=directory, limit=limit)

    if as_json:
        print_json({
            "query": query,
            "predicate": predicate,
            "directory": directory,
            "result_count": len(results),
            "results": results,
        })
        return

    click.echo(f"Predicate: {color(predicate, 'dim')}")
    click.echo(f"Found {len(results)} result(s):\n")
    for path in results:
        click.echo(f"  {path}")


# ---------------------------------------------------------------------------
# find — direct mdfind search (no AI translation)
# ---------------------------------------------------------------------------

@cli.command("find")
@click.argument("query")
@click.option("--dir", "directory", default=None, help="Limit search to this directory.")
@click.option("--limit", default=50, show_default=True, help="Maximum results to return.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_find(query: str, directory: str | None, limit: int, as_json: bool) -> None:
    """Direct mdfind search — passes QUERY unchanged to mdfind.

    QUERY can be a plain string (full-text) or an mdfind predicate.
    """
    results = search(query, directory=directory, limit=limit)

    if as_json:
        print_json({
            "query": query,
            "directory": directory,
            "result_count": len(results),
            "results": results,
        })
        return

    click.echo(f"Query: {color(query, 'dim')}")
    click.echo(f"Found {len(results)} result(s):\n")
    for path in results:
        click.echo(f"  {path}")


# ---------------------------------------------------------------------------
# health — Spotlight index health per volume
# ---------------------------------------------------------------------------

@cli.command("health")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_health(as_json: bool) -> None:
    """Show Spotlight index health for all mounted volumes."""
    from mactools_macspot.engine import audit_index_health

    report = audit_index_health()

    if as_json:
        print_json({
            "total_volumes": report.total_volumes,
            "enabled": report.enabled_count,
            "disabled": report.disabled_count,
            "healthy": report.healthy,
            "issues": report.issues,
            "volumes": [
                {
                    "volume": s.volume,
                    "enabled": s.enabled,
                    "status": s.status,
                }
                for s in report.statuses
            ],
        })
        return

    headers = ["Volume", "Indexing", "Status"]
    rows = [
        [
            s.volume,
            color("Enabled", "ok") if s.enabled else color("Disabled", "critical"),
            s.status,
        ]
        for s in report.statuses
    ]
    click.echo(md_table(headers, rows))
    click.echo()

    if report.issues:
        click.echo(color("Issues detected:", "warning"))
        for issue in report.issues:
            click.echo(f"  {color('!!', 'warning')} {issue}")
    else:
        click.echo(color("All volumes are indexing normally.", "ok"))

    click.echo(
        f"\nTotal volumes: {report.total_volumes}  "
        f"Enabled: {report.enabled_count}  "
        f"Disabled: {report.disabled_count}"
    )


# ---------------------------------------------------------------------------
# metadata — show file metadata attributes
# ---------------------------------------------------------------------------

@cli.command("metadata")
@click.argument("path")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def cmd_metadata(path: str, as_json: bool) -> None:
    """Show Spotlight metadata attributes for a file at PATH."""
    meta = get_metadata(path)

    if as_json:
        print_json({"path": meta.path, "attributes": meta.attributes})
        return

    if not meta.attributes:
        click.echo(f"No metadata found for: {path}")
        return

    click.echo(f"Metadata for: {color(path, 'dim')}\n")
    headers = ["Attribute", "Value"]
    rows = [
        [key, str(value)[:120]]
        for key, value in sorted(meta.attributes.items())
    ]
    click.echo(md_table(headers, rows))
