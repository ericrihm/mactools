"""macdefaults CLI — macOS defaults system intelligence."""

from __future__ import annotations

import json

import click

from mactools_core.defaults import list_domains, read_domain
from mactools_core.output import color, md_table, print_json, print_findings

from mactools_macdefaults.engine import audit_defaults, get_power_user_recommendations, search_key
from mactools_macdefaults.ai import DEFAULTS_EXPLAINER_PROMPT, DEFAULTS_RECOMMENDER_PROMPT, SEARCH_EXPLAINER_PROMPT


@click.group()
def cli() -> None:
    """macOS defaults system intelligence."""


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask Claude to explain the findings.")
def audit(as_json: bool, analyze: bool) -> None:
    """Scan interesting defaults and show settings modified from factory values."""
    result = audit_defaults()

    if as_json:
        print_json(result.to_dict())
        return

    click.echo(f"\n  Defaults Audit — {result.total_checked} keys checked, "
               f"{color(str(result.modified_count), 'warning')} modified from factory\n")

    headers = ["Domain", "Key", "Description", "Factory", "Current", "Modified"]
    rows = []
    for f in result.findings:
        modified_marker = color("YES", "warning") if f.modified else color("no", "dim")
        factory_str = str(f.factory_value) if f.factory_value is not None else color("(absent)", "dim")
        current_str = str(f.current_value) if f.current_value is not None else color("(absent)", "dim")
        rows.append([f.domain, f.key, f.description, factory_str, current_str, modified_marker])

    click.echo(md_table(headers, rows))

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        context_lines = [f"Modified defaults ({result.modified_count} of {result.total_checked} checked):"]
        for f in result.findings:
            if f.modified:
                context_lines.append(
                    f"  {f.domain} / {f.key}: factory={f.factory_value!r}, current={f.current_value!r}"
                )
        result_ai = ai_analyze(
            system_prompt=DEFAULTS_EXPLAINER_PROMPT,
            context="\n".join(context_lines),
        )
        click.echo(f"\n  {color('Analysis', 'info')}\n")
        click.echo(result_ai.text)


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("domain")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def read(domain: str, as_json: bool) -> None:
    """Read all keys in a specific defaults domain."""
    d = read_domain(domain)
    if d.error:
        click.echo(color(f"  Error reading {domain}: {d.error}", "critical"), err=True)
        raise SystemExit(1)

    if as_json:
        print_json({"domain": domain, "keys": d.keys})
        return

    click.echo(f"\n  {domain}  ({color(str(d.key_count), 'info')} keys)\n")
    if not d.keys:
        click.echo(color("  (empty domain)", "dim"))
        return

    headers = ["Key", "Value"]
    rows = []
    for k, v in sorted(d.keys.items()):
        if isinstance(v, (bytes, bytearray)):
            display = f"<binary {len(v)} bytes>"
        elif isinstance(v, str) and len(v) > 120:
            display = v[:120] + "…"
        elif isinstance(v, dict):
            display = f"<dict {len(v)} keys>"
        elif isinstance(v, list):
            display = f"<list {len(v)} items>"
        else:
            display = str(v)
        rows.append([k, display])
    click.echo(md_table(headers, rows))


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("key")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask Claude to explain the results.")
def search(key: str, as_json: bool, analyze: bool) -> None:
    """Search across all defaults domains for a matching key name."""
    click.echo(color(f"  Searching all domains for '{key}'…", "dim"), err=True)
    matches = search_key(key)

    if as_json:
        print_json(matches)
        return

    if not matches:
        click.echo(f"  No keys matching '{key}' found across any domain.")
        return

    click.echo(f"\n  Found {color(str(len(matches)), 'info')} match(es) for '{key}'\n")
    headers = ["Domain", "Key", "Value"]
    rows = [[m["domain"], m["key"], str(m["value"])] for m in matches]
    click.echo(md_table(headers, rows))

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        context = f"Search key: '{key}'\nResults:\n"
        for m in matches[:20]:
            context += f"  {m['domain']} / {m['key']} = {m['value']!r}\n"
        result = ai_analyze(system_prompt=SEARCH_EXPLAINER_PROMPT, context=context)
        click.echo(f"\n  {color('Analysis', 'info')}\n")
        click.echo(result.text)


# ---------------------------------------------------------------------------
# recommend
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask Claude for personalized recommendations.")
def recommend(as_json: bool, analyze: bool) -> None:
    """Show power-user defaults recommendations."""
    recs = get_power_user_recommendations()

    if as_json:
        print_json(recs)
        return

    click.echo(f"\n  Power-User Defaults Recommendations ({len(recs)} total)\n")
    current_category = None
    for r in recs:
        if r["category"] != current_category:
            current_category = r["category"]
            click.echo(f"\n  {color(current_category, 'info')}")
        click.echo(f"    {color('--', 'dim')} {r['title']}")
        click.echo(f"       {color(r['explanation'], 'dim')}")
        click.echo(f"       {color(r['command'], 'ok')}")
        if r["restart_required"] != "none":
            restart_msg = f"Restart required: {r['restart_required']}"
            click.echo(f"       {color(restart_msg, 'warning')}")

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        audit = audit_defaults()
        current_state = "Current system defaults state:\n"
        for f in audit.findings:
            if f.modified:
                current_state += f"  {f.domain}/{f.key} = {f.current_value!r} (factory: {f.factory_value!r})\n"
            else:
                current_state += f"  {f.domain}/{f.key} = {f.current_value!r} (at factory default)\n"
        context = current_state + "\nPlease give personalized recommendations."
        result = ai_analyze(system_prompt=DEFAULTS_RECOMMENDER_PROMPT, context=context)
        click.echo(f"\n  {color('Personalized Analysis', 'info')}\n")
        click.echo(result.text)


# ---------------------------------------------------------------------------
# domains
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def domains(as_json: bool) -> None:
    """List all preference domains with key counts."""
    click.echo(color("  Loading all defaults domains…", "dim"), err=True)
    domain_list = list_domains()
    rows_data = []
    for domain in sorted(domain_list):
        d = read_domain(domain)
        rows_data.append({
            "domain": domain,
            "key_count": d.key_count,
            "error": d.error,
        })

    if as_json:
        print_json(rows_data)
        return

    click.echo(f"\n  {color(str(len(domain_list)), 'info')} preference domains\n")
    headers = ["Domain", "Keys", "Status"]
    rows = []
    for item in rows_data:
        status = color(item["error"], "warning") if item["error"] else color("ok", "ok")
        rows.append([item["domain"], str(item["key_count"]), status])
    click.echo(md_table(headers, rows))


def main() -> None:
    cli()
