"""macnet CLI — macOS network configuration intelligence."""

from __future__ import annotations

import click

from mactools_core.network import get_hardware_ports, get_dns_config, get_network_overview
from mactools_core.output import color, md_table, print_json, print_findings

from mactools_macnet.engine import diagnose_network, explain_dns_chain, get_full_overview
from mactools_macnet.ai import NETWORK_STATUS_PROMPT, NETWORK_DIAGNOSE_PROMPT, DNS_EXPLAINER_PROMPT


@click.group()
def cli() -> None:
    """macOS network configuration intelligence."""


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask AI to interpret the network state.")
def status(as_json: bool, analyze: bool) -> None:
    """Full network overview: ports, DNS, proxy, active interface."""
    overview = get_full_overview()

    if as_json:
        data = {
            "active_interface": overview.active_interface,
            "ports": [
                {
                    "name": p.name,
                    "device": p.device,
                    "address": p.address,
                }
                for p in overview.ports
            ],
            "dns_resolvers": [
                {
                    "domain": r.domain,
                    "nameservers": r.nameservers,
                    "search_domains": r.search_domains,
                    "interface": r.interface,
                }
                for r in overview.dns_resolvers
            ],
            "proxy": {
                "http_enabled": overview.proxy.http_enabled,
                "http_proxy": overview.proxy.http_proxy,
                "https_enabled": overview.proxy.https_enabled,
                "https_proxy": overview.proxy.https_proxy,
                "socks_enabled": overview.proxy.socks_enabled,
                "socks_proxy": overview.proxy.socks_proxy,
                "exceptions": overview.proxy.exceptions,
            } if overview.proxy else None,
        }
        print_json(data)
        return

    click.echo(f"\n  Network Status\n")

    # Active interface
    if overview.active_interface:
        click.echo(f"  Active interface: {color(overview.active_interface, 'ok')}")
    else:
        click.echo(f"  Active interface: {color('none detected', 'warning')}")

    # Ports
    click.echo(f"\n  Hardware Ports ({len(overview.ports)})\n")
    if overview.ports:
        headers = ["Port", "Device", "MAC Address"]
        rows = [[p.name, p.device or color("(no device)", "dim"), p.address or ""] for p in overview.ports]
        click.echo(md_table(headers, rows))

    # DNS
    click.echo(f"\n  DNS Resolvers ({len(overview.dns_resolvers)})\n")
    if overview.dns_resolvers:
        headers = ["#", "Nameservers", "Domain", "Interface"]
        rows = []
        for i, r in enumerate(overview.dns_resolvers, 1):
            ns = ", ".join(r.nameservers) if r.nameservers else color("none", "dim")
            rows.append([str(i), ns, r.domain or "", r.interface or ""])
        click.echo(md_table(headers, rows))
    else:
        click.echo(color("  No DNS resolvers found.", "warning"))

    # Proxy
    if overview.proxy:
        proxy_items = []
        if overview.proxy.http_enabled:
            proxy_items.append(f"HTTP: {overview.proxy.http_proxy}")
        if overview.proxy.https_enabled:
            proxy_items.append(f"HTTPS: {overview.proxy.https_proxy}")
        if overview.proxy.socks_enabled:
            proxy_items.append(f"SOCKS: {overview.proxy.socks_proxy}")
        if proxy_items:
            click.echo(f"\n  Proxy: {color(', '.join(proxy_items), 'warning')}")
            if overview.proxy.exceptions:
                click.echo(f"  Bypass: {', '.join(overview.proxy.exceptions)}")
        else:
            click.echo(f"\n  Proxy: {color('none configured', 'ok')}")

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        context_parts = [
            f"Active interface: {overview.active_interface or 'none'}",
            f"Hardware ports ({len(overview.ports)}): "
            + ", ".join(f"{p.name} ({p.device})" for p in overview.ports),
            f"DNS resolvers ({len(overview.dns_resolvers)}): "
            + "; ".join(
                f"ns=[{', '.join(r.nameservers)}] domain={r.domain!r} iface={r.interface!r}"
                for r in overview.dns_resolvers[:8]
            ),
        ]
        if overview.proxy:
            context_parts.append(
                f"Proxy: HTTP={overview.proxy.http_enabled}/{overview.proxy.http_proxy}, "
                f"HTTPS={overview.proxy.https_enabled}/{overview.proxy.https_proxy}"
            )
        result = ai_analyze(
            system_prompt=NETWORK_STATUS_PROMPT,
            context="\n".join(context_parts),
        )
        click.echo(f"\n  {color('Analysis', 'info')}\n")
        click.echo(result.text)


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def dns(as_json: bool) -> None:
    """Show and explain the DNS resolver chain."""
    resolvers = get_dns_config()

    if as_json:
        print_json([
            {
                "domain": r.domain,
                "nameservers": r.nameservers,
                "search_domains": r.search_domains,
                "interface": r.interface,
            }
            for r in resolvers
        ])
        return

    explanation = explain_dns_chain(resolvers)
    click.echo(f"\n{explanation}")


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def ports(as_json: bool) -> None:
    """List all hardware network ports."""
    hw_ports = get_hardware_ports()

    if as_json:
        print_json([
            {"name": p.name, "device": p.device, "address": p.address}
            for p in hw_ports
        ])
        return

    click.echo(f"\n  Hardware Network Ports ({len(hw_ports)})\n")
    if not hw_ports:
        click.echo(color("  No hardware ports found.", "warning"))
        return

    headers = ["Port Name", "Device", "MAC Address"]
    rows = [
        [p.name, p.device or color("(no device)", "dim"), p.address or color("(no address)", "dim")]
        for p in hw_ports
    ]
    click.echo(md_table(headers, rows))


# ---------------------------------------------------------------------------
# diagnose
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--analyze", is_flag=True, help="Ask AI for a diagnosis narrative.")
def diagnose(as_json: bool, analyze: bool) -> None:
    """Diagnose common network issues: DNS conflicts, proxy misconfig, inactive interfaces."""
    overview = get_full_overview()
    issues = diagnose_network(overview)

    if as_json:
        print_json([i.to_dict() for i in issues])
        return

    click.echo(f"\n  Network Diagnostics — {len(issues)} finding(s)\n")
    findings = [
        {
            "severity": i.severity,
            "title": f"[{i.category}] {i.title}",
            "detail": i.detail,
        }
        for i in issues
    ]
    print_findings(findings)

    if analyze:
        from mactools_core.ai import analyze as ai_analyze
        context = "Network diagnostic findings:\n"
        for i in issues:
            context += f"  [{i.severity.upper()}] [{i.category}] {i.title}\n"
            context += f"    {i.detail}\n"
        context += f"\nContext: active_interface={overview.active_interface!r}, "
        context += f"ports={len(overview.ports)}, dns_resolvers={len(overview.dns_resolvers)}"
        result = ai_analyze(system_prompt=NETWORK_DIAGNOSE_PROMPT, context=context)
        click.echo(f"\n  {color('Analysis', 'info')}\n")
        click.echo(result.text)


def main() -> None:
    cli()
