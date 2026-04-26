"""macadmin — privileged macOS operations for AI agents."""

import json

import click

from mactools_macadmin import engine


@click.group()
def main():
    """macadmin — privileged macOS admin for AI agents.

    Wraps sudo, SSH, Tailscale, and fleet operations so Claude Code
    and other AI agents can perform system administration through
    a GUI askpass dialog instead of requiring a TTY.
    """


@main.command()
@click.option("--json", "as_json", is_flag=True, help="JSON output")
def setup(as_json):
    """First-run setup: install askpass, configure sudoers, verify SSH."""
    result = engine.setup_all()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        for key, val in result.items():
            if isinstance(val, dict):
                status = val.get("status", str(val))
                click.echo(f"  {key}: {status}")
            else:
                click.echo(f"  {key}: {val}")


@main.group()
def ssh():
    """SSH / Remote Login management."""


@ssh.command("enable")
@click.option("--json", "as_json", is_flag=True)
def ssh_enable(as_json):
    """Enable macOS Remote Login (SSH)."""
    result = engine.enable_ssh()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"SSH: {result['status']}")


@ssh.command("status")
@click.option("--json", "as_json", is_flag=True)
def ssh_status(as_json):
    """Check SSH / Remote Login state."""
    result = engine.ssh_status()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  enabled: {result['enabled']}")
        click.echo(f"  authorized_keys: {result['authorized_keys']}")
        click.echo(f"  port: {result['port']}")


@ssh.command("authorize-key")
@click.argument("key_path", default="")
@click.option("--json", "as_json", is_flag=True)
def ssh_authorize_key(key_path, as_json):
    """Add a public key to authorized_keys."""
    result = engine.authorize_key(key_path)
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  {result['status']}: {result.get('key', '')}")


@main.group()
def tailscale():
    """Tailscale node management."""


@tailscale.command("status")
@click.option("--json", "as_json", is_flag=True)
def tailscale_status(as_json):
    """Show Tailscale node status and peers."""
    result = engine.tailscale_status()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  hostname: {result.get('hostname', 'unknown')}")
        click.echo(f"  ip: {result.get('ip', 'unknown')}")
        click.echo(f"  online: {result.get('online', False)}")
        if result.get("peers"):
            click.echo(f"\n  Peers ({len(result['peers'])}):")
            for p in result["peers"]:
                status = "online" if p.get("online") else "offline"
                click.echo(f"    {p['hostname']:30s} {p['ip']:20s} {p['os']:10s} {status}")


@main.group()
def fleet():
    """Fleet identity and peer management."""


@fleet.command("identity")
@click.option("--json", "as_json", is_flag=True)
def fleet_identity(as_json):
    """Write/update fleet identity.toml."""
    result = engine.fleet_identity()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  hostname: {result['hostname']}")
        click.echo(f"  ip: {result['ip']}")
        click.echo(f"  ram: {result['ram_gb']}GB, cores: {result['cpu_cores']}, gpu: {result['gpu']}")
        click.echo(f"  agents: {', '.join(result['agents'])}")
        click.echo(f"  written: {result['file']}")


@fleet.command("peers")
@click.option("--json", "as_json", is_flag=True)
def fleet_peers(as_json):
    """List known fleet peers."""
    result = engine.fleet_peers()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        if not result:
            click.echo("  No peers found")
            return
        for p in result:
            click.echo(f"  {p.get('hostname', p['file']):30s} {p.get('tailscale_ip', ''):20s} {p.get('status', 'unknown')}")


@main.group()
def sharing():
    """macOS sharing services."""


@sharing.command("status")
@click.option("--json", "as_json", is_flag=True)
def sharing_status(as_json):
    """Check all sharing services."""
    result = engine.sharing_status()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        for service, enabled in result.items():
            icon = "ON" if enabled else "off"
            click.echo(f"  {service:20s} {icon}")


@main.group()
def sudo():
    """sudo-askpass management."""


@sudo.command("test")
@click.option("--json", "as_json", is_flag=True)
def sudo_test(as_json):
    """Verify sudo-askpass works."""
    result = engine.sudo_test()
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  status: {result['status']}")
        click.echo(f"  askpass: {result['askpass']}")
        if result.get("error"):
            click.echo(f"  error: {result['error']}")


@sudo.command("cache")
@click.option("--json", "as_json", is_flag=True)
def sudo_cache(as_json):
    """Prime sudo credential cache (triggers one password dialog)."""
    from mactools_core.admin import prime_sudo_cache
    ok = prime_sudo_cache()
    result = {"status": "cached" if ok else "failed"}
    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"  sudo cache: {result['status']}")
