"""macadmin engine — privileged macOS operations for AI agents."""

from __future__ import annotations

import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

from mactools_core.admin import (
    has_askpass, install_askpass, sudo_run, is_ssh_enabled,
    get_sharing_status, has_sudoers_config, install_sudoers_config,
    prime_sudo_cache, askpass_path,
)
from mactools_core.runner import run, run_json


FLEET_DIR = Path.home() / ".interop" / "fleet"
IDENTITY_FILE = FLEET_DIR / "identity.toml"
PEERS_DIR = FLEET_DIR / "peers"


def setup_all() -> dict:
    """Full first-run setup: askpass, sudoers, SSH check."""
    results = {}

    if has_askpass():
        results["askpass"] = {"status": "ok", "path": askpass_path()}
    else:
        ok = install_askpass()
        results["askpass"] = {"status": "installed" if ok else "failed", "path": askpass_path()}

    shell_profile = Path.home() / ".zshrc"
    if shell_profile.exists():
        content = shell_profile.read_text()
        if "SUDO_ASKPASS" not in content:
            with open(shell_profile, "a") as f:
                f.write(f'\nexport SUDO_ASKPASS="{askpass_path()}"\n')
            results["shell_profile"] = "updated"
        else:
            results["shell_profile"] = "already configured"
    else:
        results["shell_profile"] = "not found"

    if has_sudoers_config():
        results["sudoers"] = "ok"
    else:
        ok = install_sudoers_config()
        results["sudoers"] = "installed" if ok else "failed (run with sudo)"

    results["ssh_enabled"] = is_ssh_enabled()
    results["sudo_works"] = prime_sudo_cache()

    return results


def enable_ssh() -> dict:
    """Enable macOS Remote Login (SSH)."""
    if is_ssh_enabled():
        return {"status": "already_enabled"}

    r = sudo_run(["launchctl", "load", "-w", "/System/Library/LaunchDaemons/ssh.plist"])
    if not r.ok:
        r = sudo_run(["systemsetup", "-setremotelogin", "on"])

    enabled = is_ssh_enabled()
    return {
        "status": "enabled" if enabled else "failed",
        "error": r.stderr if not enabled else None,
    }


def ssh_status() -> dict:
    """Check SSH/Remote Login state."""
    enabled = is_ssh_enabled()
    authorized_keys = Path.home() / ".ssh" / "authorized_keys"
    key_count = 0
    if authorized_keys.exists():
        key_count = len([l for l in authorized_keys.read_text().splitlines() if l.strip() and not l.startswith("#")])

    return {
        "enabled": enabled,
        "authorized_keys": key_count,
        "port": 22,
    }


def authorize_key(key_path: str = "") -> dict:
    """Add a public key to authorized_keys."""
    if not key_path:
        key_path = str(Path.home() / ".ssh" / "id_ed25519.pub")

    key_file = Path(key_path)
    if not key_file.exists():
        return {"status": "failed", "error": f"Key not found: {key_path}"}

    key_content = key_file.read_text().strip()
    auth_keys = Path.home() / ".ssh" / "authorized_keys"
    auth_keys.parent.mkdir(mode=0o700, exist_ok=True)

    if auth_keys.exists() and key_content in auth_keys.read_text():
        return {"status": "already_authorized", "key": key_path}

    with open(auth_keys, "a") as f:
        f.write(key_content + "\n")
    auth_keys.chmod(0o600)

    return {"status": "authorized", "key": key_path}


def tailscale_status() -> dict:
    """Get Tailscale node status."""
    r = run(["tailscale", "status", "--json"], timeout=10)
    if not r.ok:
        return {"status": "not_running", "error": r.stderr}

    import json as _json
    data = _json.loads(r.stdout)
    self_node = data.get("Self", {})
    peers = []
    for _, peer in data.get("Peer", {}).items():
        peers.append({
            "hostname": peer.get("HostName", ""),
            "os": peer.get("OS", ""),
            "ip": peer.get("TailscaleIPs", [""])[0],
            "online": peer.get("Online", False),
            "last_seen": peer.get("LastSeen", ""),
        })

    return {
        "hostname": self_node.get("HostName", ""),
        "ip": self_node.get("TailscaleIPs", [""])[0] if self_node.get("TailscaleIPs") else "",
        "online": self_node.get("Online", False),
        "peers": peers,
    }


def sharing_status() -> dict:
    """Check all sharing services."""
    return get_sharing_status()


def fleet_identity() -> dict:
    """Generate and write fleet identity."""
    ts = tailscale_status()

    hw_mem = run(["sysctl", "-n", "hw.memsize"])
    ram_gb = int(hw_mem.stdout.strip()) // (1024 ** 3) if hw_mem.ok else 0

    hw_cpu = run(["sysctl", "-n", "hw.ncpu"])
    cpu_cores = int(hw_cpu.stdout.strip()) if hw_cpu.ok else 0

    arch_r = run(["uname", "-m"])
    arch = arch_r.stdout.strip() if arch_r.ok else "unknown"

    sw_r = run(["sw_vers", "-productVersion"])
    os_version = sw_r.stdout.strip() if sw_r.ok else "unknown"

    build_r = run(["sw_vers", "-buildVersion"])
    os_build = build_r.stdout.strip() if build_r.ok else ""

    gpu_r = run(["system_profiler", "SPDisplaysDataType", "-detailLevel", "mini"])
    gpu = ""
    if gpu_r.ok:
        for line in gpu_r.stdout.splitlines():
            if "Chipset Model" in line:
                gpu = line.split(":")[-1].strip()
                break

    import shutil
    has_claude = shutil.which("claude") is not None
    has_codex = shutil.which("codex") is not None
    agents = []
    if has_claude:
        agents.append("claude-code")
    if has_codex:
        agents.append("codex-cli")

    py_r = run(["python3", "--version"])
    python_version = py_r.stdout.strip().split()[-1] if py_r.ok else ""

    hostname = ts.get("hostname", socket.gethostname())
    hostname_safe = hostname.lower().replace("’", "").replace("'", "").replace(" ", "-")
    ip = ts.get("ip", "")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    agents_toml = ", ".join(f'"{a}"' for a in agents)

    identity = f"""[machine]
hostname = "{hostname_safe}"
hostname_display = "{hostname}"
tailscale_ip = "{ip}"
os = "darwin"
arch = "{arch}"
os_version = "macOS {os_version} ({os_build})"
chip = "{gpu or 'unknown'}"

[capabilities]
gpu = "{gpu}"
ram_gb = {ram_gb}
cpu_cores = {cpu_cores}
has_claude = {'true' if has_claude else 'false'}
has_codex = {'true' if has_codex else 'false'}
agents = [{agents_toml}]
python_version = "{python_version}"

[health]
last_seen = "{now}"
nats_port = 4222
status = "online"

[network]
ssh_enabled = {'true' if is_ssh_enabled() else 'false'}
ssh_port = 22
"""

    FLEET_DIR.mkdir(parents=True, exist_ok=True)
    PEERS_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(identity)
    (PEERS_DIR / f"{hostname_safe}.toml").write_text(identity)

    return {
        "hostname": hostname_safe,
        "ip": ip,
        "file": str(IDENTITY_FILE),
        "ram_gb": ram_gb,
        "cpu_cores": cpu_cores,
        "gpu": gpu,
        "agents": agents,
    }


def fleet_peers() -> list[dict]:
    """List known fleet peers."""
    peers = []
    if not PEERS_DIR.exists():
        return peers
    for f in PEERS_DIR.glob("*.toml"):
        content = f.read_text()
        peer = {"file": f.name}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("["):
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                if key in ("hostname", "tailscale_ip", "os", "arch", "ram_gb",
                           "cpu_cores", "status", "last_seen", "ssh_enabled"):
                    peer[key] = val
        peers.append(peer)
    return peers


def sudo_test() -> dict:
    """Verify sudo-askpass works."""
    if not has_askpass():
        return {"status": "no_askpass", "path": askpass_path()}

    r = sudo_run(["echo", "ok"])
    return {
        "status": "ok" if r.ok and "ok" in r.stdout else "failed",
        "askpass": askpass_path(),
        "error": r.stderr if not r.ok else None,
    }
