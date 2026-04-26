"""macOS network configuration — networksetup, scutil, system_profiler."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run


@dataclass
class NetworkPort:
    name: str
    device: str
    address: str = ""
    status: str = "inactive"
    speed: str = ""
    media: str = ""


@dataclass
class DNSResolver:
    domain: str = ""
    nameservers: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    interface: str = ""


@dataclass
class ProxyConfig:
    http_enabled: bool = False
    http_proxy: str = ""
    https_enabled: bool = False
    https_proxy: str = ""
    socks_enabled: bool = False
    socks_proxy: str = ""
    exceptions: list[str] = field(default_factory=list)


@dataclass
class NetworkOverview:
    ports: list[NetworkPort] = field(default_factory=list)
    dns_resolvers: list[DNSResolver] = field(default_factory=list)
    proxy: Optional[ProxyConfig] = None
    active_interface: str = ""
    external_ip: str = ""


def get_hardware_ports() -> list[NetworkPort]:
    r = run(["networksetup", "-listallhardwareports"])
    if not r.ok:
        return []
    ports = []
    current: dict = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            if current:
                ports.append(NetworkPort(**current))
            current = {"name": line.split(":", 1)[1].strip(), "device": ""}
        elif line.startswith("Device:"):
            current["device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            current["address"] = line.split(":", 1)[1].strip()
    if current:
        ports.append(NetworkPort(**current))
    return ports


def get_dns_config() -> list[DNSResolver]:
    r = run(["scutil", "--dns"])
    if not r.ok:
        return []
    resolvers = []
    current: Optional[DNSResolver] = None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("resolver"):
            if current and current.nameservers:
                resolvers.append(current)
            current = DNSResolver()
        elif current:
            if line.startswith("domain"):
                current.domain = line.split(":", 1)[1].strip()
            elif line.startswith("nameserver"):
                ns = line.split("[", 1)
                if len(ns) > 1:
                    current.nameservers.append(ns[1].rstrip("]").strip().split("]")[0])
                else:
                    current.nameservers.append(line.split(":", 1)[1].strip())
            elif line.startswith("search domain"):
                current.search_domains.append(line.split(":", 1)[1].strip())
            elif line.startswith("if_index"):
                iface_match = re.search(r"\((\w+)\)", line)
                if iface_match:
                    current.interface = iface_match.group(1)
    if current and current.nameservers:
        resolvers.append(current)
    return resolvers


def get_network_overview() -> NetworkOverview:
    ports = get_hardware_ports()
    dns = get_dns_config()
    r = run(["scutil", "--nwi"])
    active = ""
    if r.ok:
        for line in r.stdout.splitlines():
            if "IPv4" in line and ":" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    active = parts[1].strip().split()[0] if parts[1].strip() else ""
                    break
    return NetworkOverview(ports=ports, dns_resolvers=dns, active_interface=active)
