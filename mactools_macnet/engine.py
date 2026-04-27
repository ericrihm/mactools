"""Engine for macOS network configuration intelligence."""

from __future__ import annotations

from dataclasses import dataclass

from mactools_core.network import (
    DNSResolver,
    NetworkOverview,
    get_network_overview,
)


# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------

@dataclass
class NetworkIssue:
    severity: str   # "critical" | "warning" | "info"
    title: str
    detail: str
    category: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
        }


def diagnose_network(overview: NetworkOverview) -> list[NetworkIssue]:
    """Check a NetworkOverview for common misconfigurations and issues."""
    issues: list[NetworkIssue] = []

    # --- DNS duplicate nameserver check ---
    seen_ns: dict[str, list[str]] = {}
    for resolver in overview.dns_resolvers:
        for ns in resolver.nameservers:
            seen_ns.setdefault(ns, []).append(resolver.domain or resolver.interface or "global")
    for ns, domains in seen_ns.items():
        if len(domains) > 2:
            issues.append(NetworkIssue(
                severity="warning",
                category="DNS",
                title=f"Nameserver {ns} appears in {len(domains)} resolvers",
                detail=f"Duplicate entries in: {', '.join(domains[:5])}. "
                       "This is usually harmless but may indicate leftover VPN configs.",
            ))

    # --- No active interface ---
    if not overview.active_interface:
        issues.append(NetworkIssue(
            severity="warning",
            category="Connectivity",
            title="No active network interface detected",
            detail="scutil --nwi returned no active IPv4 interface. "
                   "The Mac may be offline or all interfaces are inactive.",
        ))

    # --- No DNS resolvers ---
    if not overview.dns_resolvers:
        issues.append(NetworkIssue(
            severity="critical",
            category="DNS",
            title="No DNS resolvers configured",
            detail="scutil --dns returned no resolver entries. "
                   "DNS lookups will fail. Check System Settings > Wi-Fi/Ethernet > DNS.",
        ))

    # --- Proxy configured but no active interface ---
    if overview.proxy and overview.active_interface == "":
        if overview.proxy.http_enabled or overview.proxy.https_enabled or overview.proxy.socks_enabled:
            issues.append(NetworkIssue(
                severity="info",
                category="Proxy",
                title="Proxy configured but no active network interface",
                detail="A proxy is set but no active interface was found. "
                       "Proxy settings will have no effect until a network is available.",
            ))

    # --- Proxy with no exceptions ---
    if overview.proxy and (overview.proxy.http_enabled or overview.proxy.https_enabled):
        if not overview.proxy.exceptions:
            issues.append(NetworkIssue(
                severity="info",
                category="Proxy",
                title="HTTP proxy active with no bypass exceptions",
                detail="All traffic will route through the proxy including localhost and LAN. "
                       "Consider adding '*.local, 169.254/16, 127.0.0.1' to proxy exceptions.",
            ))

    # --- Too many DNS resolvers (potential VPN fragmentation) ---
    if len(overview.dns_resolvers) > 10:
        issues.append(NetworkIssue(
            severity="info",
            category="DNS",
            title=f"{len(overview.dns_resolvers)} DNS resolvers active",
            detail="A high resolver count often indicates multiple active VPN configurations "
                   "or split-DNS policies. This is normal for complex network environments.",
        ))

    # --- Ports with no device ---
    empty_ports = [p.name for p in overview.ports if not p.device]
    if empty_ports:
        issues.append(NetworkIssue(
            severity="info",
            category="Ports",
            title=f"{len(empty_ports)} hardware port(s) have no device assigned",
            detail=f"Ports without devices: {', '.join(empty_ports[:5])}. "
                   "These may be virtual ports or adapters not currently connected.",
        ))

    if not issues:
        issues.append(NetworkIssue(
            severity="ok",
            category="Overall",
            title="No network issues detected",
            detail="DNS, proxy, and interface configuration all appear normal.",
        ))

    return issues


# ---------------------------------------------------------------------------
# DNS chain explanation
# ---------------------------------------------------------------------------

def explain_dns_chain(resolvers: list[DNSResolver]) -> str:
    """Build a human-readable explanation of the DNS resolution chain."""
    if not resolvers:
        return "No DNS resolvers are configured on this system."

    lines = [f"DNS Resolution Chain — {len(resolvers)} resolver(s) active\n"]
    for i, r in enumerate(resolvers, 1):
        ns_list = ", ".join(r.nameservers) if r.nameservers else "none"
        domain_label = f" (domain: {r.domain})" if r.domain else ""
        iface_label = f" [interface: {r.interface}]" if r.interface else ""
        search_label = ""
        if r.search_domains:
            search_label = f"\n     Search: {', '.join(r.search_domains)}"
        lines.append(f"  {i:>2}. Resolver{domain_label}{iface_label}")
        lines.append(f"       Nameservers: {ns_list}{search_label}")

    # Classify resolver types
    system_count = sum(
        1 for r in resolvers
        if any(ns.startswith("192.168.") or ns.startswith("10.") or ns == "127.0.0.1"
               for ns in r.nameservers)
    )
    public_count = sum(
        1 for r in resolvers
        if any(ns in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1")
               for ns in r.nameservers)
    )
    vpn_count = len(resolvers) - system_count - public_count

    lines.append("")
    lines.append("  Summary:")
    if system_count:
        lines.append(f"    - {system_count} local/router resolver(s) (RFC-1918 or loopback)")
    if public_count:
        lines.append(f"    - {public_count} public resolver(s) (Google/Cloudflare)")
    if vpn_count > 0:
        lines.append(f"    - {vpn_count} other/VPN resolver(s)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def get_full_overview() -> NetworkOverview:
    return get_network_overview()
