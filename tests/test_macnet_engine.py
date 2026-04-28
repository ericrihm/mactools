"""Tests for mactools_macnet.engine — network diagnosis and DNS chain explanation."""

from __future__ import annotations

import pytest

from mactools_core.network import DNSResolver, NetworkOverview, NetworkPort, ProxyConfig
from mactools_macnet.engine import NetworkIssue, diagnose_network, explain_dns_chain


# ---------------------------------------------------------------------------
# Helpers / fixture factories
# ---------------------------------------------------------------------------

def _overview(
    ports: list[NetworkPort] | None = None,
    dns_resolvers: list[DNSResolver] | None = None,
    proxy: ProxyConfig | None = None,
    active_interface: str = "en0",
    external_ip: str = "",
) -> NetworkOverview:
    return NetworkOverview(
        ports=ports or [],
        dns_resolvers=dns_resolvers or [],
        proxy=proxy,
        active_interface=active_interface,
        external_ip=external_ip,
    )


def _resolver(
    nameservers: list[str] | None = None,
    domain: str = "",
    interface: str = "",
    search_domains: list[str] | None = None,
) -> DNSResolver:
    return DNSResolver(
        nameservers=nameservers or [],
        domain=domain,
        interface=interface,
        search_domains=search_domains or [],
    )


def _port(name: str, device: str = "en0") -> NetworkPort:
    return NetworkPort(name=name, device=device)


def _proxy(
    http_enabled: bool = False,
    https_enabled: bool = False,
    socks_enabled: bool = False,
    exceptions: list[str] | None = None,
) -> ProxyConfig:
    return ProxyConfig(
        http_enabled=http_enabled,
        https_enabled=https_enabled,
        socks_enabled=socks_enabled,
        exceptions=exceptions or [],
    )


# ===========================================================================
# diagnose_network
# ===========================================================================

class TestDiagnoseNetwork:
    """diagnose_network(overview) -> list[NetworkIssue]"""

    def test_healthy_overview_returns_single_ok_issue(self):
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert len(issues) == 1
        assert issues[0].severity == "ok"
        assert issues[0].category == "Overall"

    def test_no_active_interface_raises_warning(self):
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["8.8.8.8"])],
            active_interface="",
        )
        issues = diagnose_network(overview)
        connectivity_issues = [i for i in issues if i.category == "Connectivity"]
        assert len(connectivity_issues) == 1
        assert connectivity_issues[0].severity == "warning"
        assert "No active network interface" in connectivity_issues[0].title

    def test_no_dns_resolvers_returns_critical(self):
        overview = _overview(dns_resolvers=[], active_interface="en0")
        issues = diagnose_network(overview)
        dns_issues = [i for i in issues if i.category == "DNS"]
        assert any(i.severity == "critical" for i in dns_issues)
        assert any("No DNS resolvers" in i.title for i in dns_issues)

    def test_proxy_configured_but_no_interface_returns_info(self):
        # active_interface must be exactly "" (empty string, not None) per the engine check
        p = _proxy(http_enabled=True)
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["8.8.8.8"])],
            proxy=p,
            active_interface="",
        )
        issues = diagnose_network(overview)
        proxy_issues = [i for i in issues if i.category == "Proxy"]
        assert any("no active network interface" in i.title for i in proxy_issues)
        assert all(i.severity == "info" for i in proxy_issues)

    def test_http_proxy_with_no_exceptions_returns_info(self):
        p = _proxy(http_enabled=True, exceptions=[])
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            proxy=p,
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        bypass_issues = [i for i in issues if "bypass" in i.title.lower() or "no bypass" in i.title.lower()]
        assert len(bypass_issues) == 1
        assert bypass_issues[0].severity == "info"

    def test_https_proxy_with_no_exceptions_returns_info(self):
        p = _proxy(https_enabled=True, exceptions=[])
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            proxy=p,
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        bypass_issues = [i for i in issues if i.category == "Proxy" and "no bypass" in i.title.lower()]
        assert len(bypass_issues) == 1

    def test_proxy_with_exceptions_does_not_raise_no_exceptions_issue(self):
        p = _proxy(http_enabled=True, exceptions=["*.local", "127.0.0.1"])
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            proxy=p,
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert not any("no bypass" in i.title.lower() for i in issues)

    def test_socks_only_proxy_does_not_trigger_no_exceptions_issue(self):
        """Only HTTP/HTTPS proxies trigger the 'no exceptions' check — SOCKS alone does not."""
        p = _proxy(socks_enabled=True, http_enabled=False, https_enabled=False, exceptions=[])
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["10.0.0.1"])],
            proxy=p,
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert not any("no bypass" in i.title.lower() for i in issues)

    def test_more_than_ten_resolvers_returns_info(self):
        resolvers = [_resolver(nameservers=[f"10.0.0.{i}"]) for i in range(11)]
        overview = _overview(dns_resolvers=resolvers, active_interface="en0")
        issues = diagnose_network(overview)
        dns_count_issues = [i for i in issues if "resolvers active" in i.title]
        assert len(dns_count_issues) == 1
        assert dns_count_issues[0].severity == "info"
        assert "11" in dns_count_issues[0].title

    def test_exactly_ten_resolvers_does_not_trigger_high_count_issue(self):
        resolvers = [_resolver(nameservers=[f"10.0.0.{i}"]) for i in range(10)]
        overview = _overview(dns_resolvers=resolvers, active_interface="en0")
        issues = diagnose_network(overview)
        assert not any("resolvers active" in i.title for i in issues)

    def test_ports_without_device_returns_info(self):
        ports = [
            _port("Wi-Fi", device="en0"),
            _port("Thunderbolt 1", device=""),
            _port("Thunderbolt 2", device=""),
        ]
        overview = _overview(
            ports=ports,
            dns_resolvers=[_resolver(nameservers=["8.8.8.8"])],
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        port_issues = [i for i in issues if i.category == "Ports"]
        assert len(port_issues) == 1
        assert port_issues[0].severity == "info"
        assert "2" in port_issues[0].title

    def test_all_ports_have_devices_no_port_issue(self):
        ports = [_port("Wi-Fi", device="en0"), _port("Ethernet", device="en1")]
        overview = _overview(
            ports=ports,
            dns_resolvers=[_resolver(nameservers=["8.8.8.8"])],
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert not any(i.category == "Ports" for i in issues)

    def test_duplicate_nameserver_in_more_than_two_resolvers_triggers_warning(self):
        shared_ns = "8.8.8.8"
        resolvers = [
            _resolver(nameservers=[shared_ns], domain=f"domain{i}.local")
            for i in range(3)
        ]
        overview = _overview(dns_resolvers=resolvers, active_interface="en0")
        issues = diagnose_network(overview)
        dup_issues = [i for i in issues if "Nameserver" in i.title and "appears in" in i.title]
        assert len(dup_issues) == 1
        assert dup_issues[0].severity == "warning"
        assert shared_ns in dup_issues[0].title

    def test_duplicate_nameserver_in_exactly_two_resolvers_does_not_trigger(self):
        """Duplicate nameserver only flagged if it appears in > 2 resolvers."""
        shared_ns = "1.1.1.1"
        resolvers = [
            _resolver(nameservers=[shared_ns], domain="vpn.local"),
            _resolver(nameservers=[shared_ns], domain="corp.local"),
        ]
        overview = _overview(dns_resolvers=resolvers, active_interface="en0")
        issues = diagnose_network(overview)
        assert not any("appears in" in i.title for i in issues)

    def test_issue_to_dict_contains_all_required_keys(self):
        overview = _overview(active_interface="")  # triggers Connectivity warning
        issues = diagnose_network(overview)
        for issue in issues:
            d = issue.to_dict()
            assert "severity" in d
            assert "category" in d
            assert "title" in d
            assert "detail" in d

    def test_multiple_issues_can_be_returned_simultaneously(self):
        """Empty DNS + no active interface + ports without device all fire at once."""
        ports = [_port("USB Adapter", device="")]
        overview = _overview(
            ports=ports,
            dns_resolvers=[],
            active_interface="",
        )
        issues = diagnose_network(overview)
        categories = {i.category for i in issues}
        assert "DNS" in categories
        assert "Connectivity" in categories
        assert "Ports" in categories

    def test_empty_ports_list_produces_no_port_issue(self):
        overview = _overview(
            ports=[],
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert not any(i.category == "Ports" for i in issues)

    def test_no_issues_result_has_ok_severity(self):
        overview = _overview(
            dns_resolvers=[_resolver(nameservers=["192.168.1.1"])],
            active_interface="en0",
        )
        issues = diagnose_network(overview)
        assert all(i.severity == "ok" for i in issues)


# ===========================================================================
# explain_dns_chain
# ===========================================================================

class TestExplainDnsChain:
    """explain_dns_chain(resolvers) -> str"""

    def test_empty_resolvers_returns_no_resolvers_message(self):
        result = explain_dns_chain([])
        assert "No DNS resolvers" in result

    def test_single_resolver_contains_nameserver(self):
        resolvers = [_resolver(nameservers=["192.168.1.1"])]
        result = explain_dns_chain(resolvers)
        assert "192.168.1.1" in result

    def test_resolver_count_in_header(self):
        resolvers = [
            _resolver(nameservers=["8.8.8.8"]),
            _resolver(nameservers=["1.1.1.1"]),
        ]
        result = explain_dns_chain(resolvers)
        assert "2 resolver(s)" in result

    def test_domain_label_present_when_set(self):
        resolvers = [_resolver(nameservers=["10.0.0.1"], domain="corp.local")]
        result = explain_dns_chain(resolvers)
        assert "corp.local" in result

    def test_interface_label_present_when_set(self):
        resolvers = [_resolver(nameservers=["10.0.0.1"], interface="utun0")]
        result = explain_dns_chain(resolvers)
        assert "utun0" in result

    def test_search_domains_included_in_output(self):
        resolvers = [_resolver(nameservers=["192.168.1.1"], search_domains=["example.com"])]
        result = explain_dns_chain(resolvers)
        assert "example.com" in result

    def test_local_resolver_classified_as_system(self):
        resolvers = [_resolver(nameservers=["192.168.1.1"])]
        result = explain_dns_chain(resolvers)
        assert "local/router" in result

    def test_loopback_resolver_classified_as_system(self):
        resolvers = [_resolver(nameservers=["127.0.0.1"])]
        result = explain_dns_chain(resolvers)
        assert "local/router" in result

    def test_google_dns_classified_as_public(self):
        resolvers = [_resolver(nameservers=["8.8.8.8"])]
        result = explain_dns_chain(resolvers)
        assert "public" in result

    def test_cloudflare_dns_classified_as_public(self):
        resolvers = [_resolver(nameservers=["1.1.1.1"])]
        result = explain_dns_chain(resolvers)
        assert "public" in result

    def test_vpn_resolver_classified_as_other(self):
        # A non-RFC1918, non-loopback, non-well-known-public NS
        resolvers = [_resolver(nameservers=["172.16.200.1"])]
        result = explain_dns_chain(resolvers)
        assert "other/VPN" in result

    def test_resolver_with_no_nameservers_shows_none(self):
        resolvers = [_resolver(nameservers=[])]
        result = explain_dns_chain(resolvers)
        assert "none" in result

    def test_summary_section_present_for_multiple_types(self):
        resolvers = [
            _resolver(nameservers=["192.168.1.1"]),
            _resolver(nameservers=["8.8.8.8"]),
        ]
        result = explain_dns_chain(resolvers)
        assert "Summary:" in result
