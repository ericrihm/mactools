"""Tests for mactools_core parser functions across all modules."""

from __future__ import annotations

import plistlib
from unittest.mock import patch, MagicMock

import pytest

from mactools_core.runner import RunResult


def _ok(stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(stdout=stdout, stderr=stderr, returncode=0, ok=True)


def _fail(stderr: str = "error") -> RunResult:
    return RunResult(stdout="", stderr=stderr, returncode=1, ok=False)


# ===========================================================================
# unified_log — parse_log_output
# ===========================================================================

class TestParseLogOutput:
    def setup_method(self):
        from mactools_core.unified_log import parse_log_output
        self.parse = parse_log_output

    def test_parses_well_formed_entry(self):
        line = (
            "2024-01-15 10:23:45.123456+0000  "
            "0xabc123  error  0xdef456  "
            "42  0  kernel: (com.apple.driver) [MySub] [MyCat] Something went wrong"
        )
        entries = self.parse(line)
        assert len(entries) == 1
        e = entries[0]
        assert e.level == "error"
        assert e.pid == 42
        assert "Something went wrong" in e.message

    def test_skips_header_line(self):
        text = "Timestamp                       Thread     Type\n"
        entries = self.parse(text)
        assert entries == []

    def test_skips_separator_line(self):
        text = "--- Some separator ---\n"
        entries = self.parse(text)
        assert entries == []

    def test_skips_blank_lines(self):
        entries = self.parse("\n\n\n")
        assert entries == []

    def test_continuation_line_appended_to_previous_message(self):
        line1 = (
            "2024-01-15 10:23:45.123456+0000  "
            "0xabc123  error  0xdef456  "
            "42  0  kernel: (sub) [cat] First line"
        )
        continuation = "    continued here"
        text = f"{line1}\n{continuation}"
        entries = self.parse(text)
        assert len(entries) == 1
        assert "continued here" in entries[0].message

    def test_log_entry_datetime_property(self):
        line = (
            "2024-03-10 14:30:00.000000+0000  "
            "0x1  default  0x2  "
            "100  0  launchd: (sub) [cat] msg"
        )
        entries = self.parse(line)
        assert len(entries) == 1
        dt = entries[0].datetime
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 3

    def test_multiple_entries(self):
        lines = []
        for i in range(3):
            lines.append(
                f"2024-01-15 10:2{i}:00.000000+0000  "
                f"0xabc{i}  error  0xdef{i}  "
                f"{i}  0  proc{i}: msg{i}"
            )
        entries = self.parse("\n".join(lines))
        assert len(entries) == 3


# ===========================================================================
# unified_log — log_stats parsing
# ===========================================================================

class TestLogStats:
    def test_parses_total_error_fault(self):
        from mactools_core.unified_log import log_stats
        output = "Total: 123456\nError: 42\nFault: 7\n"
        with patch("mactools_core.unified_log.run", return_value=_ok(stdout=output)):
            stats = log_stats()
        assert stats.total_events == 123456
        assert stats.error_count == 42
        assert stats.fault_count == 7

    def test_returns_empty_stats_on_failure(self):
        from mactools_core.unified_log import log_stats, LogStats
        with patch("mactools_core.unified_log.run", return_value=_fail()):
            stats = log_stats()
        assert stats.total_events == 0
        assert stats.error_count == 0


# ===========================================================================
# system_profiler — _parse_cores, _parse_memory
# ===========================================================================

class TestSystemProfilerParsers:
    def test_parse_cores_apple_silicon_format(self):
        from mactools_core.system_profiler import _parse_cores
        total, perf, eff = _parse_cores("proc 10:4:6")
        assert total == 10
        assert perf == 4
        assert eff == 6

    def test_parse_cores_plain_number(self):
        from mactools_core.system_profiler import _parse_cores
        total, perf, eff = _parse_cores("8")
        assert total == 8
        assert perf == 0
        assert eff == 0

    def test_parse_cores_raw_integer_string(self):
        from mactools_core.system_profiler import _parse_cores
        total, perf, eff = _parse_cores("4")
        assert total == 4

    def test_parse_cores_empty_string(self):
        from mactools_core.system_profiler import _parse_cores
        total, perf, eff = _parse_cores("")
        assert total == 0

    def test_parse_memory_gb(self):
        from mactools_core.system_profiler import _parse_memory
        assert _parse_memory("16 GB") == 16

    def test_parse_memory_gb_lowercase(self):
        from mactools_core.system_profiler import _parse_memory
        assert _parse_memory("32 gb") == 32

    def test_parse_memory_no_space(self):
        from mactools_core.system_profiler import _parse_memory
        assert _parse_memory("8GB") == 8

    def test_parse_memory_empty(self):
        from mactools_core.system_profiler import _parse_memory
        assert _parse_memory("") == 0

    def test_parse_memory_no_match(self):
        from mactools_core.system_profiler import _parse_memory
        assert _parse_memory("unknown") == 0


class TestGetHardware:
    def test_returns_hardware_info_from_plist(self):
        from mactools_core.system_profiler import get_hardware
        items = [{
            "machine_name": "Mac mini",
            "chip_type": "Apple M2",
            "number_processors": "proc 8:4:4",
            "physical_memory": "16 GB",
            "serial_number": "SN12345",
            "os_version": "macOS 14",
            "local_host_name": "mymac",
        }]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            hw = get_hardware()
        assert hw.model == "Mac mini"
        assert hw.chip == "Apple M2"
        assert hw.cores_total == 8
        assert hw.memory_gb == 16
        assert hw.serial == "SN12345"
        assert hw.hostname == "mymac"

    def test_returns_empty_info_when_no_data(self):
        from mactools_core.system_profiler import get_hardware, HardwareInfo
        with patch("mactools_core.system_profiler.run_plist", return_value=None):
            hw = get_hardware()
        assert hw.model == ""
        assert hw.cores_total == 0


class TestGetFirewall:
    def test_returns_enabled_true_when_not_off(self):
        from mactools_core.system_profiler import get_firewall
        items = [{"spfirewall_globalstate": "spfirewall_globalstate_on"}]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            fw = get_firewall()
        assert fw.enabled is True

    def test_returns_enabled_false_when_off(self):
        from mactools_core.system_profiler import get_firewall
        items = [{"spfirewall_globalstate": "spfirewall_globalstate_off"}]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            fw = get_firewall()
        assert fw.enabled is False

    def test_stealth_mode_yes(self):
        from mactools_core.system_profiler import get_firewall
        items = [{
            "spfirewall_globalstate": "spfirewall_globalstate_on",
            "spfirewall_stealthmode": "Yes",
        }]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            fw = get_firewall()
        assert fw.stealth is True

    def test_allowed_apps_from_dict(self):
        from mactools_core.system_profiler import get_firewall
        items = [{
            "spfirewall_globalstate": "spfirewall_globalstate_on",
            "spfirewall_applications": {"com.example.app": "allow", "com.other.app": "allow"},
        }]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            fw = get_firewall()
        assert "com.example.app" in fw.allowed_apps

    def test_allowed_apps_from_list(self):
        from mactools_core.system_profiler import get_firewall
        items = [{
            "spfirewall_globalstate": "spfirewall_globalstate_on",
            "spfirewall_applications": [{"_name": "MyApp"}, {"_name": "OtherApp"}],
        }]
        plist_data = [{"_items": items}]
        with patch("mactools_core.system_profiler.run_plist", return_value=plist_data):
            fw = get_firewall()
        assert "MyApp" in fw.allowed_apps


# ===========================================================================
# launchctl — list_services, _classify_source, vendor property
# ===========================================================================

class TestLaunchctlParsers:
    def test_list_services_parses_running(self):
        from mactools_core.launchctl import list_services
        output = (
            "PID\tStatus\tLabel\n"
            "12345\t0\tcom.apple.Finder\n"
            "-\t0\tcom.google.keystone.agent\n"
        )
        with patch("mactools_core.launchctl.run", return_value=_ok(stdout=output)):
            services = list_services()
        assert len(services) == 2
        finder = services[0]
        assert finder.label == "com.apple.Finder"
        assert finder.pid == 12345
        assert finder.running is True

    def test_list_services_parses_stopped(self):
        from mactools_core.launchctl import list_services
        output = "PID\tStatus\tLabel\n-\t0\tcom.google.keystone.agent\n"
        with patch("mactools_core.launchctl.run", return_value=_ok(stdout=output)):
            services = list_services()
        assert services[0].pid == -1
        assert services[0].running is False

    def test_list_services_returns_empty_on_failure(self):
        from mactools_core.launchctl import list_services
        with patch("mactools_core.launchctl.run", return_value=_fail()):
            services = list_services()
        assert services == []

    def test_is_apple_set_for_com_apple_prefix(self):
        from mactools_core.launchctl import list_services
        output = "PID\tStatus\tLabel\n-\t0\tcom.apple.Safari\n"
        with patch("mactools_core.launchctl.run", return_value=_ok(stdout=output)):
            services = list_services()
        assert services[0].is_apple is True

    def test_is_apple_false_for_third_party(self):
        from mactools_core.launchctl import list_services
        output = "PID\tStatus\tLabel\n-\t0\tcom.docker.helper\n"
        with patch("mactools_core.launchctl.run", return_value=_ok(stdout=output)):
            services = list_services()
        assert services[0].is_apple is False

    def test_status_nonzero_parsed(self):
        from mactools_core.launchctl import list_services
        output = "PID\tStatus\tLabel\n-\t78\tcom.example.crasher\n"
        with patch("mactools_core.launchctl.run", return_value=_ok(stdout=output)):
            services = list_services()
        assert services[0].status == 78

    def test_classify_source_system(self):
        from mactools_core.launchctl import _classify_source
        from pathlib import Path
        assert _classify_source(Path("/System/Library/LaunchDaemons/foo.plist")) == "system"

    def test_classify_source_user(self):
        from mactools_core.launchctl import _classify_source
        from pathlib import Path
        import os
        home = Path.home()
        assert _classify_source(home / "Library" / "LaunchAgents" / "foo.plist") == "user"

    def test_classify_source_global(self):
        from mactools_core.launchctl import _classify_source
        from pathlib import Path
        assert _classify_source(Path("/Library/LaunchDaemons/foo.plist")) == "global"

    def test_vendor_property_google(self):
        from mactools_core.launchctl import LaunchService
        svc = LaunchService(label="com.google.keystone.agent", is_apple=False)
        assert svc.vendor == "Google"

    def test_vendor_property_apple(self):
        from mactools_core.launchctl import LaunchService
        svc = LaunchService(label="com.apple.Finder", is_apple=True)
        assert svc.vendor == "Apple"

    def test_vendor_property_third_party(self):
        from mactools_core.launchctl import LaunchService
        svc = LaunchService(label="com.unknown.tool", is_apple=False)
        assert svc.vendor == "Third-party"


# ===========================================================================
# security — SIP, Gatekeeper, FileVault, codesign parsing
# ===========================================================================

class TestSecurityParsers:
    def test_sip_enabled(self):
        from mactools_core.security import get_sip_status
        with patch("mactools_core.security.run", return_value=_ok(stdout="System Integrity Protection status: enabled.")):
            status = get_sip_status()
        assert status.enabled is True

    def test_sip_disabled(self):
        from mactools_core.security import get_sip_status
        with patch("mactools_core.security.run", return_value=_ok(stdout="System Integrity Protection status: disabled.")):
            status = get_sip_status()
        assert status.enabled is False

    def test_gatekeeper_enabled(self):
        from mactools_core.security import get_gatekeeper_status
        with patch("mactools_core.security.run", return_value=_ok(stderr="assessments enabled")):
            status = get_gatekeeper_status()
        assert status.enabled is True

    def test_gatekeeper_disabled(self):
        from mactools_core.security import get_gatekeeper_status
        with patch("mactools_core.security.run", return_value=_ok(stderr="assessments disabled")):
            status = get_gatekeeper_status()
        assert status.enabled is False

    def test_filevault_enabled(self):
        from mactools_core.security import get_filevault_status
        with patch("mactools_core.security.run", return_value=_ok(stdout="FileVault is On.")):
            status = get_filevault_status()
        assert status.enabled is True

    def test_filevault_disabled(self):
        from mactools_core.security import get_filevault_status
        with patch("mactools_core.security.run", return_value=_ok(stdout="FileVault is Off.")):
            status = get_filevault_status()
        assert status.enabled is False

    def test_check_codesign_parses_authority_and_team(self):
        from mactools_core.security import check_codesign
        codesign_output = (
            "Identifier=com.example.app\n"
            "TeamIdentifier=ABCD1234\n"
            "Format=app bundle\n"
            "Authority=Apple Root CA\n"
            "Authority=Developer ID Certification Authority\n"
        )
        spctl_result = _ok(stdout="accepted\nsource=Notarized Developer ID")
        with patch("mactools_core.security.run") as mock_run:
            mock_run.side_effect = [
                _ok(stdout="", stderr=codesign_output),  # codesign -dvvv
                spctl_result,                             # spctl --assess
                _fail(),                                  # codesign entitlements
            ]
            sig = check_codesign("/Applications/MyApp.app")
        assert sig.signed is True
        assert sig.identifier == "com.example.app"
        assert sig.team_id == "ABCD1234"
        assert len(sig.authority_chain) == 2

    def test_check_codesign_unsigned_app(self):
        from mactools_core.security import check_codesign
        with patch("mactools_core.security.run", return_value=RunResult(
            stdout="", stderr="/tmp/fake: not signed", returncode=1, ok=False
        )):
            sig = check_codesign("/tmp/fake")
        assert sig.signed is False
        assert "not signed" in sig.error


# ===========================================================================
# defaults — list_domains, read_domain
# ===========================================================================

class TestDefaultsParsers:
    def test_list_domains_splits_on_comma(self):
        from mactools_core.defaults import list_domains
        output = "com.apple.finder, com.apple.dock, NSGlobalDomain"
        with patch("mactools_core.defaults.run", return_value=_ok(stdout=output)):
            domains = list_domains()
        assert "com.apple.finder" in domains
        assert "com.apple.dock" in domains
        assert "NSGlobalDomain" in domains
        assert len(domains) == 3

    def test_list_domains_returns_empty_on_failure(self):
        from mactools_core.defaults import list_domains
        with patch("mactools_core.defaults.run", return_value=_fail()):
            domains = list_domains()
        assert domains == []

    def test_read_domain_returns_domain_with_keys(self):
        from mactools_core.defaults import read_domain
        plist_data = {"AppleShowAllFiles": True, "ShowPathbar": False}
        plist_bytes = plistlib.dumps(plist_data).decode()
        with patch("mactools_core.defaults.run", return_value=_ok(stdout=plist_bytes)):
            domain = read_domain("com.apple.finder")
        assert domain.name == "com.apple.finder"
        assert "AppleShowAllFiles" in domain.keys
        assert domain.key_count == 2

    def test_read_domain_error_on_failure(self):
        from mactools_core.defaults import read_domain
        with patch("mactools_core.defaults.run", return_value=_fail(stderr="Domain not found")):
            domain = read_domain("nonexistent.domain")
        assert domain.error == "Domain not found"
        assert domain.keys == {}

    def test_read_domain_error_on_bad_plist(self):
        from mactools_core.defaults import read_domain
        with patch("mactools_core.defaults.run", return_value=_ok(stdout="this is not xml")):
            domain = read_domain("bad.domain")
        assert domain.error != ""

    def test_domain_key_count_property(self):
        from mactools_core.defaults import DefaultsDomain
        d = DefaultsDomain(name="test", keys={"a": 1, "b": 2, "c": 3})
        assert d.key_count == 3


# ===========================================================================
# network — get_hardware_ports, get_dns_config
# ===========================================================================

class TestNetworkParsers:
    def test_get_hardware_ports_parses_ports(self):
        from mactools_core.network import get_hardware_ports
        output = (
            "Hardware Port: Wi-Fi\n"
            "Device: en0\n"
            "Ethernet Address: aa:bb:cc:dd:ee:ff\n"
            "\n"
            "Hardware Port: Ethernet\n"
            "Device: en1\n"
            "Ethernet Address: 11:22:33:44:55:66\n"
        )
        with patch("mactools_core.network.run", return_value=_ok(stdout=output)):
            ports = get_hardware_ports()
        assert len(ports) == 2
        wifi = ports[0]
        assert wifi.name == "Wi-Fi"
        assert wifi.device == "en0"
        assert wifi.address == "aa:bb:cc:dd:ee:ff"

    def test_get_hardware_ports_returns_empty_on_failure(self):
        from mactools_core.network import get_hardware_ports
        with patch("mactools_core.network.run", return_value=_fail()):
            ports = get_hardware_ports()
        assert ports == []

    def test_get_dns_config_parses_resolvers(self):
        from mactools_core.network import get_dns_config
        # Use format WITHOUT brackets so the simple else-branch fires:
        # "nameserver : 192.168.1.1" splits on ":" giving " 192.168.1.1"
        output = (
            "DNS configuration\n\n"
            "resolver #1\n"
            "  domain   : local\n"
            "  nameserver : 192.168.1.1\n"
            "  nameserver : 8.8.8.8\n"
            "\n"
            "resolver #2\n"
            "  nameserver : 1.1.1.1\n"
        )
        with patch("mactools_core.network.run", return_value=_ok(stdout=output)):
            resolvers = get_dns_config()
        # Both resolvers have nameservers, so both should be included
        assert len(resolvers) == 2
        assert "192.168.1.1" in resolvers[0].nameservers
        assert "8.8.8.8" in resolvers[0].nameservers
        assert resolvers[0].domain == "local"

    def test_get_dns_config_returns_empty_on_failure(self):
        from mactools_core.network import get_dns_config
        with patch("mactools_core.network.run", return_value=_fail()):
            resolvers = get_dns_config()
        assert resolvers == []

    def test_resolver_without_nameservers_excluded(self):
        from mactools_core.network import get_dns_config
        output = "resolver #1\n  domain   : empty\n"
        with patch("mactools_core.network.run", return_value=_ok(stdout=output)):
            resolvers = get_dns_config()
        assert resolvers == []


# ===========================================================================
# diskutil — list_apfs_containers parsing
# ===========================================================================

class TestDiskutilParsers:
    def test_list_apfs_containers_from_plist(self):
        from mactools_core.diskutil import list_apfs_containers
        data = {
            "Containers": [{
                "ContainerReference": "disk1",
                "CapacityCeiling": 500_000_000_000,
                "CapacityFree": 200_000_000_000,
                "Volumes": [
                    {
                        "Name": "Macintosh HD",
                        "DeviceIdentifier": "disk1s1",
                        "Roles": ["System"],
                        "CapacityInUse": 50_000_000_000,
                        "Encryption": False,
                        "Mounted": True,
                        "MountPoint": "/",
                    }
                ],
            }]
        }
        with patch("mactools_core.diskutil.run_plist", return_value=data):
            containers = list_apfs_containers()
        assert len(containers) == 1
        c = containers[0]
        assert c.identifier == "disk1"
        assert c.capacity_bytes == 500_000_000_000
        assert c.free_bytes == 200_000_000_000
        assert len(c.volumes) == 1
        v = c.volumes[0]
        assert v.name == "Macintosh HD"
        assert v.role == "System"
        assert v.mounted is True
        assert v.mount_point == "/"

    def test_list_apfs_containers_returns_empty_when_no_data(self):
        from mactools_core.diskutil import list_apfs_containers
        with patch("mactools_core.diskutil.run_plist", return_value=None):
            containers = list_apfs_containers()
        assert containers == []

    def test_volume_encrypted_flag(self):
        from mactools_core.diskutil import list_apfs_containers
        data = {
            "Containers": [{
                "ContainerReference": "disk1",
                "CapacityCeiling": 100,
                "CapacityFree": 50,
                "Volumes": [{
                    "Name": "Data",
                    "DeviceIdentifier": "disk1s2",
                    "Roles": ["Data"],
                    "CapacityInUse": 20,
                    "Encryption": True,
                    "Mounted": True,
                    "MountPoint": "/System/Volumes/Data",
                }],
            }]
        }
        with patch("mactools_core.diskutil.run_plist", return_value=data):
            containers = list_apfs_containers()
        assert containers[0].volumes[0].encrypted is True

    def test_get_disk_info_from_plist(self):
        from mactools_core.diskutil import get_disk_info
        data = {
            "MediaName": "APPLE SSD AP0512",
            "TotalSize": 512_000_000_000,
            "MediaType": "SSD",
            "Internal": True,
            "Removable": False,
            "SMARTStatus": "Verified",
        }
        with patch("mactools_core.diskutil.run_plist", return_value=data):
            info = get_disk_info("disk0")
        assert info.name == "APPLE SSD AP0512"
        assert info.size_bytes == 512_000_000_000
        assert info.smart_status == "Verified"
        assert info.internal is True


# ===========================================================================
# power — get_power_settings, get_sleep_preventers, get_thermal_state
# ===========================================================================

class TestPowerParsers:
    def test_get_power_settings_parses_sleep(self):
        from mactools_core.power import get_power_settings
        output = (
            "Battery Power:\n"
            " sleep                5\n"
            " displaysleep         3\n"
            " disksleep            10\n"
            " womp                 0\n"
            " powernap             1\n"
        )
        with patch("mactools_core.power.run", return_value=_ok(stdout=output)):
            settings = get_power_settings()
        assert settings.sleep_timer == 5
        assert settings.display_sleep == 3
        assert settings.disk_sleep == 10
        assert settings.wake_on_lan is False
        assert settings.power_nap is True

    def test_get_power_settings_returns_defaults_on_failure(self):
        from mactools_core.power import get_power_settings
        with patch("mactools_core.power.run", return_value=_fail()):
            settings = get_power_settings()
        assert settings.sleep_timer == 0

    def test_get_sleep_preventers_parses_assertions(self):
        from mactools_core.power import get_sleep_preventers
        output = (
            "Assertion status system-wide:\n"
            'pid 999(mds_stores): [0x0001234] PreventUserIdleSystemSleep named: "Spotlight indexing"\n'
            'pid 42(coreaudiod): [0x0005678] PreventUserIdleDisplaySleep named: "Audio is playing"\n'
        )
        with patch("mactools_core.power.run", return_value=_ok(stdout=output)):
            preventers = get_sleep_preventers()
        assert len(preventers) == 2
        assert preventers[0].pid == 999
        assert preventers[0].name == "mds_stores"
        assert preventers[0].assertion_type == "PreventUserIdleSystemSleep"
        assert preventers[0].detail == "Spotlight indexing"

    def test_get_sleep_preventers_empty_on_failure(self):
        from mactools_core.power import get_sleep_preventers
        with patch("mactools_core.power.run", return_value=_fail()):
            preventers = get_sleep_preventers()
        assert preventers == []

    def test_get_thermal_state_throttled(self):
        from mactools_core.power import get_thermal_state
        # The code checks for "speed limit" (spaces) then uses regex cpu_speed_limit
        # (underscores). Both must be present to correctly parse a non-100 limit.
        output = "CPU speed limit\ncpu_speed_limit = 75\n"
        with patch("mactools_core.power.run", return_value=_ok(stdout=output)):
            state = get_thermal_state()
        assert state.level == "throttled"
        assert state.cpu_speed_limit == 75

    def test_get_thermal_state_critical(self):
        from mactools_core.power import get_thermal_state
        output = "CPU speed limit\ncpu_speed_limit = 30\n"
        with patch("mactools_core.power.run", return_value=_ok(stdout=output)):
            state = get_thermal_state()
        assert state.level == "critical"
        assert state.cpu_speed_limit == 30

    def test_get_thermal_state_nominal(self):
        from mactools_core.power import get_thermal_state
        output = "CPU speed limit\ncpu_speed_limit = 100\n"
        with patch("mactools_core.power.run", return_value=_ok(stdout=output)):
            state = get_thermal_state()
        assert state.level == "nominal"

    def test_get_thermal_state_returns_default_on_failure(self):
        from mactools_core.power import get_thermal_state
        with patch("mactools_core.power.run", return_value=_fail()):
            state = get_thermal_state()
        assert state.level == "nominal"


# ===========================================================================
# spotlight — get_index_status, search result parsing
# ===========================================================================

class TestSpotlightParsers:
    def test_get_index_status_enabled(self):
        from mactools_core.spotlight import get_index_status
        output = (
            "/:\n"
            "    Indexing enabled.\n"
            "/Volumes/ExternalDrive:\n"
            "    Indexing disabled.\n"
        )
        with patch("mactools_core.spotlight.run", return_value=_ok(stdout=output)):
            statuses = get_index_status()
        assert len(statuses) == 2
        assert statuses[0].volume == "/"
        assert statuses[0].enabled is True
        assert statuses[1].volume == "/Volumes/ExternalDrive"
        assert statuses[1].enabled is False

    def test_get_index_status_empty_on_failure(self):
        from mactools_core.spotlight import get_index_status
        with patch("mactools_core.spotlight.run", return_value=_fail()):
            statuses = get_index_status()
        assert statuses == []

    def test_search_returns_file_list(self):
        from mactools_core.spotlight import search
        output = "/Users/user/file1.pdf\n/Users/user/file2.pdf\n"
        with patch("mactools_core.spotlight.run", return_value=_ok(stdout=output)):
            results = search("kind:pdf")
        assert len(results) == 2
        assert "/Users/user/file1.pdf" in results

    def test_search_respects_limit(self):
        from mactools_core.spotlight import search
        lines = "\n".join(f"/file{i}.txt" for i in range(100))
        with patch("mactools_core.spotlight.run", return_value=_ok(stdout=lines)):
            results = search("query", limit=10)
        assert len(results) == 10

    def test_search_returns_empty_on_failure(self):
        from mactools_core.spotlight import search
        with patch("mactools_core.spotlight.run", return_value=_fail()):
            results = search("query")
        assert results == []


# ===========================================================================
# shortcuts — list_shortcuts parsing
# ===========================================================================

class TestShortcutsParsers:
    def test_list_shortcuts_parses_names(self):
        from mactools_core.shortcuts import list_shortcuts
        output = "Morning Routine\nCompress Images\nSend Summary\n"
        with patch("mactools_core.shortcuts.run", return_value=_ok(stdout=output)):
            shortcuts = list_shortcuts()
        assert len(shortcuts) == 3
        assert shortcuts[0].name == "Morning Routine"
        assert shortcuts[2].name == "Send Summary"

    def test_list_shortcuts_empty_on_failure(self):
        from mactools_core.shortcuts import list_shortcuts
        with patch("mactools_core.shortcuts.run", return_value=_fail()):
            shortcuts = list_shortcuts()
        assert shortcuts == []

    def test_list_shortcuts_skips_blank_lines(self):
        from mactools_core.shortcuts import list_shortcuts
        output = "Shortcut One\n\n\nShortcut Two\n"
        with patch("mactools_core.shortcuts.run", return_value=_ok(stdout=output)):
            shortcuts = list_shortcuts()
        assert len(shortcuts) == 2


# ===========================================================================
# macsec engine — compute_security_score
# ===========================================================================

class TestComputeSecurityScore:
    def setup_method(self):
        from mactools_macsec.engine import SecurityFinding, compute_security_score
        self.Finding = SecurityFinding
        self.compute = compute_security_score

    def test_all_ok_gives_100(self):
        findings = [
            self.Finding("SIP", "ok", "", category="SIP"),
            self.Finding("Gatekeeper", "ok", "", category="Gatekeeper"),
            self.Finding("FileVault", "ok", "", category="FileVault"),
            self.Finding("Firewall", "ok", "", category="Firewall"),
            self.Finding("SSH", "ok", "", category="Remote"),
            self.Finding("Auth", "ok", "", category="Auth"),
        ]
        result = self.compute(findings)
        assert result["score"] == 100
        assert result["max"] == 100

    def test_critical_finding_reduces_score(self):
        findings = [
            self.Finding("SIP disabled", "critical", "", category="SIP"),
            self.Finding("Gatekeeper", "ok", "", category="Gatekeeper"),
            self.Finding("FileVault", "ok", "", category="FileVault"),
            self.Finding("Firewall", "ok", "", category="Firewall"),
            self.Finding("Auth", "ok", "", category="Auth"),
        ]
        result = self.compute(findings)
        assert result["score"] < 100

    def test_warning_reduces_score_less_than_critical(self):
        from mactools_macsec.engine import SecurityFinding, compute_security_score

        findings_warn = [
            SecurityFinding("Remote", "warning", "", category="Remote"),
        ]
        findings_crit = [
            SecurityFinding("Remote", "critical", "", category="Remote"),
        ]
        score_warn = compute_security_score(findings_warn)["score"]
        score_crit = compute_security_score(findings_crit)["score"]
        assert score_warn > score_crit

    def test_result_has_expected_keys(self):
        findings = [self.Finding("Note", "ok", "", category="SIP")]
        result = self.compute(findings)
        assert "score" in result
        assert "max" in result
        assert "percent" in result
        assert "breakdown" in result

    def test_as_dict_method(self):
        f = self.Finding("Title", "warning", "Some detail", fix_command="cmd", category="Auth")
        d = f.as_dict()
        assert d["title"] == "Title"
        assert d["severity"] == "warning"
        assert d["fix_command"] == "cmd"
        assert d["category"] == "Auth"
