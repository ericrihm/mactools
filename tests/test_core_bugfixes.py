"""Tests for core module bug fixes — validates all critical fixes."""

from __future__ import annotations

from unittest.mock import patch, MagicMock
from dataclasses import dataclass

import pytest


# ---------------------------------------------------------------------------
# diskutil: capacity_bytes vs used_bytes fix
# ---------------------------------------------------------------------------


class TestDiskutilCapacity:
    def test_capacity_uses_quota_not_in_use(self):
        from mactools_core.diskutil import APFSVolume, list_apfs_containers

        plist_data = {
            "Containers": [{
                "ContainerReference": "disk1",
                "CapacityCeiling": 500_000_000_000,
                "CapacityFree": 200_000_000_000,
                "Volumes": [{
                    "Name": "Macintosh HD",
                    "DeviceIdentifier": "disk1s1",
                    "Roles": ["Data"],
                    "CapacityQuota": 400_000_000_000,
                    "CapacityInUse": 250_000_000_000,
                    "Encryption": False,
                    "Mounted": True,
                    "MountPoint": "/",
                }],
            }],
        }

        with patch("mactools_core.diskutil.run_plist", return_value=plist_data):
            containers = list_apfs_containers()

        assert len(containers) == 1
        vol = containers[0].volumes[0]
        assert vol.capacity_bytes == 400_000_000_000
        assert vol.used_bytes == 250_000_000_000
        assert vol.capacity_bytes != vol.used_bytes

    def test_capacity_fallback_to_in_use_when_no_quota(self):
        from mactools_core.diskutil import list_apfs_containers

        plist_data = {
            "Containers": [{
                "ContainerReference": "disk1",
                "CapacityCeiling": 500_000_000_000,
                "CapacityFree": 200_000_000_000,
                "Volumes": [{
                    "Name": "Macintosh HD",
                    "DeviceIdentifier": "disk1s1",
                    "Roles": [],
                    "CapacityInUse": 100_000_000,
                    "Encryption": False,
                    "Mounted": True,
                    "MountPoint": "/",
                }],
            }],
        }

        with patch("mactools_core.diskutil.run_plist", return_value=plist_data):
            containers = list_apfs_containers()

        vol = containers[0].volumes[0]
        assert vol.capacity_bytes == 100_000_000
        assert vol.used_bytes == 100_000_000


# ---------------------------------------------------------------------------
# shortcuts: input_data passed to run()
# ---------------------------------------------------------------------------


class TestShortcutsInputData:
    def test_run_shortcut_passes_input_data(self):
        from mactools_core.runner import RunResult

        with patch("mactools_core.shortcuts.run") as mock_run:
            mock_run.return_value = RunResult(stdout="output", stderr="", returncode=0, ok=True)
            from mactools_core.shortcuts import run_shortcut
            result = run_shortcut("My Shortcut", input_text="hello world")

        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("input_data") == "hello world" or \
               (len(call_kwargs.args) > 2 or call_kwargs[1].get("input_data") == "hello world")

    def test_run_shortcut_no_input(self):
        from mactools_core.runner import RunResult

        with patch("mactools_core.shortcuts.run") as mock_run:
            mock_run.return_value = RunResult(stdout="done", stderr="", returncode=0, ok=True)
            from mactools_core.shortcuts import run_shortcut
            result = run_shortcut("My Shortcut")

        args = mock_run.call_args
        cmd = args[0][0]
        assert "--input-path" not in cmd


# ---------------------------------------------------------------------------
# unified_log: predicate + process combination
# ---------------------------------------------------------------------------


class TestUnifiedLogPredicate:
    def test_both_predicate_and_process_combined(self):
        from mactools_core.runner import RunResult

        with patch("mactools_core.unified_log.run") as mock_run:
            mock_run.return_value = RunResult(stdout="", stderr="", returncode=0, ok=True)
            from mactools_core.unified_log import log_show
            log_show(predicate="eventMessage contains 'error'", process="kernel")

        cmd = mock_run.call_args[0][0]
        pred_indices = [i for i, c in enumerate(cmd) if c == "--predicate"]
        assert len(pred_indices) == 1
        pred_value = cmd[pred_indices[0] + 1]
        assert "AND" in pred_value
        assert "kernel" in pred_value
        assert "error" in pred_value

    def test_only_predicate(self):
        from mactools_core.runner import RunResult

        with patch("mactools_core.unified_log.run") as mock_run:
            mock_run.return_value = RunResult(stdout="", stderr="", returncode=0, ok=True)
            from mactools_core.unified_log import log_show
            log_show(predicate="eventMessage contains 'test'")

        cmd = mock_run.call_args[0][0]
        pred_indices = [i for i, c in enumerate(cmd) if c == "--predicate"]
        assert len(pred_indices) == 1

    def test_only_process(self):
        from mactools_core.runner import RunResult

        with patch("mactools_core.unified_log.run") as mock_run:
            mock_run.return_value = RunResult(stdout="", stderr="", returncode=0, ok=True)
            from mactools_core.unified_log import log_show
            log_show(process="WindowServer")

        cmd = mock_run.call_args[0][0]
        pred_indices = [i for i, c in enumerate(cmd) if c == "--predicate"]
        assert len(pred_indices) == 1
        assert "WindowServer" in cmd[pred_indices[0] + 1]


# ---------------------------------------------------------------------------
# security: remote_management now populated
# ---------------------------------------------------------------------------


class TestSecurityRemoteManagement:
    def test_remote_management_detected(self):
        from mactools_core.runner import RunResult

        mock_returns = {
            "csrutil": RunResult("System Integrity Protection status: enabled.", "", 0, True),
            "spctl": RunResult("assessments enabled", "", 0, True),
            "fdesetup": RunResult("FileVault is On.", "", 0, True),
            "ps": RunResult("root  1234  0.0  ARDAgent\nroot  5678  screensharingd", "", 0, True),
            "systemsetup": RunResult("Remote Login: Off", "", 0, True),
        }

        def mock_run(cmd, **kwargs):
            for key, result in mock_returns.items():
                if key in cmd[0]:
                    return result
            return RunResult("", "", 0, True)

        with patch("mactools_core.security.run", side_effect=mock_run), \
             patch("mactools_core.security.get_firewall") as mock_fw:
            mock_fw.return_value = MagicMock(enabled=True, stealth=False)
            from mactools_core.security import get_security_posture
            posture = get_security_posture()

        assert posture.remote_management is True

    def test_remote_management_not_detected(self):
        from mactools_core.runner import RunResult

        mock_returns = {
            "csrutil": RunResult("System Integrity Protection status: enabled.", "", 0, True),
            "spctl": RunResult("assessments enabled", "", 0, True),
            "fdesetup": RunResult("FileVault is On.", "", 0, True),
            "ps": RunResult("root  1234  0.0  launchd\nroot  5678  syslogd", "", 0, True),
            "systemsetup": RunResult("Remote Login: Off", "", 0, True),
        }

        def mock_run(cmd, **kwargs):
            for key, result in mock_returns.items():
                if key in cmd[0]:
                    return result
            return RunResult("", "", 0, True)

        with patch("mactools_core.security.run", side_effect=mock_run), \
             patch("mactools_core.security.get_firewall") as mock_fw:
            mock_fw.return_value = MagicMock(enabled=True, stealth=False)
            from mactools_core.security import get_security_posture
            posture = get_security_posture()

        assert posture.remote_management is False


# ---------------------------------------------------------------------------
# admin: ps aux called only once
# ---------------------------------------------------------------------------


class TestAdminPsAux:
    def test_sharing_status_single_ps_call(self):
        from mactools_core.runner import RunResult

        ssh_result = RunResult("ok", "", 0, True)
        ps_result = RunResult(
            "root  123  ARDAgent\nroot  456  screensharingd\nroot  789  smbd",
            "", 0, True,
        )

        call_count = {"ps": 0}
        original_returns = [ssh_result, ps_result]
        call_idx = [0]

        def mock_run(cmd, **kwargs):
            if "ps" in cmd:
                call_count["ps"] += 1
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(original_returns):
                return original_returns[idx]
            return RunResult("", "", 0, True)

        with patch("mactools_core.admin.run", side_effect=mock_run):
            from mactools_core.admin import get_sharing_status
            status = get_sharing_status()

        assert call_count["ps"] == 1
        assert status["ard_agent"] is True
        assert status["screen_sharing"] is True
        assert status["file_sharing"] is True


# ---------------------------------------------------------------------------
# ai: CLI fallback includes system_prompt
# ---------------------------------------------------------------------------


class TestAICLIFallback:
    def test_cli_fallback_includes_system_prompt(self):
        import subprocess

        with patch("mactools_core.ai.Anthropic", side_effect=ImportError):
            pass

        with patch.dict("sys.modules", {"anthropic": None}):
            with patch("subprocess.run") as mock_sub:
                mock_sub.return_value = MagicMock(
                    returncode=0, stdout="AI response here", stderr=""
                )
                from mactools_core.ai import analyze
                result = analyze("You are a security expert.", "Check this config")

                call_args = mock_sub.call_args[0][0]
                prompt_arg = call_args[2]  # ["claude", "-p", PROMPT, ...]
                assert "security expert" in prompt_arg
                assert "Check this config" in prompt_arg


# ---------------------------------------------------------------------------
# output: format_bytes
# ---------------------------------------------------------------------------


class TestFormatBytes:
    def test_terabytes(self):
        from mactools_core.output import format_bytes
        assert "TB" in format_bytes(2_000_000_000_000)

    def test_gigabytes(self):
        from mactools_core.output import format_bytes
        result = format_bytes(16_000_000_000)
        assert "GB" in result
        assert "16.0" in result

    def test_megabytes(self):
        from mactools_core.output import format_bytes
        assert "MB" in format_bytes(500_000_000)

    def test_bytes(self):
        from mactools_core.output import format_bytes
        assert "B" in format_bytes(1024)

    def test_zero(self):
        from mactools_core.output import format_bytes
        assert "0" in format_bytes(0)


# ---------------------------------------------------------------------------
# macnet: severity is "ok" not broken hasattr
# ---------------------------------------------------------------------------


class TestMacnetSeverity:
    def test_no_issues_returns_ok_severity(self):
        from mactools_core.network import NetworkOverview, DNSResolver

        overview = NetworkOverview(
            ports=[],
            dns_resolvers=[DNSResolver(nameservers=["8.8.8.8"])],
            active_interface="en0",
        )

        from mactools_macnet.engine import diagnose_network
        issues = diagnose_network(overview)
        ok_issues = [i for i in issues if i.severity == "ok"]
        assert len(ok_issues) >= 1


# ---------------------------------------------------------------------------
# macsec cli: analyze not shadowed
# ---------------------------------------------------------------------------


class TestMacsecAnalyzeShadow:
    def test_cli_imports_ai_analyze(self):
        import mactools_macsec.cli as cli_mod
        assert hasattr(cli_mod, "ai_analyze")
        assert callable(cli_mod.ai_analyze)

    def test_macprivacy_imports_ai_analyze(self):
        import mactools_macprivacy.cli as cli_mod
        assert hasattr(cli_mod, "ai_analyze")
        assert callable(cli_mod.ai_analyze)

    def test_macsign_imports_ai_analyze(self):
        import mactools_macsign.cli as cli_mod
        assert hasattr(cli_mod, "ai_analyze")
        assert callable(cli_mod.ai_analyze)


# ---------------------------------------------------------------------------
# macadmin: tailscale_status handles bad JSON
# ---------------------------------------------------------------------------


class TestMacadminTailscaleJSON:
    def test_handles_malformed_json(self):
        from mactools_core.runner import RunResult

        with patch("mactools_macadmin.engine.run") as mock_run:
            mock_run.return_value = RunResult(
                stdout="WARNING: some non-json output", stderr="", returncode=0, ok=True,
            )
            from mactools_macadmin.engine import tailscale_status
            result = tailscale_status()

        assert result["status"] == "error"
        assert "invalid JSON" in result.get("error", "")

    def test_handles_valid_json(self):
        from mactools_core.runner import RunResult
        import json

        data = {
            "Self": {"HostName": "mypc", "TailscaleIPs": ["100.64.0.1"], "Online": True},
            "Peer": {},
        }

        with patch("mactools_macadmin.engine.run") as mock_run:
            mock_run.return_value = RunResult(
                stdout=json.dumps(data), stderr="", returncode=0, ok=True,
            )
            from mactools_macadmin.engine import tailscale_status
            result = tailscale_status()

        assert result["hostname"] == "mypc"
        assert result["ip"] == "100.64.0.1"


# ---------------------------------------------------------------------------
# network: proxy detection
# ---------------------------------------------------------------------------


class TestNetworkProxy:
    def test_proxy_detected(self):
        from mactools_core.runner import RunResult

        def mock_run(cmd, **kwargs):
            if "-getwebproxy" in cmd:
                return RunResult("Enabled: Yes\nServer: proxy.corp.com\nPort: 8080", "", 0, True)
            if "-getsecurewebproxy" in cmd:
                return RunResult("Enabled: No\nServer: \nPort: 0", "", 0, True)
            if "-getsocksfirewallproxy" in cmd:
                return RunResult("Enabled: No\nServer: \nPort: 0", "", 0, True)
            if "-getproxybypassdomains" in cmd:
                return RunResult("*.local\nlocalhost", "", 0, True)
            if "-listallhardwareports" in cmd:
                return RunResult("", "", 0, True)
            if "scutil" in cmd[0]:
                return RunResult("", "", 0, True)
            return RunResult("", "", 0, True)

        with patch("mactools_core.network.run", side_effect=mock_run):
            from mactools_core.network import get_proxy_config
            proxy = get_proxy_config()

        assert proxy is not None
        assert proxy.http_enabled is True
        assert "proxy.corp.com" in proxy.http_proxy
        assert "8080" in proxy.http_proxy
        assert "*.local" in proxy.exceptions

    def test_no_proxy_returns_none(self):
        from mactools_core.runner import RunResult

        def mock_run(cmd, **kwargs):
            return RunResult("Enabled: No\nServer: \nPort: 0", "", 0, True)

        with patch("mactools_core.network.run", side_effect=mock_run):
            from mactools_core.network import get_proxy_config
            proxy = get_proxy_config()

        assert proxy is None
