"""CLI smoke tests for macadmin — all commands and subcommands."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mactools_macadmin.cli import main


@pytest.fixture(autouse=True)
def runner():
    return CliRunner()


class TestMacadminHelp:
    def test_root_help(self, runner):
        result = runner.invoke(main, ["--help"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "macadmin" in result.output

    def test_setup_help(self, runner):
        result = runner.invoke(main, ["setup", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_ssh_help(self, runner):
        result = runner.invoke(main, ["ssh", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_ssh_enable_help(self, runner):
        result = runner.invoke(main, ["ssh", "enable", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_ssh_status_help(self, runner):
        result = runner.invoke(main, ["ssh", "status", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_ssh_authorize_key_help(self, runner):
        result = runner.invoke(main, ["ssh", "authorize-key", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_tailscale_help(self, runner):
        result = runner.invoke(main, ["tailscale", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_tailscale_status_help(self, runner):
        result = runner.invoke(main, ["tailscale", "status", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_fleet_help(self, runner):
        result = runner.invoke(main, ["fleet", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_fleet_identity_help(self, runner):
        result = runner.invoke(main, ["fleet", "identity", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_fleet_peers_help(self, runner):
        result = runner.invoke(main, ["fleet", "peers", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_sharing_help(self, runner):
        result = runner.invoke(main, ["sharing", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_sharing_status_help(self, runner):
        result = runner.invoke(main, ["sharing", "status", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_sudo_help(self, runner):
        result = runner.invoke(main, ["sudo", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_sudo_test_help(self, runner):
        result = runner.invoke(main, ["sudo", "test", "--help"], catch_exceptions=False)
        assert result.exit_code == 0

    def test_sudo_cache_help(self, runner):
        result = runner.invoke(main, ["sudo", "cache", "--help"], catch_exceptions=False)
        assert result.exit_code == 0


class TestSetupCommand:
    def test_setup_json_output(self, runner):
        mock_result = {
            "askpass": {"status": "ok", "path": "/fake"},
            "shell_profile": "already configured",
            "sudoers": "ok",
            "ssh_enabled": True,
            "sudo_works": True,
        }
        with patch("mactools_macadmin.cli.engine.setup_all", return_value=mock_result):
            result = runner.invoke(main, ["setup", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["askpass"]["status"] == "ok"

    def test_setup_text_output(self, runner):
        mock_result = {
            "askpass": {"status": "ok", "path": "/fake"},
            "shell_profile": "already configured",
            "sudoers": "ok",
            "ssh_enabled": True,
            "sudo_works": True,
        }
        with patch("mactools_macadmin.cli.engine.setup_all", return_value=mock_result):
            result = runner.invoke(main, ["setup"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "askpass" in result.output


class TestSshCommands:
    def test_ssh_status_json(self, runner):
        mock_result = {"enabled": True, "authorized_keys": 3, "port": 22}
        with patch("mactools_macadmin.cli.engine.ssh_status", return_value=mock_result):
            result = runner.invoke(main, ["ssh", "status", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["enabled"] is True
        assert data["authorized_keys"] == 3

    def test_ssh_status_text(self, runner):
        mock_result = {"enabled": False, "authorized_keys": 0, "port": 22}
        with patch("mactools_macadmin.cli.engine.ssh_status", return_value=mock_result):
            result = runner.invoke(main, ["ssh", "status"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "enabled" in result.output

    def test_ssh_enable_json(self, runner):
        with patch("mactools_macadmin.cli.engine.enable_ssh", return_value={"status": "enabled", "error": None}):
            result = runner.invoke(main, ["ssh", "enable", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "enabled"

    def test_ssh_authorize_key_json(self, runner):
        with patch("mactools_macadmin.cli.engine.authorize_key", return_value={"status": "authorized", "key": "/tmp/k"}):
            result = runner.invoke(main, ["ssh", "authorize-key", "/tmp/k", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "authorized"


class TestTailscaleCommands:
    def test_tailscale_status_json(self, runner):
        mock_result = {
            "hostname": "mac-mini",
            "ip": "100.0.0.1",
            "online": True,
            "peers": [{"hostname": "rtx", "ip": "100.0.0.2", "os": "windows", "online": True, "last_seen": ""}],
        }
        with patch("mactools_macadmin.cli.engine.tailscale_status", return_value=mock_result):
            result = runner.invoke(main, ["tailscale", "status", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["hostname"] == "mac-mini"
        assert len(data["peers"]) == 1

    def test_tailscale_status_text_with_peers(self, runner):
        mock_result = {
            "hostname": "mac-mini",
            "ip": "100.0.0.1",
            "online": True,
            "peers": [{"hostname": "rtx", "ip": "100.0.0.2", "os": "windows", "online": False, "last_seen": ""}],
        }
        with patch("mactools_macadmin.cli.engine.tailscale_status", return_value=mock_result):
            result = runner.invoke(main, ["tailscale", "status"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "mac-mini" in result.output
        assert "rtx" in result.output

    def test_tailscale_not_running(self, runner):
        with patch("mactools_macadmin.cli.engine.tailscale_status", return_value={"status": "not_running", "error": "nope"}):
            result = runner.invoke(main, ["tailscale", "status", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "not_running"


class TestFleetCommands:
    def test_fleet_identity_json(self, runner):
        mock_result = {
            "hostname": "mac-mini",
            "ip": "100.0.0.1",
            "file": "/tmp/identity.toml",
            "ram_gb": 24,
            "cpu_cores": 10,
            "gpu": "Apple M4",
            "agents": ["claude-code"],
        }
        with patch("mactools_macadmin.cli.engine.fleet_identity", return_value=mock_result):
            result = runner.invoke(main, ["fleet", "identity", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ram_gb"] == 24
        assert "claude-code" in data["agents"]

    def test_fleet_identity_text(self, runner):
        mock_result = {
            "hostname": "mac-mini",
            "ip": "100.0.0.1",
            "file": "/tmp/identity.toml",
            "ram_gb": 24,
            "cpu_cores": 10,
            "gpu": "Apple M4",
            "agents": ["claude-code"],
        }
        with patch("mactools_macadmin.cli.engine.fleet_identity", return_value=mock_result):
            result = runner.invoke(main, ["fleet", "identity"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "mac-mini" in result.output
        assert "24" in result.output

    def test_fleet_peers_json(self, runner):
        mock_result = [
            {"hostname": "rtx", "tailscale_ip": "100.0.0.2", "status": "online", "file": "rtx.toml"},
        ]
        with patch("mactools_macadmin.cli.engine.fleet_peers", return_value=mock_result):
            result = runner.invoke(main, ["fleet", "peers", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["hostname"] == "rtx"

    def test_fleet_peers_empty(self, runner):
        with patch("mactools_macadmin.cli.engine.fleet_peers", return_value=[]):
            result = runner.invoke(main, ["fleet", "peers"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "No peers" in result.output


class TestSharingCommands:
    def test_sharing_status_json(self, runner):
        mock_result = {"remote_login": True, "ard_agent": False, "screen_sharing": False, "file_sharing": False}
        with patch("mactools_macadmin.cli.engine.sharing_status", return_value=mock_result):
            result = runner.invoke(main, ["sharing", "status", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["remote_login"] is True

    def test_sharing_status_text(self, runner):
        mock_result = {"remote_login": True, "ard_agent": False, "screen_sharing": False, "file_sharing": True}
        with patch("mactools_macadmin.cli.engine.sharing_status", return_value=mock_result):
            result = runner.invoke(main, ["sharing", "status"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "ON" in result.output
        assert "off" in result.output


class TestSudoCommands:
    def test_sudo_test_json(self, runner):
        mock_result = {"status": "ok", "askpass": "/fake/askpass", "error": None}
        with patch("mactools_macadmin.cli.engine.sudo_test", return_value=mock_result):
            result = runner.invoke(main, ["sudo", "test", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"

    def test_sudo_test_text_with_error(self, runner):
        mock_result = {"status": "failed", "askpass": "/fake/askpass", "error": "denied"}
        with patch("mactools_macadmin.cli.engine.sudo_test", return_value=mock_result):
            result = runner.invoke(main, ["sudo", "test"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "failed" in result.output
        assert "denied" in result.output

    def test_sudo_cache_success(self, runner):
        with patch("mactools_core.admin.prime_sudo_cache", return_value=True):
            result = runner.invoke(main, ["sudo", "cache", "--json"], catch_exceptions=False)
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "cached"

    def test_sudo_cache_failure(self, runner):
        with patch("mactools_core.admin.prime_sudo_cache", return_value=False):
            result = runner.invoke(main, ["sudo", "cache"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "failed" in result.output
