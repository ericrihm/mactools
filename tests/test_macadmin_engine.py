"""Tests for mactools_macadmin.engine — all privileged macOS admin operations."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

import pytest

from mactools_core.runner import RunResult


def _ok(stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(stdout=stdout, stderr=stderr, returncode=0, ok=True)


def _fail(stderr: str = "error") -> RunResult:
    return RunResult(stdout="", stderr=stderr, returncode=1, ok=False)


# ===========================================================================
# setup_all
# ===========================================================================

class TestSetupAll:
    def setup_method(self):
        from mactools_macadmin.engine import setup_all
        self.setup_all = setup_all

    def test_returns_all_expected_keys(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert "askpass" in result
        assert "shell_profile" in result
        assert "sudoers" in result
        assert "ssh_enabled" in result
        assert "sudo_works" in result

    def test_askpass_already_installed(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["askpass"]["status"] == "ok"

    def test_askpass_installs_when_missing(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=False), \
             patch("mactools_macadmin.engine.install_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["askpass"]["status"] == "installed"

    def test_askpass_install_failure(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=False), \
             patch("mactools_macadmin.engine.install_askpass", return_value=False), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["askpass"]["status"] == "failed"

    def test_shell_profile_already_configured(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["shell_profile"] == "already configured"

    def test_shell_profile_updated_when_missing_askpass(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="# just zshrc, no askpass"), \
             patch("builtins.open", mock_open()):
            result = self.setup_all()
        assert result["shell_profile"] == "updated"

    def test_sudoers_already_configured(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["sudoers"] == "ok"

    def test_sudoers_installs_when_missing(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=False), \
             patch("mactools_macadmin.engine.install_sudoers_config", return_value=True), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert result["sudoers"] == "installed"

    def test_sudoers_install_failure(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.has_sudoers_config", return_value=False), \
             patch("mactools_macadmin.engine.install_sudoers_config", return_value=False), \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("mactools_macadmin.engine.prime_sudo_cache", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="export SUDO_ASKPASS=x"):
            result = self.setup_all()
        assert "failed" in result["sudoers"]


# ===========================================================================
# enable_ssh
# ===========================================================================

class TestEnableSsh:
    def setup_method(self):
        from mactools_macadmin.engine import enable_ssh
        self.enable_ssh = enable_ssh

    def test_already_enabled(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True):
            result = self.enable_ssh()
        assert result["status"] == "already_enabled"

    def test_enables_via_launchctl(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", side_effect=[False, True]), \
             patch("mactools_macadmin.engine.sudo_run", return_value=_ok()):
            result = self.enable_ssh()
        assert result["status"] == "enabled"

    def test_falls_back_to_systemsetup(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", side_effect=[False, True]), \
             patch("mactools_macadmin.engine.sudo_run", side_effect=[_fail(), _ok()]):
            result = self.enable_ssh()
        assert result["status"] == "enabled"

    def test_enable_failure(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", side_effect=[False, False]), \
             patch("mactools_macadmin.engine.sudo_run", return_value=_fail("permission denied")):
            result = self.enable_ssh()
        assert result["status"] == "failed"
        assert result["error"] is not None


# ===========================================================================
# ssh_status
# ===========================================================================

class TestSshStatus:
    def setup_method(self):
        from mactools_macadmin.engine import ssh_status
        self.ssh_status = ssh_status

    def test_returns_expected_keys(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("pathlib.Path.exists", return_value=False):
            result = self.ssh_status()
        assert "enabled" in result
        assert "authorized_keys" in result
        assert "port" in result

    def test_enabled_true(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("pathlib.Path.exists", return_value=False):
            result = self.ssh_status()
        assert result["enabled"] is True
        assert result["port"] == 22

    def test_counts_authorized_keys(self):
        keys_content = "ssh-ed25519 AAAA key1\nssh-ed25519 BBBB key2\n# comment\n\n"
        with patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=keys_content):
            result = self.ssh_status()
        assert result["authorized_keys"] == 2

    def test_no_authorized_keys_file(self):
        with patch("mactools_macadmin.engine.is_ssh_enabled", return_value=False), \
             patch("pathlib.Path.exists", return_value=False):
            result = self.ssh_status()
        assert result["authorized_keys"] == 0


# ===========================================================================
# authorize_key
# ===========================================================================

class TestAuthorizeKey:
    def setup_method(self):
        from mactools_macadmin.engine import authorize_key
        self.authorize_key = authorize_key

    def test_key_not_found(self, tmp_path):
        result = self.authorize_key(str(tmp_path / "nonexistent.pub"))
        assert result["status"] == "failed"
        assert "not found" in result["error"].lower()

    def test_key_already_authorized(self, tmp_path):
        key_file = tmp_path / "id_ed25519.pub"
        key_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@host\n")
        auth_keys = tmp_path / ".ssh" / "authorized_keys"
        auth_keys.parent.mkdir(parents=True)
        auth_keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@host\n")

        with patch("mactools_macadmin.engine.Path") as MockPath:
            MockPath.side_effect = lambda p: Path(p)
            MockPath.home.return_value = tmp_path

            result = self.authorize_key(str(key_file))
        assert result["status"] == "already_authorized"

    def test_authorizes_new_key(self, tmp_path):
        key_file = tmp_path / "id_ed25519.pub"
        key_file.write_text("ssh-ed25519 NEWKEY test@host\n")
        auth_keys = tmp_path / ".ssh" / "authorized_keys"
        auth_keys.parent.mkdir(parents=True)
        auth_keys.write_text("ssh-ed25519 OLDKEY other@host\n")

        with patch("mactools_macadmin.engine.Path") as MockPath:
            MockPath.side_effect = lambda p: Path(p)
            MockPath.home.return_value = tmp_path

            result = self.authorize_key(str(key_file))
        assert result["status"] == "authorized"
        assert auth_keys.read_text().count("NEWKEY") == 1

    def test_uses_default_key_path(self, tmp_path):
        default_key = tmp_path / ".ssh" / "id_ed25519.pub"
        default_key.parent.mkdir(parents=True)
        default_key.write_text("ssh-ed25519 DEFAULT test@host\n")
        auth_keys = tmp_path / ".ssh" / "authorized_keys"
        auth_keys.write_text("")

        with patch("mactools_macadmin.engine.Path") as MockPath:
            MockPath.side_effect = lambda p: Path(p)
            MockPath.home.return_value = tmp_path

            result = self.authorize_key("")
        assert result["status"] == "authorized"


# ===========================================================================
# tailscale_status
# ===========================================================================

SAMPLE_TAILSCALE_JSON = json.dumps({
    "Self": {
        "HostName": "erics-mac-mini",
        "TailscaleIPs": ["100.114.118.11"],
        "Online": True,
    },
    "Peer": {
        "abc123": {
            "HostName": "rtx-1",
            "OS": "windows",
            "TailscaleIPs": ["100.121.168.27"],
            "Online": True,
            "LastSeen": "2026-04-26T10:00:00Z",
        },
        "def456": {
            "HostName": "thinkpad",
            "OS": "windows",
            "TailscaleIPs": ["100.77.230.1"],
            "Online": False,
            "LastSeen": "2025-12-01T00:00:00Z",
        },
    },
})


class TestTailscaleStatus:
    def setup_method(self):
        from mactools_macadmin.engine import tailscale_status
        self.tailscale_status = tailscale_status

    def test_parses_self_node(self):
        with patch("mactools_macadmin.engine.run", return_value=_ok(stdout=SAMPLE_TAILSCALE_JSON)):
            result = self.tailscale_status()
        assert result["hostname"] == "erics-mac-mini"
        assert result["ip"] == "100.114.118.11"
        assert result["online"] is True

    def test_parses_peers(self):
        with patch("mactools_macadmin.engine.run", return_value=_ok(stdout=SAMPLE_TAILSCALE_JSON)):
            result = self.tailscale_status()
        assert len(result["peers"]) == 2
        rtx = [p for p in result["peers"] if p["hostname"] == "rtx-1"][0]
        assert rtx["os"] == "windows"
        assert rtx["ip"] == "100.121.168.27"
        assert rtx["online"] is True

    def test_offline_peer(self):
        with patch("mactools_macadmin.engine.run", return_value=_ok(stdout=SAMPLE_TAILSCALE_JSON)):
            result = self.tailscale_status()
        thinkpad = [p for p in result["peers"] if p["hostname"] == "thinkpad"][0]
        assert thinkpad["online"] is False

    def test_not_running(self):
        with patch("mactools_macadmin.engine.run", return_value=_fail("tailscale not found")):
            result = self.tailscale_status()
        assert result["status"] == "not_running"
        assert "error" in result

    def test_no_peers(self):
        data = json.dumps({"Self": {"HostName": "solo", "TailscaleIPs": ["10.0.0.1"], "Online": True}, "Peer": {}})
        with patch("mactools_macadmin.engine.run", return_value=_ok(stdout=data)):
            result = self.tailscale_status()
        assert result["peers"] == []

    def test_self_no_tailscale_ips(self):
        data = json.dumps({"Self": {"HostName": "test", "TailscaleIPs": None, "Online": False}, "Peer": {}})
        with patch("mactools_macadmin.engine.run", return_value=_ok(stdout=data)):
            result = self.tailscale_status()
        assert result["ip"] == ""


# ===========================================================================
# sharing_status
# ===========================================================================

class TestSharingStatus:
    def setup_method(self):
        from mactools_macadmin.engine import sharing_status
        self.sharing_status = sharing_status

    def test_delegates_to_core(self):
        expected = {"remote_login": True, "ard_agent": False, "screen_sharing": False, "file_sharing": False}
        with patch("mactools_macadmin.engine.get_sharing_status", return_value=expected):
            result = self.sharing_status()
        assert result == expected


# ===========================================================================
# fleet_identity
# ===========================================================================

class TestFleetIdentity:
    def setup_method(self):
        from mactools_macadmin.engine import fleet_identity
        self.fleet_identity = fleet_identity

    def test_returns_expected_keys(self, tmp_path):
        ts_data = {"hostname": "test-mac", "ip": "100.0.0.1"}
        with patch("mactools_macadmin.engine.tailscale_status", return_value=ts_data), \
             patch("mactools_macadmin.engine.run") as mock_run, \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("shutil.which", return_value=None), \
             patch("mactools_macadmin.engine.FLEET_DIR", tmp_path / "fleet"), \
             patch("mactools_macadmin.engine.IDENTITY_FILE", tmp_path / "fleet" / "identity.toml"), \
             patch("mactools_macadmin.engine.PEERS_DIR", tmp_path / "fleet" / "peers"):
            mock_run.side_effect = [
                _ok("25769803776"),      # hw.memsize (24GB)
                _ok("10"),               # hw.ncpu
                _ok("arm64"),            # uname -m
                _ok("15.4"),             # sw_vers productVersion
                _ok("24E248"),           # sw_vers buildVersion
                _ok("    Chipset Model: Apple M4\n"),  # system_profiler
                _ok("Python 3.14.0"),    # python3 --version
            ]
            result = self.fleet_identity()
        assert "hostname" in result
        assert "ip" in result
        assert "ram_gb" in result
        assert "cpu_cores" in result
        assert "gpu" in result
        assert "agents" in result
        assert result["ram_gb"] == 24
        assert result["cpu_cores"] == 10
        assert result["gpu"] == "Apple M4"

    def test_writes_identity_file(self, tmp_path):
        ts_data = {"hostname": "test-mac", "ip": "100.0.0.1"}
        fleet_dir = tmp_path / "fleet"
        identity_file = fleet_dir / "identity.toml"
        peers_dir = fleet_dir / "peers"
        with patch("mactools_macadmin.engine.tailscale_status", return_value=ts_data), \
             patch("mactools_macadmin.engine.run") as mock_run, \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=False), \
             patch("shutil.which", return_value=None), \
             patch("mactools_macadmin.engine.FLEET_DIR", fleet_dir), \
             patch("mactools_macadmin.engine.IDENTITY_FILE", identity_file), \
             patch("mactools_macadmin.engine.PEERS_DIR", peers_dir):
            mock_run.side_effect = [
                _ok("17179869184"),      # 16GB
                _ok("8"),
                _ok("arm64"),
                _ok("15.4"),
                _ok("24E248"),
                _ok(""),                 # no GPU line
                _ok("Python 3.12.0"),
            ]
            result = self.fleet_identity()
        assert identity_file.exists()
        content = identity_file.read_text()
        assert "test-mac" in content
        assert "100.0.0.1" in content
        peer_file = peers_dir / "test-mac.toml"
        assert peer_file.exists()

    def test_sanitizes_hostname(self, tmp_path):
        ts_data = {"hostname": "Eric's Mac Mini", "ip": "10.0.0.1"}
        fleet_dir = tmp_path / "fleet"
        with patch("mactools_macadmin.engine.tailscale_status", return_value=ts_data), \
             patch("mactools_macadmin.engine.run") as mock_run, \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("shutil.which", return_value=None), \
             patch("mactools_macadmin.engine.FLEET_DIR", fleet_dir), \
             patch("mactools_macadmin.engine.IDENTITY_FILE", fleet_dir / "identity.toml"), \
             patch("mactools_macadmin.engine.PEERS_DIR", fleet_dir / "peers"):
            mock_run.side_effect = [
                _ok("8589934592"), _ok("4"), _ok("arm64"),
                _ok("15.0"), _ok("24A1"), _ok(""), _ok("Python 3.12.0"),
            ]
            result = self.fleet_identity()
        assert result["hostname"] == "erics-mac-mini"

    def test_detects_agents(self, tmp_path):
        ts_data = {"hostname": "test", "ip": "10.0.0.1"}
        fleet_dir = tmp_path / "fleet"
        with patch("mactools_macadmin.engine.tailscale_status", return_value=ts_data), \
             patch("mactools_macadmin.engine.run") as mock_run, \
             patch("mactools_macadmin.engine.is_ssh_enabled", return_value=True), \
             patch("shutil.which", side_effect=lambda x: "/usr/bin/claude" if x == "claude" else None), \
             patch("mactools_macadmin.engine.FLEET_DIR", fleet_dir), \
             patch("mactools_macadmin.engine.IDENTITY_FILE", fleet_dir / "identity.toml"), \
             patch("mactools_macadmin.engine.PEERS_DIR", fleet_dir / "peers"):
            mock_run.side_effect = [
                _ok("8589934592"), _ok("4"), _ok("arm64"),
                _ok("15.0"), _ok("24A1"), _ok(""), _ok("Python 3.12.0"),
            ]
            result = self.fleet_identity()
        assert "claude-code" in result["agents"]
        assert "codex-cli" not in result["agents"]


# ===========================================================================
# fleet_peers
# ===========================================================================

class TestFleetPeers:
    def setup_method(self):
        from mactools_macadmin.engine import fleet_peers
        self.fleet_peers = fleet_peers

    def test_returns_empty_when_no_dir(self, tmp_path):
        with patch("mactools_macadmin.engine.PEERS_DIR", tmp_path / "nonexistent"):
            result = self.fleet_peers()
        assert result == []

    def test_parses_toml_peer_files(self, tmp_path):
        peers_dir = tmp_path / "peers"
        peers_dir.mkdir()
        (peers_dir / "rtx-1.toml").write_text(
            '[machine]\nhostname = "rtx-1"\ntailscale_ip = "100.121.168.27"\n'
            'os = "windows"\narch = "AMD64"\n\n'
            '[capabilities]\nram_gb = 63\ncpu_cores = 16\n\n'
            '[health]\nstatus = "online"\nlast_seen = "2026-04-26T10:00:00Z"\n\n'
            '[network]\nssh_enabled = true\n'
        )
        with patch("mactools_macadmin.engine.PEERS_DIR", peers_dir):
            result = self.fleet_peers()
        assert len(result) == 1
        peer = result[0]
        assert peer["hostname"] == "rtx-1"
        assert peer["tailscale_ip"] == "100.121.168.27"
        assert peer["os"] == "windows"
        assert peer["file"] == "rtx-1.toml"

    def test_multiple_peers(self, tmp_path):
        peers_dir = tmp_path / "peers"
        peers_dir.mkdir()
        (peers_dir / "mac-mini.toml").write_text('hostname = "mac-mini"\nstatus = "online"\n')
        (peers_dir / "rtx.toml").write_text('hostname = "rtx"\nstatus = "idle"\n')
        with patch("mactools_macadmin.engine.PEERS_DIR", peers_dir):
            result = self.fleet_peers()
        assert len(result) == 2
        hostnames = {p["hostname"] for p in result}
        assert hostnames == {"mac-mini", "rtx"}

    def test_ignores_non_toml_files(self, tmp_path):
        peers_dir = tmp_path / "peers"
        peers_dir.mkdir()
        (peers_dir / "readme.md").write_text("not a peer")
        (peers_dir / "peer.toml").write_text('hostname = "real"\n')
        with patch("mactools_macadmin.engine.PEERS_DIR", peers_dir):
            result = self.fleet_peers()
        assert len(result) == 1


# ===========================================================================
# sudo_test
# ===========================================================================

class TestSudoTest:
    def setup_method(self):
        from mactools_macadmin.engine import sudo_test
        self.sudo_test = sudo_test

    def test_no_askpass(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=False), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"):
            result = self.sudo_test()
        assert result["status"] == "no_askpass"

    def test_sudo_works(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.sudo_run", return_value=_ok("ok\n")):
            result = self.sudo_test()
        assert result["status"] == "ok"
        assert result["error"] is None

    def test_sudo_fails(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.sudo_run", return_value=_fail("auth failed")):
            result = self.sudo_test()
        assert result["status"] == "failed"
        assert "auth failed" in result["error"]

    def test_sudo_returns_unexpected_output(self):
        with patch("mactools_macadmin.engine.has_askpass", return_value=True), \
             patch("mactools_macadmin.engine.askpass_path", return_value="/fake/askpass"), \
             patch("mactools_macadmin.engine.sudo_run", return_value=_ok("unexpected")):
            result = self.sudo_test()
        assert result["status"] == "failed"
