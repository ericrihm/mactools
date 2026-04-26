"""Smoke tests for all 12 mactools CLIs — verify --help exits 0 with no real I/O.

Uses Click's CliRunner to invoke each CLI group's --help, which exercises the
argument/option parsing code without calling any subprocess or system tools.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def assert_help_ok(cli_obj, subcommand: str | None = None) -> None:
    """Invoke --help on a CLI group (or subcommand) and assert exit code 0."""
    runner = CliRunner()
    args = ["--help"] if subcommand is None else [subcommand, "--help"]
    result = runner.invoke(cli_obj, args, catch_exceptions=False)
    assert result.exit_code == 0, (
        f"--help returned exit code {result.exit_code}.\nOutput:\n{result.output}"
    )
    assert result.output.strip() != ""


# ===========================================================================
# opslog
# ===========================================================================

class TestOpslogCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_opslog.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_errors_help(self):
        assert_help_ok(self.cli, "errors")

    def test_stats_help(self):
        assert_help_ok(self.cli, "stats")

    def test_search_help(self):
        assert_help_ok(self.cli, "search")

    def test_triage_help(self):
        assert_help_ok(self.cli, "triage")


# ===========================================================================
# opsmac
# ===========================================================================

class TestOpsmacCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_opsmac.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_health_help(self):
        assert_help_ok(self.cli, "health")

    def test_score_help(self):
        assert_help_ok(self.cli, "score")


# ===========================================================================
# maclaunch
# ===========================================================================

class TestMaclaunchCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_maclaunch.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_list_help(self):
        assert_help_ok(self.cli, "list")

    def test_audit_help(self):
        assert_help_ok(self.cli, "audit")


# ===========================================================================
# macsec
# ===========================================================================

class TestMacsecCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macsec.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_audit_help(self):
        assert_help_ok(self.cli, "audit")

    def test_score_help(self):
        assert_help_ok(self.cli, "score")

    def test_fix_help(self):
        assert_help_ok(self.cli, "fix")


# ===========================================================================
# macsign
# ===========================================================================

class TestMacsignCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macsign.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_check_help(self):
        assert_help_ok(self.cli, "check")

    def test_scan_help(self):
        assert_help_ok(self.cli, "scan")

    def test_entitlements_help(self):
        assert_help_ok(self.cli, "entitlements")

    def test_packages_help(self):
        assert_help_ok(self.cli, "packages")


# ===========================================================================
# macprivacy
# ===========================================================================

class TestMacprivacyCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macprivacy.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_audit_help(self):
        assert_help_ok(self.cli, "audit")

    def test_list_help(self):
        assert_help_ok(self.cli, "list")

    def test_revoke_help(self):
        assert_help_ok(self.cli, "revoke")


# ===========================================================================
# macdefaults
# ===========================================================================

class TestMacdefaultsCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macdefaults.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_audit_help(self):
        assert_help_ok(self.cli, "audit")

    def test_recommend_help(self):
        assert_help_ok(self.cli, "recommend")


# ===========================================================================
# macnet
# ===========================================================================

class TestMacnetCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macnet.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_status_help(self):
        assert_help_ok(self.cli, "status")

    def test_diagnose_help(self):
        assert_help_ok(self.cli, "diagnose")


# ===========================================================================
# macenergy
# ===========================================================================

class TestMacenergyCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macenergy.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_wake_help(self):
        assert_help_ok(self.cli, "wake")

    def test_thermal_help(self):
        assert_help_ok(self.cli, "thermal")


# ===========================================================================
# macspot
# ===========================================================================

class TestMacspotCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macspot.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_search_help(self):
        assert_help_ok(self.cli, "search")

    def test_find_help(self):
        assert_help_ok(self.cli, "find")

    def test_health_help(self):
        assert_help_ok(self.cli, "health")

    def test_metadata_help(self):
        assert_help_ok(self.cli, "metadata")


# ===========================================================================
# macdisk
# ===========================================================================

class TestMacdiskCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macdisk.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_status_help(self):
        assert_help_ok(self.cli, "status")

    def test_volumes_help(self):
        assert_help_ok(self.cli, "volumes")

    def test_smart_help(self):
        assert_help_ok(self.cli, "smart")


# ===========================================================================
# macshortcuts
# ===========================================================================

class TestMacshortcutsCli:
    @pytest.fixture(autouse=True)
    def _cli(self):
        from mactools_macshortcuts.cli import cli
        self.cli = cli

    def test_help(self):
        assert_help_ok(self.cli)

    def test_list_help(self):
        assert_help_ok(self.cli, "list")

    def test_run_help(self):
        assert_help_ok(self.cli, "run")

    def test_suggest_help(self):
        assert_help_ok(self.cli, "suggest")

    def test_audit_help(self):
        assert_help_ok(self.cli, "audit")
