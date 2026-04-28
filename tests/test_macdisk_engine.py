"""Tests for mactools_macdisk.engine — disk report building and issue detection."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mactools_core.diskutil import APFSContainer, APFSVolume, DiskInfo
from mactools_macdisk.engine import (
    DiskIssue,
    DiskReport,
    build_disk_report,
    identify_disk_issues,
)


# ---------------------------------------------------------------------------
# Helpers / fixture factories
# ---------------------------------------------------------------------------

def _disk(
    identifier: str = "disk0",
    name: str = "Apple SSD",
    size_bytes: int = 500_000_000_000,
    media_type: str = "Solid State",
    protocol: str = "PCIe",
    internal: bool = True,
    removable: bool = False,
    smart_status: str = "Verified",
) -> DiskInfo:
    return DiskInfo(
        identifier=identifier,
        name=name,
        size_bytes=size_bytes,
        media_type=media_type,
        protocol=protocol,
        internal=internal,
        removable=removable,
        smart_status=smart_status,
    )


def _volume(
    name: str = "Macintosh HD",
    identifier: str = "disk1s1",
    role: str = "System",
    used_bytes: int = 50_000_000_000,
    encrypted: bool = True,
    mounted: bool = True,
    mount_point: str = "/",
) -> APFSVolume:
    return APFSVolume(
        name=name,
        identifier=identifier,
        role=role,
        used_bytes=used_bytes,
        encrypted=encrypted,
        mounted=mounted,
        mount_point=mount_point,
    )


def _container(
    identifier: str = "disk1",
    capacity_bytes: int = 500_000_000_000,
    free_bytes: int = 200_000_000_000,
    volumes: list[APFSVolume] | None = None,
) -> APFSContainer:
    return APFSContainer(
        identifier=identifier,
        capacity_bytes=capacity_bytes,
        free_bytes=free_bytes,
        volumes=volumes or [],
    )


def _report(
    disks: list[DiskInfo] | None = None,
    containers: list[APFSContainer] | None = None,
    smart_statuses: dict[str, str] | None = None,
) -> DiskReport:
    return DiskReport(
        disks=disks or [],
        containers=containers or [],
        smart_statuses=smart_statuses or {},
    )


# ===========================================================================
# DiskReport properties
# ===========================================================================

class TestDiskReportProperties:
    """DiskReport computed properties: total_capacity_bytes, total_free_bytes."""

    def test_total_capacity_sums_disk_sizes(self):
        disks = [
            _disk(identifier="disk0", size_bytes=500_000_000_000),
            _disk(identifier="disk1", size_bytes=1_000_000_000_000),
        ]
        report = _report(disks=disks)
        assert report.total_capacity_bytes == 1_500_000_000_000

    def test_total_free_sums_container_free(self):
        containers = [
            _container(identifier="disk1", free_bytes=100_000_000_000),
            _container(identifier="disk2", free_bytes=50_000_000_000),
        ]
        report = _report(containers=containers)
        assert report.total_free_bytes == 150_000_000_000

    def test_empty_report_total_capacity_is_zero(self):
        assert _report().total_capacity_bytes == 0

    def test_empty_report_total_free_is_zero(self):
        assert _report().total_free_bytes == 0


# ===========================================================================
# DiskReport.to_dict
# ===========================================================================

class TestDiskReportToDict:
    def test_to_dict_contains_required_keys(self):
        d = _report().to_dict()
        for key in ("disks", "apfs_containers", "summary"):
            assert key in d

    def test_summary_has_total_capacity_and_total_free(self):
        report = _report(
            disks=[_disk(size_bytes=500_000_000_000)],
            containers=[_container(free_bytes=200_000_000_000)],
        )
        d = report.to_dict()
        assert "total_capacity" in d["summary"]
        assert "total_free" in d["summary"]

    def test_disk_dict_includes_smart_status_from_smart_statuses(self):
        d = _disk(identifier="disk0", smart_status="")
        report = _report(disks=[d], smart_statuses={"disk0": "Verified"})
        result = report.to_dict()
        assert result["disks"][0]["smart_status"] == "Verified"

    def test_disk_dict_prefers_inline_smart_status_over_dict(self):
        d = _disk(identifier="disk0", smart_status="Verified")
        report = _report(disks=[d], smart_statuses={"disk0": "Failed"})
        result = report.to_dict()
        # DiskInfo.smart_status takes precedence
        assert result["disks"][0]["smart_status"] == "Verified"

    def test_container_used_pct_computed_correctly(self):
        container = _container(capacity_bytes=1_000_000_000, free_bytes=100_000_000)
        report = _report(containers=[container])
        d = report.to_dict()
        assert d["apfs_containers"][0]["used_pct"] == 90.0

    def test_container_with_zero_capacity_used_pct_is_zero(self):
        container = _container(capacity_bytes=0, free_bytes=0)
        report = _report(containers=[container])
        d = report.to_dict()
        assert d["apfs_containers"][0]["used_pct"] == 0

    def test_volume_encrypted_flag_present(self):
        vol = _volume(encrypted=True)
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        d = report.to_dict()
        assert d["apfs_containers"][0]["volumes"][0]["encrypted"] is True


# ===========================================================================
# identify_disk_issues
# ===========================================================================

class TestIdentifyDiskIssues:
    """identify_disk_issues(report) -> list[DiskIssue]"""

    def test_healthy_report_no_issues(self):
        vol = _volume(role="System", encrypted=True, mount_point="/")
        container = _container(free_bytes=200_000_000_000, volumes=[vol])
        disk = _disk(smart_status="Verified")
        report = _report(disks=[disk], containers=[container])
        issues = identify_disk_issues(report)
        assert issues == []

    def test_critically_low_free_space_returns_critical_issue(self):
        # 3% free → below 5% critical threshold
        total = 500_000_000_000
        free = int(total * 0.03)
        container = _container(capacity_bytes=total, free_bytes=free)
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        critical_issues = [i for i in issues if i.severity == "critical" and "low disk space" in i.title.lower()]
        assert len(critical_issues) == 1

    def test_low_free_space_returns_warning(self):
        # 7% free → between 5% and 10%, triggers warning
        total = 500_000_000_000
        free = int(total * 0.07)
        container = _container(capacity_bytes=total, free_bytes=free)
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        warning_issues = [i for i in issues if i.severity == "warning" and "low disk space" in i.title.lower()]
        assert len(warning_issues) == 1

    def test_adequate_free_space_no_space_issue(self):
        # 50% free → no space warning
        total = 500_000_000_000
        free = total // 2
        container = _container(capacity_bytes=total, free_bytes=free)
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        assert not any("disk space" in i.title.lower() for i in issues)

    def test_container_with_zero_capacity_skipped(self):
        container = _container(capacity_bytes=0, free_bytes=0)
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        assert issues == []

    def test_smart_failure_returns_critical_issue(self):
        disk = _disk(identifier="disk0", name="WD Blue", smart_status="Failing")
        report = _report(disks=[disk])
        issues = identify_disk_issues(report)
        smart_issues = [i for i in issues if i.severity == "critical" and "SMART failure" in i.title]
        assert len(smart_issues) == 1
        assert "disk0" in smart_issues[0].title
        assert "Failing" in smart_issues[0].detail

    def test_smart_verified_no_smart_issue(self):
        disk = _disk(smart_status="Verified")
        report = _report(disks=[disk])
        issues = identify_disk_issues(report)
        assert not any("SMART" in i.title for i in issues)

    def test_smart_passed_no_smart_issue(self):
        disk = _disk(smart_status="PASSED")
        report = _report(disks=[disk])
        issues = identify_disk_issues(report)
        assert not any("SMART" in i.title for i in issues)

    def test_smart_not_supported_no_smart_issue(self):
        disk = _disk(smart_status="Not Supported")
        report = _report(disks=[disk])
        issues = identify_disk_issues(report)
        assert not any("SMART" in i.title for i in issues)

    def test_smart_from_smart_statuses_dict_triggers_issue(self):
        """SMART status looked up from smart_statuses dict (not inline) should still trigger."""
        disk = _disk(identifier="disk0", smart_status="")
        report = _report(disks=[disk], smart_statuses={"disk0": "Failing"})
        issues = identify_disk_issues(report)
        assert any("SMART failure" in i.title for i in issues)

    def test_unencrypted_system_volume_returns_warning(self):
        vol = _volume(role="System", encrypted=False, mount_point="/")
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        enc_issues = [i for i in issues if "not encrypted" in i.title]
        assert len(enc_issues) == 1
        assert enc_issues[0].severity == "warning"

    def test_unencrypted_data_volume_returns_warning(self):
        vol = _volume(name="Data", identifier="disk1s2", role="Data",
                      encrypted=False, mount_point="/System/Volumes/Data")
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        enc_issues = [i for i in issues if "not encrypted" in i.title]
        assert len(enc_issues) == 1

    def test_encrypted_system_volume_no_encryption_issue(self):
        vol = _volume(role="System", encrypted=True, mount_point="/")
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        assert not any("not encrypted" in i.title for i in issues)

    def test_non_boot_unencrypted_volume_no_issue(self):
        """Volumes that are not System/Data roles and not at '/' are not checked for encryption."""
        vol = _volume(name="Backup", identifier="disk1s5", role="",
                      encrypted=False, mount_point="/Volumes/Backup")
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        assert not any("not encrypted" in i.title for i in issues)

    def test_multiple_issues_returned_simultaneously(self):
        """Low space + SMART failure + unencrypted boot volume all fire at once."""
        total = 500_000_000_000
        free = int(total * 0.03)       # critically low
        vol = _volume(role="System", encrypted=False, mount_point="/")
        container = _container(capacity_bytes=total, free_bytes=free, volumes=[vol])
        disk = _disk(identifier="disk0", smart_status="Failing")
        report = _report(disks=[disk], containers=[container])
        issues = identify_disk_issues(report)
        severities = {i.severity for i in issues}
        assert "critical" in severities
        assert "warning" in severities
        assert len(issues) >= 3

    def test_volume_with_system_role_triggers_encryption_check(self):
        """Volume.role contains 'System' → checked for encryption."""
        vol = APFSVolume(
            name="Macintosh HD",
            identifier="disk1s1",
            role="System",
            encrypted=False,
            mounted=True,
            mount_point="",   # no '/' mount point, relies solely on role
        )
        container = _container(volumes=[vol])
        report = _report(containers=[container])
        issues = identify_disk_issues(report)
        assert any("not encrypted" in i.title for i in issues)

    def test_disk_issue_detail_not_empty(self):
        disk = _disk(smart_status="Failing")
        report = _report(disks=[disk])
        issues = identify_disk_issues(report)
        for issue in issues:
            assert issue.detail, "DiskIssue.detail must not be empty"


# ===========================================================================
# build_disk_report (mocked system calls)
# ===========================================================================

class TestBuildDiskReport:
    """build_disk_report() calls list_disks, list_apfs_containers, get_smart_status."""

    def test_returns_disk_report_instance(self):
        with patch("mactools_macdisk.engine.list_disks", return_value=[]), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=[]):
            result = build_disk_report()
        assert isinstance(result, DiskReport)

    def test_internal_disks_have_smart_status_fetched(self):
        disk = _disk(identifier="disk0", internal=True, smart_status="")
        with patch("mactools_macdisk.engine.list_disks", return_value=[disk]), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=[]), \
             patch("mactools_macdisk.engine.get_smart_status", return_value="Verified") as mock_smart:
            result = build_disk_report()
        mock_smart.assert_called_once_with("disk0")
        assert result.smart_statuses["disk0"] == "Verified"

    def test_external_disks_do_not_have_smart_status_fetched(self):
        disk = _disk(identifier="disk2", internal=False)
        with patch("mactools_macdisk.engine.list_disks", return_value=[disk]), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=[]), \
             patch("mactools_macdisk.engine.get_smart_status") as mock_smart:
            result = build_disk_report()
        mock_smart.assert_not_called()
        assert "disk2" not in result.smart_statuses

    def test_disks_propagated_to_report(self):
        disks = [_disk(identifier="disk0"), _disk(identifier="disk1", internal=False)]
        with patch("mactools_macdisk.engine.list_disks", return_value=disks), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=[]), \
             patch("mactools_macdisk.engine.get_smart_status", return_value="Verified"):
            result = build_disk_report()
        assert len(result.disks) == 2

    def test_containers_propagated_to_report(self):
        containers = [_container(identifier="disk1"), _container(identifier="disk2")]
        with patch("mactools_macdisk.engine.list_disks", return_value=[]), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=containers):
            result = build_disk_report()
        assert len(result.containers) == 2

    def test_multiple_internal_disks_all_get_smart_checked(self):
        disks = [
            _disk(identifier="disk0", internal=True),
            _disk(identifier="disk1", internal=True),
        ]
        with patch("mactools_macdisk.engine.list_disks", return_value=disks), \
             patch("mactools_macdisk.engine.list_apfs_containers", return_value=[]), \
             patch("mactools_macdisk.engine.get_smart_status", return_value="Verified") as mock_smart:
            result = build_disk_report()
        assert mock_smart.call_count == 2
        assert "disk0" in result.smart_statuses
        assert "disk1" in result.smart_statuses
