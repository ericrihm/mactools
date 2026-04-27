"""macdisk analysis engine — disk report builder, issue detection, formatting."""

from __future__ import annotations

from dataclasses import dataclass, field

from mactools_core.diskutil import (
    APFSContainer,
    APFSVolume,
    DiskInfo,
    get_smart_status,
    list_apfs_containers,
    list_disks,
)
from mactools_core.output import format_bytes as format_size


# ---------------------------------------------------------------------------
# Disk report
# ---------------------------------------------------------------------------

@dataclass
class DiskReport:
    disks: list[DiskInfo]
    containers: list[APFSContainer]
    smart_statuses: dict[str, str]  # disk_id → SMART status

    @property
    def total_capacity_bytes(self) -> int:
        return sum(d.size_bytes for d in self.disks)

    @property
    def total_free_bytes(self) -> int:
        return sum(c.free_bytes for c in self.containers)

    def to_dict(self) -> dict:
        return {
            "disks": [
                {
                    "identifier": d.identifier,
                    "name": d.name,
                    "size": format_size(d.size_bytes),
                    "size_bytes": d.size_bytes,
                    "media_type": d.media_type,
                    "protocol": d.protocol,
                    "internal": d.internal,
                    "removable": d.removable,
                    "smart_status": d.smart_status or self.smart_statuses.get(d.identifier, "unknown"),
                }
                for d in self.disks
            ],
            "apfs_containers": [
                {
                    "identifier": c.identifier,
                    "capacity": format_size(c.capacity_bytes),
                    "capacity_bytes": c.capacity_bytes,
                    "free": format_size(c.free_bytes),
                    "free_bytes": c.free_bytes,
                    "used_pct": (
                        round((c.capacity_bytes - c.free_bytes) / c.capacity_bytes * 100, 1)
                        if c.capacity_bytes > 0 else 0
                    ),
                    "volumes": [
                        {
                            "name": v.name,
                            "identifier": v.identifier,
                            "role": v.role,
                            "used": format_size(v.used_bytes),
                            "used_bytes": v.used_bytes,
                            "encrypted": v.encrypted,
                            "mounted": v.mounted,
                            "mount_point": v.mount_point,
                        }
                        for v in c.volumes
                    ],
                }
                for c in self.containers
            ],
            "summary": {
                "total_capacity": format_size(self.total_capacity_bytes),
                "total_free": format_size(self.total_free_bytes),
            },
        }


def build_disk_report() -> DiskReport:
    """Fetch disk info, APFS containers, and SMART status into a DiskReport."""
    disks = list_disks()
    containers = list_apfs_containers()

    smart_statuses: dict[str, str] = {}
    for disk in disks:
        if disk.internal:
            status = get_smart_status(disk.identifier)
            smart_statuses[disk.identifier] = status

    return DiskReport(disks=disks, containers=containers, smart_statuses=smart_statuses)


# ---------------------------------------------------------------------------
# Issue detection
# ---------------------------------------------------------------------------

@dataclass
class DiskIssue:
    severity: str  # critical / warning / info
    title: str
    detail: str


_LOW_SPACE_PCT = 10.0      # < 10% free → warning
_CRITICAL_SPACE_PCT = 5.0  # < 5% free → critical
_SNAPSHOT_THRESHOLD = 3    # more than this many snapshots is noteworthy


def identify_disk_issues(report: DiskReport) -> list[DiskIssue]:
    """Inspect a DiskReport and return a list of DiskIssue findings.

    Checks for:
    - Low or critically low free space on APFS containers
    - SMART failures on internal disks
    - Unencrypted boot volumes (role contains 'System' or mount point is '/')
    - Excessive snapshots (placeholder — diskutil snapshot list is separate)
    """
    issues: list[DiskIssue] = []

    # Space checks
    for container in report.containers:
        if container.capacity_bytes <= 0:
            continue
        free_pct = container.free_bytes / container.capacity_bytes * 100
        free_str = format_size(container.free_bytes)
        cap_str = format_size(container.capacity_bytes)

        if free_pct < _CRITICAL_SPACE_PCT:
            issues.append(DiskIssue(
                severity="critical",
                title=f"Critically low disk space on {container.identifier}",
                detail=f"Only {free_str} free ({free_pct:.1f}%) of {cap_str} — disk is nearly full.",
            ))
        elif free_pct < _LOW_SPACE_PCT:
            issues.append(DiskIssue(
                severity="warning",
                title=f"Low disk space on {container.identifier}",
                detail=f"{free_str} free ({free_pct:.1f}%) of {cap_str}.",
            ))

        # Unencrypted boot/system volume
        for volume in container.volumes:
            is_boot = (
                volume.mount_point == "/"
                or "System" in volume.role
                or "Data" in volume.role
            )
            if is_boot and not volume.encrypted:
                issues.append(DiskIssue(
                    severity="warning",
                    title=f"Volume '{volume.name}' ({volume.identifier}) is not encrypted",
                    detail=(
                        "FileVault encryption is not enabled on this volume. "
                        "Enable FileVault in System Settings → Privacy & Security."
                    ),
                ))

    # SMART failures
    for disk in report.disks:
        smart = disk.smart_status or report.smart_statuses.get(disk.identifier, "")
        if smart and smart.upper() not in ("VERIFIED", "PASSED", "OK", "NOT SUPPORTED", ""):
            issues.append(DiskIssue(
                severity="critical",
                title=f"SMART failure on {disk.identifier} ({disk.name or 'unknown'})",
                detail=(
                    f"SMART status: {smart}. Back up data immediately and consider "
                    "replacing this disk."
                ),
            ))

    return issues
