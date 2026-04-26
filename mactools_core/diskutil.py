"""macOS diskutil parser — APFS containers, volumes, SMART status."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run, run_plist


@dataclass
class DiskInfo:
    identifier: str
    name: str = ""
    size_bytes: int = 0
    media_type: str = ""
    protocol: str = ""
    internal: bool = True
    removable: bool = False
    smart_status: str = ""


@dataclass
class APFSContainer:
    identifier: str
    capacity_bytes: int = 0
    free_bytes: int = 0
    volumes: list[APFSVolume] = field(default_factory=list)


@dataclass
class APFSVolume:
    name: str
    identifier: str
    role: str = ""
    capacity_bytes: int = 0
    used_bytes: int = 0
    encrypted: bool = False
    mounted: bool = False
    mount_point: str = ""


def list_disks() -> list[DiskInfo]:
    data = run_plist(["diskutil", "list", "-plist"])
    if not data:
        return []
    disks = []
    for disk_id in data.get("WholeDisks", []):
        info = get_disk_info(disk_id)
        if info:
            disks.append(info)
    return disks


def get_disk_info(identifier: str) -> Optional[DiskInfo]:
    data = run_plist(["diskutil", "info", "-plist", identifier])
    if not data:
        return None
    return DiskInfo(
        identifier=identifier,
        name=data.get("MediaName", data.get("VolumeName", "")),
        size_bytes=data.get("TotalSize", 0),
        media_type=data.get("MediaType", ""),
        protocol=data.get("DeviceTreePath", data.get("BusProtocol", "")),
        internal=data.get("Internal", True),
        removable=data.get("Removable", False),
        smart_status=data.get("SMARTStatus", ""),
    )


def list_apfs_containers() -> list[APFSContainer]:
    data = run_plist(["diskutil", "apfs", "list", "-plist"])
    if not data:
        return []
    containers = []
    for c in data.get("Containers", []):
        volumes = []
        for v in c.get("Volumes", []):
            volumes.append(APFSVolume(
                name=v.get("Name", ""),
                identifier=v.get("DeviceIdentifier", ""),
                role=", ".join(v.get("Roles", [])),
                capacity_bytes=v.get("CapacityInUse", 0),
                used_bytes=v.get("CapacityInUse", 0),
                encrypted=v.get("Encryption", False),
                mounted=v.get("Mounted", False),
                mount_point=v.get("MountPoint", ""),
            ))
        containers.append(APFSContainer(
            identifier=c.get("ContainerReference", ""),
            capacity_bytes=c.get("CapacityCeiling", 0),
            free_bytes=c.get("CapacityFree", 0),
            volumes=volumes,
        ))
    return containers


def get_smart_status(disk: str = "disk0") -> str:
    r = run(["smartctl", "-H", f"/dev/{disk}"])
    if r.ok:
        for line in r.stdout.splitlines():
            if "SMART" in line and ("PASSED" in line or "OK" in line):
                return "PASSED"
            if "FAILED" in line:
                return "FAILED"
    data = run_plist(["diskutil", "info", "-plist", disk])
    if data:
        return data.get("SMARTStatus", "unknown")
    return "unknown"
