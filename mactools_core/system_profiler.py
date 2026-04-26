"""macOS system_profiler parser — wraps all 48+ data types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from mactools_core.runner import run_plist, run


COMMON_TYPES = [
    "SPHardwareDataType", "SPSoftwareDataType", "SPMemoryDataType",
    "SPStorageDataType", "SPNVMeDataType", "SPDisplaysDataType",
    "SPNetworkDataType", "SPFirewallDataType", "SPAirPortDataType",
    "SPBluetoothDataType", "SPPowerDataType", "SPUSBDataType",
    "SPThunderboltDataType", "SPApplicationsDataType",
]


@dataclass
class HardwareInfo:
    model: str = ""
    chip: str = ""
    cores_total: int = 0
    cores_performance: int = 0
    cores_efficiency: int = 0
    memory_gb: int = 0
    serial: str = ""
    os_version: str = ""
    hostname: str = ""


@dataclass
class StorageVolume:
    name: str = ""
    mount_point: str = ""
    filesystem: str = ""
    size_bytes: int = 0
    free_bytes: int = 0
    writable: bool = True
    encrypted: bool = False


@dataclass
class FirewallInfo:
    enabled: bool = False
    mode: str = "off"
    stealth: bool = False
    block_all: bool = False
    allow_signed: bool = False
    allowed_apps: list[str] = None

    def __post_init__(self):
        if self.allowed_apps is None:
            self.allowed_apps = []


def get_data_type(dtype: str) -> list[dict]:
    data = run_plist(["system_profiler", dtype, "-xml"])
    if not data or not isinstance(data, list):
        return []
    items = data[0].get("_items", []) if data else []
    return items


def get_hardware() -> HardwareInfo:
    items = get_data_type("SPHardwareDataType")
    if not items:
        return HardwareInfo()
    hw = items[0]
    cores_total, cores_perf, cores_eff = _parse_cores(hw.get("number_processors", "0"))
    return HardwareInfo(
        model=hw.get("machine_name", hw.get("machine_model", "")),
        chip=hw.get("chip_type", hw.get("cpu_type", "")),
        cores_total=cores_total,
        cores_performance=cores_perf,
        cores_efficiency=cores_eff,
        memory_gb=_parse_memory(hw.get("physical_memory", "")),
        serial=hw.get("serial_number", ""),
        os_version=hw.get("os_version", ""),
        hostname=hw.get("local_host_name", ""),
    )


def get_storage() -> list[StorageVolume]:
    items = get_data_type("SPStorageDataType")
    volumes = []
    for item in items:
        volumes.append(StorageVolume(
            name=item.get("_name", ""),
            mount_point=item.get("mount_point", ""),
            filesystem=item.get("file_system", ""),
            size_bytes=int(item.get("size_in_bytes", 0) or 0),
            free_bytes=int(item.get("free_space_in_bytes", 0) or 0),
            writable=item.get("writable", "yes") == "yes",
            encrypted=item.get("encrypted", "no") == "yes",
        ))
    return volumes


def get_firewall() -> FirewallInfo:
    items = get_data_type("SPFirewallDataType")
    if not items:
        return FirewallInfo()
    fw = items[0]
    mode = fw.get("spfirewall_globalstate", "")
    # 'spfirewall_globalstate_off' → disabled; anything else → enabled
    enabled = "off" not in mode.lower() and mode not in ("0", "off", "")
    block_all = "block_all" in mode.lower() or fw.get("spfirewall_blockall", "No") in ("1", "Yes")
    # stealth: key may be 'spfirewall_stealthmode' or 'spfirewall_stealthenabled'
    stealth_val = fw.get("spfirewall_stealthmode", fw.get("spfirewall_stealthenabled", "No"))
    stealth = stealth_val in ("1", "Yes")
    allow_signed_val = fw.get("spfirewall_allowsigned", "No")
    allow_signed = allow_signed_val in ("1", "Yes")
    # allowed_apps may be a dict {bundle_id: permission} or a list of dicts
    raw_apps = fw.get("spfirewall_applications", {})
    if isinstance(raw_apps, dict):
        allowed_apps = list(raw_apps.keys())
    elif isinstance(raw_apps, list):
        allowed_apps = [
            a.get("_name", str(a)) if isinstance(a, dict) else str(a)
            for a in raw_apps
        ]
    else:
        allowed_apps = []
    return FirewallInfo(
        enabled=enabled,
        mode=mode,
        stealth=stealth,
        block_all=block_all,
        allow_signed=allow_signed,
        allowed_apps=allowed_apps,
    )


def get_all_types() -> list[str]:
    r = run(["system_profiler", "-listDataTypes"])
    if not r.ok:
        return COMMON_TYPES
    return [line.strip() for line in r.stdout.splitlines() if line.strip().startswith("SP")]


def _parse_cores(procs_str: str) -> tuple[int, int, int]:
    """Parse 'number_processors' which may be 'proc 10:4:6' or a plain int string."""
    import re
    # Apple Silicon: 'proc <total>:<perf>:<eff>'
    m = re.search(r"(\d+):(\d+):(\d+)", str(procs_str))
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    # Intel / plain number
    m2 = re.search(r"\d+", str(procs_str))
    return (int(m2.group()) if m2 else 0), 0, 0


def _parse_memory(mem_str: str) -> int:
    import re
    m = re.search(r"(\d+)\s*GB", mem_str, re.IGNORECASE)
    return int(m.group(1)) if m else 0
