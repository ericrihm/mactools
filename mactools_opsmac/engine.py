"""opsmac engine — health data collection, scoring, and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mactools_core import system_profiler, security, power, diskutil
from mactools_core.system_profiler import HardwareInfo, StorageVolume, FirewallInfo
from mactools_core.security import SecurityPosture
from mactools_core.power import PowerSettings, SleepPreventer, ThermalState
from mactools_core.diskutil import APFSContainer, DiskInfo


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class StorageSummary:
    total_bytes: int = 0
    free_bytes: int = 0
    used_bytes: int = 0
    volumes: list[StorageVolume] = field(default_factory=list)
    apfs_containers: list[APFSContainer] = field(default_factory=list)
    disks: list[DiskInfo] = field(default_factory=list)
    smart_status: str = "unknown"

    @property
    def used_pct(self) -> float:
        return (self.used_bytes / self.total_bytes * 100) if self.total_bytes else 0.0

    @property
    def free_gb(self) -> float:
        return self.free_bytes / 1e9

    @property
    def total_gb(self) -> float:
        return self.total_bytes / 1e9


@dataclass
class ServiceSummary:
    total: int = 0
    running: int = 0
    failed: int = 0
    third_party_running: int = 0


@dataclass
class NetworkSummary:
    active_interface: str = ""
    port_count: int = 0
    dns_ok: bool = True


@dataclass
class HealthReport:
    hardware: HardwareInfo = field(default_factory=HardwareInfo)
    storage: StorageSummary = field(default_factory=StorageSummary)
    security: SecurityPosture = field(default_factory=SecurityPosture)
    firewall: FirewallInfo = field(default_factory=FirewallInfo)
    power_settings: PowerSettings = field(default_factory=PowerSettings)
    sleep_preventers: list[SleepPreventer] = field(default_factory=list)
    thermal: ThermalState = field(default_factory=ThermalState)
    services: ServiceSummary = field(default_factory=ServiceSummary)
    network: NetworkSummary = field(default_factory=NetworkSummary)
    score: Optional[int] = None
    findings: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def collect_health_data() -> HealthReport:
    """Gather all Mac health data and return a HealthReport."""
    report = HealthReport()

    # Hardware
    report.hardware = system_profiler.get_hardware()

    # Storage — use APFS containers for capacity, SPStorage for volume list
    volumes = system_profiler.get_storage()
    containers = diskutil.list_apfs_containers()
    disks = diskutil.list_disks()

    # Find the root volume to get overall capacity
    root_vol = next((v for v in volumes if v.mount_point == "/"), None)
    if root_vol:
        total = root_vol.size_bytes
        free = root_vol.free_bytes
    elif containers:
        total = sum(c.capacity_bytes for c in containers)
        free = sum(c.free_bytes for c in containers)
    else:
        total = 0
        free = 0

    smart = "unknown"
    if disks:
        first_internal = next((d for d in disks if d.internal), disks[0] if disks else None)
        if first_internal:
            smart = diskutil.get_smart_status(first_internal.identifier)

    report.storage = StorageSummary(
        total_bytes=total,
        free_bytes=free,
        used_bytes=max(0, total - free),
        volumes=volumes,
        apfs_containers=containers,
        disks=disks,
        smart_status=smart,
    )

    # Security
    report.security = security.get_security_posture()
    report.firewall = system_profiler.get_firewall()

    # Power
    report.power_settings = power.get_power_settings()
    report.sleep_preventers = power.get_sleep_preventers()
    report.thermal = power.get_thermal_state()

    # Services (lightweight — just launchctl list counts)
    try:
        from mactools_core import launchctl
        svcs = launchctl.list_services()
        third_party = [s for s in svcs if not s.is_apple and s.running]
        failed = [s for s in svcs if s.status not in (0, -1) and s.pid == -1]
        report.services = ServiceSummary(
            total=len(svcs),
            running=sum(1 for s in svcs if s.running),
            failed=len(failed),
            third_party_running=len(third_party),
        )
    except Exception:
        pass

    # Network (lightweight)
    try:
        from mactools_core import network
        overview = network.get_network_overview()
        report.network = NetworkSummary(
            active_interface=overview.active_interface,
            port_count=len(overview.ports),
            dns_ok=len(overview.dns_resolvers) > 0,
        )
    except Exception:
        pass

    # Score and findings
    report.findings = identify_findings(report)
    report.score = compute_health_score(report)
    return report


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_health_score(report: HealthReport) -> int:
    """Compute overall health score 0-100 across five categories.

    Breakdown:
      hardware  20 pts
      storage   20 pts
      security  30 pts
      power     15 pts
      services  15 pts
    """
    return compute_score_breakdown(report)["total"]


def compute_score_breakdown(report: HealthReport) -> dict[str, int]:
    """Return per-category scores as well as total."""
    sec = report.security
    fw = report.firewall

    hw = 20
    if report.thermal.level == "throttled":
        hw -= 5
    elif report.thermal.level == "critical":
        hw -= 15
    if report.storage.smart_status.upper() in ("FAILED", "FAILING"):
        hw -= 10
    hw = max(0, hw)

    st = 20
    used_pct = report.storage.used_pct
    if used_pct >= 95:
        st -= 15
    elif used_pct >= 85:
        st -= 10
    elif used_pct >= 70:
        st -= 5
    if report.storage.smart_status.upper() in ("FAILED", "FAILING"):
        st -= 10
    st = max(0, st)

    sc = 30
    if not sec.sip.enabled:
        sc -= 10
    if not sec.gatekeeper.enabled:
        sc -= 8
    if not sec.filevault.enabled:
        sc -= 7
    if not fw.enabled:
        sc -= 5
    if sec.remote_login:
        sc -= 2
    if fw.enabled and not fw.stealth:
        sc -= 1
    sc = max(0, sc)

    pw = 15
    if len(report.sleep_preventers) >= 3:
        pw -= 5
    elif len(report.sleep_preventers) >= 1:
        pw -= 2
    if report.thermal.level != "nominal":
        pw -= 3
    pw = max(0, pw)

    sv = 15
    if report.services.failed >= 5:
        sv -= 10
    elif report.services.failed >= 2:
        sv -= 5
    elif report.services.failed >= 1:
        sv -= 2
    sv = max(0, sv)

    return {
        "hardware": hw,
        "hardware_max": 20,
        "storage": st,
        "storage_max": 20,
        "security": sc,
        "security_max": 30,
        "power": pw,
        "power_max": 15,
        "services": sv,
        "services_max": 15,
        "total": min(100, hw + st + sc + pw + sv),
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def identify_findings(report: HealthReport) -> list[dict]:
    """Return a list of finding dicts with keys: severity, title, detail, category."""
    findings = []

    def add(severity: str, title: str, detail: str = "", category: str = "general"):
        findings.append({"severity": severity, "title": title, "detail": detail, "category": category})

    sec = report.security
    fw = report.firewall

    # --- Security findings ---
    if not sec.sip.enabled:
        add("critical", "System Integrity Protection (SIP) is disabled",
            "Re-enable with: csrutil enable (requires Recovery Mode)", "security")
    if not sec.gatekeeper.enabled:
        add("warning", "Gatekeeper is disabled",
            "Re-enable with: sudo spctl --master-enable", "security")
    if not sec.filevault.enabled:
        add("warning", "FileVault encryption is off",
            "Enable in System Settings > Privacy & Security > FileVault", "security")
    if not fw.enabled:
        add("warning", "Firewall is disabled",
            "Enable in System Settings > Network > Firewall", "security")
    elif fw.mode in ("1", "on") and not fw.stealth:
        add("info", "Firewall is on but stealth mode is off",
            "Stealth mode hides the Mac from unsolicited network probes", "security")
    if fw.enabled and fw.block_all:
        add("info", "Firewall set to block all incoming connections", category="security")
    if sec.remote_login:
        add("warning", "Remote Login (SSH) is enabled",
            "Disable in System Settings > General > Sharing if not needed", "security")

    # --- Storage findings ---
    used_pct = report.storage.used_pct
    if used_pct >= 95:
        add("critical", f"Disk critically full ({used_pct:.0f}% used)",
            f"Only {report.storage.free_gb:.1f} GB remaining", "storage")
    elif used_pct >= 85:
        add("warning", f"Disk almost full ({used_pct:.0f}% used)",
            f"{report.storage.free_gb:.1f} GB free", "storage")
    elif used_pct >= 70:
        add("info", f"Disk usage is high ({used_pct:.0f}% used)",
            f"{report.storage.free_gb:.1f} GB free", "storage")

    if report.storage.smart_status.upper() in ("FAILED", "FAILING"):
        add("critical", f"SMART status: {report.storage.smart_status}",
            "Disk failure detected — back up immediately", "storage")
    elif report.storage.smart_status.lower() not in ("verified", "passed", "ok", "unknown", ""):
        add("warning", f"SMART status: {report.storage.smart_status}", category="storage")

    # Unencrypted writable volumes
    unenc = [v for v in report.storage.volumes
             if v.writable and not v.encrypted and v.mount_point == "/"]
    if unenc:
        add("info", "Root volume is not encrypted (FileVault off)", category="storage")

    # --- Power findings ---
    for sp in report.sleep_preventers:
        add("info", f"{sp.name} preventing sleep",
            f"Assertion: {sp.assertion_type} — \"{sp.detail}\"", "power")

    if report.thermal.level == "critical":
        add("critical", "CPU is critically throttled due to thermal pressure",
            f"Speed limit: {report.thermal.cpu_speed_limit}%", "power")
    elif report.thermal.level == "throttled":
        add("warning", "CPU is thermally throttled",
            f"Speed limit: {report.thermal.cpu_speed_limit}%", "power")

    # --- Services findings ---
    if report.services.failed >= 5:
        add("warning", f"{report.services.failed} launch services have exited with errors",
            "Run: launchctl list | awk '$2 != 0 && $1 == \"-\"'", "services")
    elif report.services.failed >= 1:
        add("info", f"{report.services.failed} launch service(s) exited with non-zero status",
            "", "services")

    # --- Hardware findings ---
    if report.thermal.level not in ("nominal", ""):
        pass  # already captured above in power

    # Sort: critical first, then warning, then info, then ok
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    return findings
