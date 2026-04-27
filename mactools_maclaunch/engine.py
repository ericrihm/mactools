"""maclaunch analysis engine — risk classification, audit, and statistics."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.launchctl import LaunchService


# Paths that are suspicious when found in launch service programs
_SUSPICIOUS_PATH_PATTERNS = [
    r"/tmp/",
    r"/var/tmp/",
    r"/private/tmp/",
    r"\.sh$",
    r"\.py$",
    r"\.rb$",
    r"\.pl$",
    r"/curl\b",
    r"/wget\b",
    r"/bash\b",
    r"/sh\b",
    r"/python\b",
    r"/ruby\b",
    r"/perl\b",
    r"\.app/Contents/MacOS/.*[Hh]elper",
]

# Labels that pattern-match known malware or adware families
_SUSPICIOUS_LABEL_PATTERNS = [
    r"^com\.mac\.",
    r"^com\.agent\.",
    r"\.helper\.",
    r"update.*agent",
    r"telemetry",
    r"tracker",
    r"syslog(?!d)",
    r"^[a-f0-9]{8}-[a-f0-9]{4}-",  # UUID-style labels (often injected)
]

# Programs in these directories are generally trusted
_TRUSTED_DIRS = [
    "/System/Library/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/sbin/",
    "/bin/",
]

# Vendors that are considered low-risk (established companies)
_TRUSTED_VENDORS = {
    "Apple", "Google", "Microsoft", "Adobe", "JetBrains",
    "Zoom", "Slack", "Spotify", "Mozilla", "1Password",
    "Docker", "OrbStack", "Homebrew", "CrowdStrike", "GitHub",
}


@dataclass
class AuditFinding:
    label: str
    risk: str          # safe / low / medium / high
    category: str      # persistence / unsigned / suspicious_path / resource_hog / unknown
    title: str
    detail: str
    program: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "risk": self.risk,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "program": self.program,
        }


def classify_risk(service: LaunchService) -> str:
    """Return risk level: safe / low / medium / high."""
    if service.is_apple:
        return "safe"

    vendor = service.vendor
    if vendor in _TRUSTED_VENDORS and vendor != "Third-party":
        base_risk = "low"
    else:
        base_risk = "medium"

    # Elevate risk for suspicious paths
    program = service.program or (service.program_args[0] if service.program_args else "")
    if program:
        for pattern in _SUSPICIOUS_PATH_PATTERNS:
            if re.search(pattern, program, re.IGNORECASE):
                return "high"
        # Check if program is in an untrusted location
        if not any(program.startswith(d) for d in _TRUSTED_DIRS):
            # App bundle paths (/Applications/) are normal — don't elevate
            if not program.startswith("/Applications/") and not program.startswith(
                str(os.path.expanduser("~"))
            ):
                if base_risk == "low":
                    base_risk = "medium"

    # Suspicious label patterns
    for pattern in _SUSPICIOUS_LABEL_PATTERNS:
        if re.search(pattern, service.label, re.IGNORECASE):
            return "high"

    return base_risk


def _is_unsigned(service: LaunchService) -> bool:
    """Heuristic: non-Apple service with no plist path is likely unregistered/injected."""
    if service.is_apple:
        return False
    if service.source in ("system", "global") and not service.plist_path:
        return True
    return False


def _is_persistence_vector(service: LaunchService) -> bool:
    """Flag services that auto-start AND keep alive — stronger persistence."""
    return (not service.is_apple) and service.run_at_load and service.keep_alive


def _has_suspicious_program(service: LaunchService) -> bool:
    program = service.program or (service.program_args[0] if service.program_args else "")
    if not program:
        return False
    for pattern in _SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, program, re.IGNORECASE):
            return True
    return False


def audit_services(services: list[LaunchService]) -> list[AuditFinding]:
    """Analyze a list of LaunchServices and return audit findings."""
    findings: list[AuditFinding] = []

    for svc in services:
        if svc.is_apple:
            continue

        risk = classify_risk(svc)
        program = svc.program or (svc.program_args[0] if svc.program_args else "")

        # Check: strong persistence (RunAtLoad + KeepAlive)
        if _is_persistence_vector(svc):
            findings.append(AuditFinding(
                label=svc.label,
                risk=risk,
                category="persistence",
                title=f"Strong persistence: {svc.label}",
                detail=(
                    "RunAtLoad=true and KeepAlive=true — this service auto-starts and "
                    "will be relaunched if it exits. Vendor: " + svc.vendor
                ),
                program=program or None,
            ))

        # Check: suspicious program path
        if _has_suspicious_program(svc):
            findings.append(AuditFinding(
                label=svc.label,
                risk="high",
                category="suspicious_path",
                title=f"Suspicious program path: {svc.label}",
                detail=f"Program references an unusual path or interpreter: {program}",
                program=program,
            ))

        # Check: suspicious label pattern
        for pattern in _SUSPICIOUS_LABEL_PATTERNS:
            if re.search(pattern, svc.label, re.IGNORECASE):
                findings.append(AuditFinding(
                    label=svc.label,
                    risk="high",
                    category="suspicious_label",
                    title=f"Suspicious label pattern: {svc.label}",
                    detail=f"Label matches a known malware/adware naming pattern ({pattern})",
                    program=program or None,
                ))
                break

        # Check: third-party non-Apple persistence in global/system scope
        if svc.source in ("global", "system") and not svc.is_apple and svc.vendor == "Third-party":
            findings.append(AuditFinding(
                label=svc.label,
                risk="medium",
                category="unknown_vendor_global",
                title=f"Unknown vendor in global scope: {svc.label}",
                detail=(
                    f"Third-party service installed in {svc.source} launch directory "
                    "with no recognized vendor."
                ),
                program=program or None,
            ))

        # Check: no plist on disk (orphan / injected)
        # Skip ephemeral macOS GUI agent registrations (application.* labels are dynamic,
        # created at runtime by macOS for running apps — they never have plists on disk)
        is_ephemeral_app_agent = svc.label.startswith("application.")
        if not svc.plist_path and not svc.is_apple and not is_ephemeral_app_agent:
            findings.append(AuditFinding(
                label=svc.label,
                risk="medium",
                category="orphan",
                title=f"No plist on disk: {svc.label}",
                detail="Service is registered with launchctl but has no plist file — may be injected or orphaned.",
                program=program or None,
            ))

    # Deduplicate by (label, category)
    seen: set[tuple[str, str]] = set()
    deduped = []
    for f in findings:
        key = (f.label, f.category)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def build_stats(services: list[LaunchService]) -> dict:
    """Return summary statistics about the service list."""
    total = len(services)
    running = sum(1 for s in services if s.running)
    stopped = total - running

    by_vendor: dict[str, int] = {}
    for svc in services:
        v = svc.vendor
        by_vendor[v] = by_vendor.get(v, 0) + 1

    by_source: dict[str, int] = {}
    for svc in services:
        src = svc.source
        by_source[src] = by_source.get(src, 0) + 1

    apple = sum(1 for s in services if s.is_apple)
    third_party = sum(1 for s in services if not s.is_apple)

    persistence = sum(1 for s in services if _is_persistence_vector(s))

    return {
        "total": total,
        "running": running,
        "stopped": stopped,
        "apple": apple,
        "third_party": third_party,
        "persistence_agents": persistence,
        "by_vendor": dict(sorted(by_vendor.items(), key=lambda x: -x[1])),
        "by_source": dict(sorted(by_source.items(), key=lambda x: -x[1])),
    }
