"""Code signing intelligence engine — scans apps, audits entitlements, lists packages."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run
from mactools_core.security import check_codesign, CodeSignature


# Entitlements considered high-risk
DANGEROUS_ENTITLEMENTS: dict[str, str] = {
    "com.apple.security.cs.disable-library-validation": (
        "Allows loading arbitrary unsigned dynamic libraries (dylib injection risk)"
    ),
    "com.apple.security.cs.allow-unsigned-executable-memory": (
        "Permits JIT / unsigned executable memory (exploitability risk)"
    ),
    "com.apple.security.cs.allow-dyld-environment-variables": (
        "Allows DYLD_ env vars that could redirect library loading"
    ),
    "com.apple.security.cs.debugger": (
        "App can attach as debugger to other processes"
    ),
    "com.apple.security.get-task-allow": (
        "Other processes can attach a debugger to this app (dev builds only)"
    ),
    "com.apple.private.tcc.allow": (
        "Private TCC entitlement granting broad privacy permissions without user prompt"
    ),
    "com.apple.system-task-ports": (
        "Can access mach task ports of other processes — effectively root-equivalent"
    ),
    "com.apple.security.cs.allow-jit": (
        "Enables JIT compilation; weaker code-signing guarantees"
    ),
}

# Entitlements worth noting but not necessarily dangerous
NOTABLE_ENTITLEMENTS: set[str] = {
    "com.apple.security.network.client",
    "com.apple.security.network.server",
    "com.apple.security.files.user-selected.read-write",
    "com.apple.security.files.all",
    "com.apple.security.device.camera",
    "com.apple.security.device.microphone",
    "com.apple.security.personal-information.location",
    "com.apple.security.personal-information.contacts",
    "com.apple.security.personal-information.calendars",
    "com.apple.security.personal-information.photos-library",
}


@dataclass
class AppSignatureResult:
    path: str
    name: str
    signature: CodeSignature
    dangerous_entitlements: list[dict] = field(default_factory=list)
    notable_entitlements: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "signed": self.signature.signed,
            "valid": self.signature.valid,
            "notarized": self.signature.notarized,
            "identifier": self.signature.identifier,
            "team_id": self.signature.team_id,
            "authority_chain": self.signature.authority_chain,
            "format": self.signature.format,
            "flags": self.signature.flags,
            "error": self.signature.error,
            "dangerous_entitlements": self.dangerous_entitlements,
            "notable_entitlements": self.notable_entitlements,
        }


@dataclass
class PackageInfo:
    pkg_id: str
    version: str = ""
    volume: str = ""
    location: str = ""
    install_time: str = ""

    def as_dict(self) -> dict:
        return {
            "pkg_id": self.pkg_id,
            "version": self.version,
            "volume": self.volume,
            "location": self.location,
            "install_time": self.install_time,
        }


def scan_applications(directory: str = "/Applications") -> list[AppSignatureResult]:
    """Scan all .app bundles in directory and check their code signatures."""
    results: list[AppSignatureResult] = []

    if not os.path.isdir(directory):
        return results

    for entry in sorted(os.scandir(directory), key=lambda e: e.name.lower()):
        if not entry.name.endswith(".app"):
            continue
        path = entry.path
        name = entry.name.removesuffix(".app")
        sig = check_codesign(path)
        dangerous, notable = audit_entitlements(sig)
        results.append(AppSignatureResult(
            path=path,
            name=name,
            signature=sig,
            dangerous_entitlements=dangerous,
            notable_entitlements=notable,
        ))

    return results


def audit_entitlements(sig: CodeSignature) -> tuple[list[dict], list[str]]:
    """Inspect entitlements dict and return (dangerous_list, notable_list).

    dangerous_list: list of {key, reason}
    notable_list: list of entitlement keys that are noteworthy
    """
    dangerous: list[dict] = []
    notable: list[str] = []

    for key, value in sig.entitlements.items():
        if not value:
            continue
        if key in DANGEROUS_ENTITLEMENTS:
            dangerous.append({"key": key, "reason": DANGEROUS_ENTITLEMENTS[key]})
        elif key in NOTABLE_ENTITLEMENTS:
            notable.append(key)

    return dangerous, notable


def list_packages() -> list[PackageInfo]:
    """List installed packages via pkgutil with per-package details."""
    r = run(["pkgutil", "--pkgs"])
    if not r.ok:
        return []

    packages: list[PackageInfo] = []
    for pkg_id in r.stdout.strip().splitlines():
        pkg_id = pkg_id.strip()
        if not pkg_id:
            continue
        info = _get_pkg_info(pkg_id)
        packages.append(info)

    return packages


def _get_pkg_info(pkg_id: str) -> PackageInfo:
    """Fetch metadata for a single package ID."""
    r = run(["pkgutil", "--pkg-info", pkg_id])
    info = PackageInfo(pkg_id=pkg_id)
    if not r.ok:
        return info
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("version:"):
            info.version = line.split(":", 1)[1].strip()
        elif line.startswith("volume:"):
            info.volume = line.split(":", 1)[1].strip()
        elif line.startswith("location:"):
            info.location = line.split(":", 1)[1].strip()
        elif line.startswith("install-time:"):
            info.install_time = line.split(":", 1)[1].strip()
    return info
