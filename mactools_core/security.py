"""macOS security primitives — SIP, Gatekeeper, FileVault, codesign, keychain."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run


@dataclass
class SIPStatus:
    enabled: bool = True
    details: str = ""


@dataclass
class GatekeeperStatus:
    enabled: bool = True
    details: str = ""


@dataclass
class FileVaultStatus:
    enabled: bool = False
    details: str = ""


@dataclass
class CodeSignature:
    path: str = ""
    signed: bool = False
    valid: bool = False
    authority_chain: list[str] = field(default_factory=list)
    identifier: str = ""
    team_id: str = ""
    format: str = ""
    flags: str = ""
    entitlements: dict = field(default_factory=dict)
    notarized: bool = False
    error: str = ""


@dataclass
class SecurityPosture:
    sip: SIPStatus = field(default_factory=SIPStatus)
    gatekeeper: GatekeeperStatus = field(default_factory=GatekeeperStatus)
    filevault: FileVaultStatus = field(default_factory=FileVaultStatus)
    firewall_enabled: bool = False
    firewall_stealth: bool = False
    remote_login: bool = False
    remote_management: bool = False


def get_sip_status() -> SIPStatus:
    r = run(["csrutil", "status"])
    text = r.stdout + r.stderr
    enabled = "enabled" in text.lower() and "disabled" not in text.lower()
    return SIPStatus(enabled=enabled, details=text.strip())


def get_gatekeeper_status() -> GatekeeperStatus:
    r = run(["spctl", "--status"])
    text = r.stdout + r.stderr
    enabled = "enabled" in text.lower() or "assessments enabled" in text.lower()
    return GatekeeperStatus(enabled=enabled, details=text.strip())


def get_filevault_status() -> FileVaultStatus:
    r = run(["fdesetup", "status"])
    text = r.stdout + r.stderr
    enabled = "on" in text.lower() or "encryption" in text.lower()
    return FileVaultStatus(enabled=enabled, details=text.strip())


def get_remote_login() -> bool:
    r = run(["systemsetup", "-getremotelogin"])
    return "on" in (r.stdout + r.stderr).lower()


def check_codesign(path: str) -> CodeSignature:
    sig = CodeSignature(path=path)
    r = run(["codesign", "-dvvv", path])
    text = r.stdout + r.stderr
    if r.returncode != 0 and "not signed" in text.lower():
        sig.error = "not signed"
        return sig
    sig.signed = True
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Authority="):
            sig.authority_chain.append(line.split("=", 1)[1])
        elif line.startswith("Identifier="):
            sig.identifier = line.split("=", 1)[1]
        elif line.startswith("TeamIdentifier="):
            sig.team_id = line.split("=", 1)[1]
        elif line.startswith("Format="):
            sig.format = line.split("=", 1)[1]
        elif line.startswith("Flags="):
            sig.flags = line.split("=", 1)[1]
    r2 = run(["spctl", "--assess", "--verbose", path])
    text2 = r2.stdout + r2.stderr
    sig.valid = r2.returncode == 0
    sig.notarized = "notarized" in text2.lower()
    r3 = run(["codesign", "-d", "--entitlements", ":-", path])
    if r3.ok and r3.stdout.strip():
        try:
            import plistlib
            sig.entitlements = plistlib.loads(r3.stdout.encode())
        except (plistlib.InvalidFileException, ValueError):
            pass
    return sig


def get_security_posture() -> SecurityPosture:
    from mactools_core.system_profiler import get_firewall
    fw = get_firewall()
    rm = _check_remote_management()
    return SecurityPosture(
        sip=get_sip_status(),
        gatekeeper=get_gatekeeper_status(),
        filevault=get_filevault_status(),
        firewall_enabled=fw.enabled,
        firewall_stealth=fw.stealth,
        remote_login=get_remote_login(),
        remote_management=rm,
    )


def _check_remote_management() -> bool:
    r = run(["ps", "aux"])
    if r.ok:
        return "ARDAgent" in r.stdout or "screensharingd" in r.stdout
    return False
