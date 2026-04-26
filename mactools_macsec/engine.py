"""Security posture audit engine — checks SIP, Gatekeeper, FileVault, firewall, remote access."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run
from mactools_core.security import (
    get_sip_status,
    get_gatekeeper_status,
    get_filevault_status,
)
from mactools_core.system_profiler import get_firewall


@dataclass
class SecurityFinding:
    title: str
    severity: str  # "critical", "warning", "info", "ok"
    detail: str
    fix_command: Optional[str] = None
    category: str = ""

    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "fix_command": self.fix_command,
            "category": self.category,
        }


def _check_auto_login() -> bool:
    """Return True if auto-login is enabled (any user set)."""
    r = run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    return r.ok and r.stdout.strip() not in ("", "0")


def _check_screen_sharing() -> bool:
    """Return True if screen sharing is on."""
    r = run(["launchctl", "list", "com.apple.screensharing"])
    return r.ok


def _check_remote_management() -> bool:
    """Return True if remote management (ARD) is on."""
    r = run(["launchctl", "list", "com.apple.RemoteDesktop.agent"])
    return r.ok


def _check_remote_apple_events() -> bool:
    """Return True if remote Apple Events are enabled."""
    r = run(["systemsetup", "-getremoteappleevents"])
    return "on" in (r.stdout + r.stderr).lower()


def audit_security() -> list[SecurityFinding]:
    """Run full security posture audit and return list of SecurityFinding."""
    findings: list[SecurityFinding] = []

    # --- SIP ---
    sip = get_sip_status()
    if sip.enabled:
        findings.append(SecurityFinding(
            title="System Integrity Protection (SIP)",
            severity="ok",
            detail="SIP is enabled — system files are protected.",
            category="SIP",
        ))
    else:
        findings.append(SecurityFinding(
            title="System Integrity Protection (SIP) disabled",
            severity="critical",
            detail=f"SIP is disabled. System files and processes are unprotected. Detail: {sip.details}",
            fix_command="csrutil enable  # Reboot into Recovery Mode (hold power), open Terminal, run this",
            category="SIP",
        ))

    # --- Gatekeeper ---
    gk = get_gatekeeper_status()
    if gk.enabled:
        findings.append(SecurityFinding(
            title="Gatekeeper",
            severity="ok",
            detail="Gatekeeper is enabled — only signed software can run.",
            category="Gatekeeper",
        ))
    else:
        findings.append(SecurityFinding(
            title="Gatekeeper disabled",
            severity="critical",
            detail="Gatekeeper is disabled. Unsigned/malicious apps can run without warning.",
            fix_command="sudo spctl --master-enable",
            category="Gatekeeper",
        ))

    # --- FileVault ---
    fv = get_filevault_status()
    if fv.enabled:
        findings.append(SecurityFinding(
            title="FileVault disk encryption",
            severity="ok",
            detail=f"FileVault is on. {fv.details}",
            category="FileVault",
        ))
    else:
        findings.append(SecurityFinding(
            title="FileVault disk encryption disabled",
            severity="critical",
            detail="Disk is not encrypted. Data is accessible if the Mac is stolen.",
            fix_command="sudo fdesetup enable  # Or: System Settings > Privacy & Security > FileVault",
            category="FileVault",
        ))

    # --- Firewall ---
    fw = get_firewall()
    if fw.enabled:
        findings.append(SecurityFinding(
            title="Firewall",
            severity="ok",
            detail=f"Firewall is active (mode: {fw.mode}).",
            category="Firewall",
        ))
    else:
        findings.append(SecurityFinding(
            title="Firewall disabled",
            severity="critical",
            detail="The macOS application firewall is off. Incoming connections are unrestricted.",
            fix_command="/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            category="Firewall",
        ))

    # --- Firewall stealth mode ---
    if fw.enabled and fw.stealth:
        findings.append(SecurityFinding(
            title="Firewall stealth mode",
            severity="ok",
            detail="Stealth mode is enabled — the Mac will not respond to ICMP pings.",
            category="Firewall",
        ))
    elif fw.enabled and not fw.stealth:
        findings.append(SecurityFinding(
            title="Firewall stealth mode disabled",
            severity="warning",
            detail="Stealth mode is off. The Mac responds to network probes (ICMP ping).",
            fix_command="/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
            category="Firewall",
        ))

    # --- Remote login (SSH) ---
    r_ssh = run(["systemsetup", "-getremotelogin"])
    ssh_on = "on" in (r_ssh.stdout + r_ssh.stderr).lower()
    if ssh_on:
        findings.append(SecurityFinding(
            title="Remote Login (SSH) enabled",
            severity="warning",
            detail="SSH is on. Ensure only trusted keys are authorized and password auth is disabled.",
            fix_command="sudo systemsetup -setremotelogin off",
            category="Remote",
        ))
    else:
        findings.append(SecurityFinding(
            title="Remote Login (SSH)",
            severity="ok",
            detail="SSH remote login is disabled.",
            category="Remote",
        ))

    # --- Screen sharing ---
    screen_on = _check_screen_sharing()
    if screen_on:
        findings.append(SecurityFinding(
            title="Screen Sharing enabled",
            severity="warning",
            detail="Screen sharing (VNC) is active. Remote users may view/control your screen.",
            fix_command="sudo launchctl disable system/com.apple.screensharing",
            category="Remote",
        ))
    else:
        findings.append(SecurityFinding(
            title="Screen Sharing",
            severity="ok",
            detail="Screen sharing is disabled.",
            category="Remote",
        ))

    # --- Remote management (ARD) ---
    ard_on = _check_remote_management()
    if ard_on:
        findings.append(SecurityFinding(
            title="Remote Management (Apple Remote Desktop) enabled",
            severity="warning",
            detail="ARD agent is running. Administrators can remotely control this Mac.",
            fix_command="sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop",
            category="Remote",
        ))
    else:
        findings.append(SecurityFinding(
            title="Remote Management (ARD)",
            severity="ok",
            detail="Apple Remote Desktop is disabled.",
            category="Remote",
        ))

    # --- Auto-login ---
    auto_login = _check_auto_login()
    if auto_login:
        findings.append(SecurityFinding(
            title="Auto-login enabled",
            severity="critical",
            detail="A user account is set to log in automatically. Anyone with physical access bypasses the login screen.",
            fix_command="sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
            category="Auth",
        ))
    else:
        findings.append(SecurityFinding(
            title="Auto-login",
            severity="ok",
            detail="Auto-login is disabled — login password is required.",
            category="Auth",
        ))

    # --- Remote Apple Events ---
    rae_on = _check_remote_apple_events()
    if rae_on:
        findings.append(SecurityFinding(
            title="Remote Apple Events enabled",
            severity="warning",
            detail="Remote Apple Events allow scripts on other machines to control this Mac via AppleScript.",
            fix_command="sudo systemsetup -setremoteappleevents off",
            category="Remote",
        ))

    return findings


# Weight map for CIS-style scoring
_WEIGHTS = {
    "SIP": 15,
    "Gatekeeper": 15,
    "FileVault": 20,
    "Firewall": 25,
    "Remote": 10,
    "Stealth": 5,
    "Auth": 10,
}

_SEVERITY_PENALTY = {
    "critical": 1.0,   # full deduction
    "warning": 0.5,    # half deduction
    "info": 0.0,
    "ok": 0.0,
}


def compute_security_score(findings: list[SecurityFinding]) -> dict:
    """Compute a CIS-style security score (0-100) from findings.

    Returns a dict with keys: score, max, percent, breakdown (per-category).
    """
    # Aggregate by category: worst severity wins
    category_severity: dict[str, str] = {}
    for f in findings:
        cat = f.category
        if not cat:
            continue
        # Stealth mode gets its own sub-weight
        if cat == "Firewall" and "stealth" in f.title.lower():
            cat = "Stealth"
        current = category_severity.get(cat, "ok")
        # worst severity ordering
        order = ["critical", "warning", "info", "ok"]
        if order.index(f.severity) < order.index(current):
            category_severity[cat] = f.severity

    breakdown = {}
    total_weight = sum(_WEIGHTS.values())
    earned = 0

    for cat, weight in _WEIGHTS.items():
        sev = category_severity.get(cat, "ok")
        penalty = _SEVERITY_PENALTY.get(sev, 0.0)
        cat_earned = weight * (1.0 - penalty)
        earned += cat_earned
        breakdown[cat] = {
            "weight": weight,
            "severity": sev,
            "earned": round(cat_earned, 1),
        }

    score = round((earned / total_weight) * 100)
    return {
        "score": score,
        "max": 100,
        "percent": score,
        "breakdown": breakdown,
    }
