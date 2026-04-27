"""Privacy permissions audit engine — TCC database, system_profiler, and stale app detection."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from typing import Optional

from mactools_core.runner import run


# TCC service → human-readable category
TCC_SERVICE_NAMES: dict[str, str] = {
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceSystemPolicySysAdminFiles": "System Admin Files",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServiceReminders": "Reminders",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceMediaLibrary": "Apple Music / Media Library",
    "kTCCServiceMotion": "Motion & Fitness",
    "kTCCServiceLocation": "Location",
    "kTCCServiceSpeechRecognition": "Speech Recognition",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Send Keystrokes",
    "kTCCServiceFocusStatus": "Focus Status",
    "kTCCServiceShareKit": "Share Sheet",
    "kTCCServiceUserAvailability": "User Availability (Focus)",
    "kTCCServiceGameCenterFriends": "Game Center Friends",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceUbiquity": "iCloud",
    "kTCCServiceLinkedIn": "LinkedIn",
    "kTCCServiceTwitter": "Twitter/X",
    "kTCCServiceFacebook": "Facebook",
    "kTCCServiceSinaWeibo": "Weibo",
    "kTCCServiceTencentWeibo": "Tencent Weibo",
    "kTCCServiceWebBrowserPublicKeyCredential": "Web Browser Passkey",
    "kTCCServiceWillow": "Home App",
    "kTCCServiceExposureNotification": "Exposure Notification",
    "kTCCServiceDeveloperTool": "Developer Tools",
}

# TCC auth_value mapping
AUTH_VALUES = {
    0: "denied",
    1: "unknown",
    2: "allowed",
    3: "limited",
}

# Sensitive categories by risk level
HIGH_RISK_SERVICES = {
    "kTCCServiceScreenCapture",
    "kTCCServiceAccessibility",
    "kTCCServiceSystemPolicyAllFiles",
    "kTCCServiceListenEvent",
    "kTCCServicePostEvent",
    "kTCCServiceSystemPolicySysAdminFiles",
    "kTCCServiceDeveloperTool",
}

MEDIUM_RISK_SERVICES = {
    "kTCCServiceCamera",
    "kTCCServiceMicrophone",
    "kTCCServiceAddressBook",
    "kTCCServiceCalendar",
    "kTCCServicePhotos",
    "kTCCServiceLocation",
    "kTCCServiceSpeechRecognition",
}


@dataclass
class PermissionEntry:
    service: str
    category: str
    client: str           # bundle ID or path
    auth_value: int
    auth_reason: str
    last_modified: Optional[int] = None
    app_exists: Optional[bool] = None
    risk_level: str = "low"  # "high", "medium", "low"

    @property
    def allowed(self) -> bool:
        return self.auth_value == 2

    @property
    def status(self) -> str:
        return AUTH_VALUES.get(self.auth_value, "unknown")

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "category": self.category,
            "client": self.client,
            "allowed": self.allowed,
            "status": self.status,
            "last_modified": self.last_modified,
            "app_exists": self.app_exists,
            "risk_level": self.risk_level,
        }


_TCC_USER_DB = os.path.expanduser(
    "~/Library/Application Support/com.apple.TCC/TCC.db"
)
_TCC_SYSTEM_DB = "/Library/Application Support/com.apple.TCC/TCC.db"


def _read_tcc_db(db_path: str) -> list[PermissionEntry]:
    """Attempt to read a TCC.db file directly via sqlite3."""
    entries: list[PermissionEntry] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        # Column layout varies by macOS version; probe for what's available
        cursor.execute("PRAGMA table_info(access)")
        cols = {row[1] for row in cursor.fetchall()}

        select_cols = ["service", "client", "auth_value"]
        if "auth_reason" in cols:
            select_cols.append("auth_reason")
        else:
            select_cols.append("0 AS auth_reason")
        if "last_modified" in cols:
            select_cols.append("last_modified")
        else:
            select_cols.append("0 AS last_modified")

        query = f"SELECT {', '.join(select_cols)} FROM access"
        cursor.execute(query)
        for row in cursor.fetchall():
            service, client, auth_value, auth_reason, last_modified = row
            category = TCC_SERVICE_NAMES.get(service, service)
            risk = "high" if service in HIGH_RISK_SERVICES else (
                "medium" if service in MEDIUM_RISK_SERVICES else "low"
            )
            entries.append(PermissionEntry(
                service=service,
                category=category,
                client=client or "",
                auth_value=int(auth_value or 0),
                auth_reason=str(auth_reason or ""),
                last_modified=int(last_modified or 0),
                risk_level=risk,
            ))
        conn.close()
    except (sqlite3.Error, OSError, PermissionError):
        pass
    return entries


def _fallback_system_profiler() -> list[PermissionEntry]:
    """Fallback: use system_profiler SPPrivacyDataType for TCC snapshot."""
    from mactools_core.runner import run_plist
    entries: list[PermissionEntry] = []
    data = run_plist(["system_profiler", "SPPrivacyDataType", "-xml"])
    if not data or not isinstance(data, list):
        return entries
    items = data[0].get("_items", []) if data else []
    for item in items:
        service_name = item.get("_name", "")
        category = item.get("spprivacy_category", service_name)
        for app_entry in item.get("spprivacy_apps", []):
            client = app_entry.get("_name", "")
            granted = app_entry.get("spprivacy_access", "No") == "Yes"
            auth_value = 2 if granted else 0
            entries.append(PermissionEntry(
                service=service_name,
                category=category,
                client=client,
                auth_value=auth_value,
                auth_reason="system_profiler",
                risk_level="low",
            ))
    return entries


def audit_permissions() -> list[PermissionEntry]:
    """Read TCC database state; falls back to system_profiler if TCC.db is not accessible."""
    entries: list[PermissionEntry] = []

    # Try user TCC database first
    entries.extend(_read_tcc_db(_TCC_USER_DB))

    # Try system TCC database (may need Full Disk Access)
    system_entries = _read_tcc_db(_TCC_SYSTEM_DB)
    seen = {(e.service, e.client) for e in entries}
    for e in system_entries:
        if (e.service, e.client) not in seen:
            entries.append(e)
            seen.add((e.service, e.client))

    # If no entries at all, fall back to system_profiler
    if not entries:
        entries = _fallback_system_profiler()

    # Resolve app_exists for each entry
    for e in entries:
        e.app_exists = _resolve_app_exists(e.client)

    return entries


def categorize_permissions(
    entries: list[PermissionEntry],
) -> dict[str, list[PermissionEntry]]:
    """Group permission entries by human-readable category."""
    grouped: dict[str, list[PermissionEntry]] = {}
    for e in entries:
        grouped.setdefault(e.category, []).append(e)
    return dict(sorted(grouped.items()))


def identify_stale_permissions(
    entries: list[PermissionEntry],
) -> list[PermissionEntry]:
    """Return allowed permissions whose app no longer exists at the expected path."""
    stale = []
    for e in entries:
        if e.allowed and e.app_exists is False:
            stale.append(e)
    return stale


def _resolve_app_exists(client: str) -> Optional[bool]:
    """Check whether the app / binary referenced by client still exists."""
    if not client:
        return None

    # Bundle IDs: try to resolve via mdfind / lsregister
    if "." in client and not client.startswith("/"):
        # It looks like a bundle ID — check via mdfind
        r = run([
            "mdfind",
            f"kMDItemCFBundleIdentifier == '{client}'",
        ])
        if r.ok and r.stdout.strip():
            # At least one path found
            for path in r.stdout.strip().splitlines():
                if os.path.exists(path.strip()):
                    return True
            return False
        # mdfind found nothing — assume unknown
        return None

    # Absolute path — check directly
    if client.startswith("/"):
        return os.path.exists(client)

    return None
