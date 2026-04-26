"""Shared test fixtures for mactools test suite."""

from __future__ import annotations

import plistlib
from unittest.mock import MagicMock

import pytest

from mactools_core.runner import RunResult


# ---------------------------------------------------------------------------
# RunResult factories
# ---------------------------------------------------------------------------

def make_ok(stdout: str = "", stderr: str = "") -> RunResult:
    """Return a successful RunResult."""
    return RunResult(stdout=stdout, stderr=stderr, returncode=0, ok=True)


def make_fail(stderr: str = "error", returncode: int = 1) -> RunResult:
    """Return a failed RunResult."""
    return RunResult(stdout="", stderr=stderr, returncode=returncode, ok=False)


@pytest.fixture
def ok_result():
    return make_ok


@pytest.fixture
def fail_result():
    return make_fail


# ---------------------------------------------------------------------------
# Sample plist bytes — minimal APFS container list
# ---------------------------------------------------------------------------

SAMPLE_APFS_PLIST_DATA = {
    "Containers": [
        {
            "ContainerReference": "disk1",
            "CapacityCeiling": 500_000_000_000,
            "CapacityFree": 200_000_000_000,
            "Volumes": [
                {
                    "Name": "Macintosh HD",
                    "DeviceIdentifier": "disk1s1",
                    "Roles": ["System"],
                    "CapacityInUse": 50_000_000_000,
                    "Encryption": False,
                    "Mounted": True,
                    "MountPoint": "/",
                },
                {
                    "Name": "Data",
                    "DeviceIdentifier": "disk1s2",
                    "Roles": ["Data"],
                    "CapacityInUse": 100_000_000_000,
                    "Encryption": True,
                    "Mounted": True,
                    "MountPoint": "/System/Volumes/Data",
                },
            ],
        }
    ]
}


@pytest.fixture
def apfs_plist_bytes():
    return plistlib.dumps(SAMPLE_APFS_PLIST_DATA)


# ---------------------------------------------------------------------------
# Sample launchctl list output
# ---------------------------------------------------------------------------

SAMPLE_LAUNCHCTL_LIST = """\
PID\tStatus\tLabel
12345\t0\tcom.apple.Finder
-\t0\tcom.google.keystone.agent
678\t0\tcom.apple.Safari
-\t78\tcom.example.crasher
"""

@pytest.fixture
def launchctl_list_output():
    return SAMPLE_LAUNCHCTL_LIST


# ---------------------------------------------------------------------------
# Sample log output (compact style)
# ---------------------------------------------------------------------------

SAMPLE_LOG_LINE = (
    "2024-01-15 10:23:45.123456+0000  "
    "0xabc123  error  0xdef456  "
    "42  0  kernel: (com.apple.driver) [MySubsystem] [MyCategory] Something went wrong"
)

SAMPLE_LOG_OUTPUT = f"""\
Timestamp                       Thread     Type        Activity             PID    TTL
{SAMPLE_LOG_LINE}
"""

@pytest.fixture
def sample_log_line():
    return SAMPLE_LOG_LINE


@pytest.fixture
def sample_log_output():
    return SAMPLE_LOG_OUTPUT


# ---------------------------------------------------------------------------
# Sample pmset output
# ---------------------------------------------------------------------------

SAMPLE_PMSET_CUSTOM = """\
Battery Power:
 sleep                5
 displaysleep         3
 disksleep            10
 womp                 0
 powernap             1
AC Power:
 sleep                0
 displaysleep         10
 disksleep            10
 womp                 1
 powernap             1
"""

SAMPLE_PMSET_ASSERTIONS = """\
Assertion status system-wide:
 BackgroundTask                 1
 PreventUserIdleSystemSleep     1
pid 999(mds_stores): [0x0001234] PreventUserIdleSystemSleep named: "Spotlight indexing"
pid 42(coreaudiod): [0x0005678] PreventUserIdleDisplaySleep named: "Audio is playing"
"""

SAMPLE_PMSET_THERM = """\
CPU Speed Limit = 75
GPU Speed Limit = 100
"""

@pytest.fixture
def pmset_custom_output():
    return SAMPLE_PMSET_CUSTOM


@pytest.fixture
def pmset_assertions_output():
    return SAMPLE_PMSET_ASSERTIONS


@pytest.fixture
def pmset_therm_output():
    return SAMPLE_PMSET_THERM


# ---------------------------------------------------------------------------
# Sample networksetup / scutil output
# ---------------------------------------------------------------------------

SAMPLE_HARDWARE_PORTS = """\
Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Ethernet
Device: en1
Ethernet Address: 11:22:33:44:55:66

Hardware Port: Thunderbolt 1
Device: en2
Ethernet Address: 00:00:00:00:00:01
"""

SAMPLE_SCUTIL_DNS = """\
DNS configuration

resolver #1
  domain   : local
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 5 (en0)
  search domain[0] : example.com

resolver #2
  nameserver[0] : 1.1.1.1
"""

@pytest.fixture
def hardware_ports_output():
    return SAMPLE_HARDWARE_PORTS


@pytest.fixture
def scutil_dns_output():
    return SAMPLE_SCUTIL_DNS


# ---------------------------------------------------------------------------
# Sample mdutil / mdfind output
# ---------------------------------------------------------------------------

SAMPLE_MDUTIL_SA = """\
/:
    Indexing enabled.
/Volumes/ExternalDrive:
    Indexing disabled.
"""

@pytest.fixture
def mdutil_sa_output():
    return SAMPLE_MDUTIL_SA


# ---------------------------------------------------------------------------
# Sample shortcuts list output
# ---------------------------------------------------------------------------

SAMPLE_SHORTCUTS_LIST = """\
Morning Routine
Compress Images
Send Summary
"""

@pytest.fixture
def shortcuts_list_output():
    return SAMPLE_SHORTCUTS_LIST
