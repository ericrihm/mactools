"""Tests for mactools_macprivacy.engine — TCC database audit, categorization, and stale permission detection."""

from __future__ import annotations

from unittest.mock import patch, MagicMock, call

import pytest

from mactools_core.runner import RunResult


def _ok(stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(stdout=stdout, stderr=stderr, returncode=0, ok=True)


def _fail(stderr: str = "error") -> RunResult:
    return RunResult(stdout="", stderr=stderr, returncode=1, ok=False)


# ---------------------------------------------------------------------------
# Helpers to build fake sqlite3 responses
# ---------------------------------------------------------------------------

def _make_cursor(pragma_rows: list[tuple], access_rows: list[tuple]) -> MagicMock:
    """Return a mock cursor that yields pragma_rows on first fetchall, access_rows on second."""
    cursor = MagicMock()
    cursor.fetchall.side_effect = [pragma_rows, access_rows]
    return cursor


def _pragma_all_cols() -> list[tuple]:
    """PRAGMA table_info rows for a full-featured TCC schema."""
    # (cid, name, type, notnull, dflt_value, pk)
    return [
        (0, "service", "TEXT", 0, None, 0),
        (1, "client", "TEXT", 0, None, 0),
        (2, "auth_value", "INTEGER", 0, None, 0),
        (3, "auth_reason", "INTEGER", 0, None, 0),
        (4, "last_modified", "INTEGER", 0, None, 0),
    ]


def _pragma_minimal_cols() -> list[tuple]:
    """PRAGMA rows without auth_reason or last_modified (older macOS schema)."""
    return [
        (0, "service", "TEXT", 0, None, 0),
        (1, "client", "TEXT", 0, None, 0),
        (2, "auth_value", "INTEGER", 0, None, 0),
    ]


# ===========================================================================
# PermissionEntry dataclass
# ===========================================================================

class TestPermissionEntry:
    def setup_method(self):
        from mactools_macprivacy.engine import PermissionEntry
        self.PermissionEntry = PermissionEntry

    def test_allowed_true_when_auth_value_is_2(self):
        e = self.PermissionEntry(
            service="kTCCServiceCamera", category="Camera",
            client="com.example.app", auth_value=2, auth_reason="4",
        )
        assert e.allowed is True

    def test_allowed_false_for_denied(self):
        e = self.PermissionEntry(
            service="kTCCServiceCamera", category="Camera",
            client="com.example.app", auth_value=0, auth_reason="0",
        )
        assert e.allowed is False

    def test_status_maps_auth_values(self):
        from mactools_macprivacy.engine import AUTH_VALUES
        for value, label in AUTH_VALUES.items():
            e = self.PermissionEntry(
                service="s", category="c", client="x",
                auth_value=value, auth_reason="",
            )
            assert e.status == label

    def test_status_unknown_for_unrecognised_value(self):
        e = self.PermissionEntry(
            service="s", category="c", client="x",
            auth_value=99, auth_reason="",
        )
        assert e.status == "unknown"

    def test_as_dict_contains_expected_keys(self):
        e = self.PermissionEntry(
            service="kTCCServiceMicrophone", category="Microphone",
            client="com.zoom.xos", auth_value=2, auth_reason="4",
            last_modified=1700000000, app_exists=True, risk_level="medium",
        )
        d = e.as_dict()
        assert d["service"] == "kTCCServiceMicrophone"
        assert d["category"] == "Microphone"
        assert d["client"] == "com.zoom.xos"
        assert d["allowed"] is True
        assert d["status"] == "allowed"
        assert d["last_modified"] == 1700000000
        assert d["app_exists"] is True
        assert d["risk_level"] == "medium"

    def test_risk_level_defaults_to_low(self):
        e = self.PermissionEntry(
            service="kTCCServicePhotos", category="Photos",
            client="com.example.app", auth_value=2, auth_reason="",
        )
        assert e.risk_level == "low"


# ===========================================================================
# _read_tcc_db
# ===========================================================================

class TestReadTccDb:
    def setup_method(self):
        from mactools_macprivacy.engine import _read_tcc_db
        self._read_tcc_db = _read_tcc_db

    def _make_conn(self, cursor: MagicMock) -> MagicMock:
        conn = MagicMock()
        conn.cursor.return_value = cursor
        return conn

    def test_returns_entries_from_full_schema(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceCamera", "com.example.zoom", 2, 4, 1700000000),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert len(entries) == 1
        e = entries[0]
        assert e.service == "kTCCServiceCamera"
        assert e.client == "com.example.zoom"
        assert e.auth_value == 2
        assert e.category == "Camera"

    def test_assigns_correct_risk_level_high(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceScreenCapture", "com.evil.app", 2, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].risk_level == "high"

    def test_assigns_correct_risk_level_medium(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceMicrophone", "com.example.app", 2, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].risk_level == "medium"

    def test_assigns_correct_risk_level_low(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceGameCenterFriends", "com.apple.game", 2, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].risk_level == "low"

    def test_handles_minimal_schema_without_auth_reason_or_last_modified(self):
        """Older macOS TCC schemas omit auth_reason and last_modified columns."""
        cursor = _make_cursor(
            pragma_rows=_pragma_minimal_cols(),
            access_rows=[
                ("kTCCServiceCalendar", "com.apple.ical", 2, 0, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert len(entries) == 1
        assert entries[0].auth_reason == "0"
        assert entries[0].last_modified == 0

    def test_returns_empty_list_when_db_inaccessible(self):
        with patch("sqlite3.connect", side_effect=Exception("permission denied")):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries == []

    def test_returns_empty_list_for_empty_access_table(self):
        cursor = _make_cursor(pragma_rows=_pragma_all_cols(), access_rows=[])
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries == []

    def test_unknown_service_uses_raw_service_name_as_category(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceUnknownFuture", "com.example.app", 2, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].category == "kTCCServiceUnknownFuture"

    def test_null_client_becomes_empty_string(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceCamera", None, 2, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].client == ""

    def test_null_auth_value_defaults_to_zero(self):
        cursor = _make_cursor(
            pragma_rows=_pragma_all_cols(),
            access_rows=[
                ("kTCCServiceCamera", "com.app", None, 4, 0),
            ],
        )
        conn = self._make_conn(cursor)
        with patch("sqlite3.connect", return_value=conn):
            entries = self._read_tcc_db("/fake/TCC.db")
        assert entries[0].auth_value == 0


# ===========================================================================
# _resolve_app_exists
# ===========================================================================

class TestResolveAppExists:
    def setup_method(self):
        from mactools_macprivacy.engine import _resolve_app_exists
        self._resolve_app_exists = _resolve_app_exists

    def test_returns_none_for_empty_client(self):
        result = self._resolve_app_exists("")
        assert result is None

    def test_absolute_path_exists(self):
        with patch("os.path.exists", return_value=True):
            result = self._resolve_app_exists("/Applications/Zoom.app")
        assert result is True

    def test_absolute_path_missing(self):
        with patch("os.path.exists", return_value=False):
            result = self._resolve_app_exists("/Applications/GoneApp.app")
        assert result is False

    def test_bundle_id_found_via_mdfind(self):
        with patch("mactools_macprivacy.engine.run", return_value=_ok("/Applications/Zoom.app\n")), \
             patch("os.path.exists", return_value=True):
            result = self._resolve_app_exists("us.zoom.xos")
        assert result is True

    def test_bundle_id_mdfind_returns_path_that_does_not_exist(self):
        with patch("mactools_macprivacy.engine.run", return_value=_ok("/Applications/Deleted.app\n")), \
             patch("os.path.exists", return_value=False):
            result = self._resolve_app_exists("com.deleted.app")
        assert result is False

    def test_bundle_id_mdfind_finds_nothing_returns_none(self):
        with patch("mactools_macprivacy.engine.run", return_value=_ok("")):
            result = self._resolve_app_exists("com.notfound.app")
        assert result is None

    def test_bundle_id_mdfind_fails_returns_none(self):
        with patch("mactools_macprivacy.engine.run", return_value=_fail("mdfind error")):
            result = self._resolve_app_exists("com.example.app")
        assert result is None

    def test_plain_name_without_dot_or_slash_returns_none(self):
        result = self._resolve_app_exists("SomeProcessName")
        assert result is None


# ===========================================================================
# audit_permissions
# ===========================================================================

class TestAuditPermissions:
    def setup_method(self):
        from mactools_macprivacy.engine import audit_permissions
        self.audit_permissions = audit_permissions

    def _entry(self, service="kTCCServiceCamera", client="com.example.app",
               auth_value=2, auth_reason="4", last_modified=0,
               category="Camera", risk_level="medium"):
        from mactools_macprivacy.engine import PermissionEntry
        return PermissionEntry(
            service=service, category=category, client=client,
            auth_value=auth_value, auth_reason=auth_reason,
            last_modified=last_modified, risk_level=risk_level,
        )

    def test_returns_list_of_permission_entries(self):
        entry = self._entry()
        with patch("mactools_macprivacy.engine._read_tcc_db", return_value=[entry]), \
             patch("mactools_macprivacy.engine._resolve_app_exists", return_value=True):
            result = self.audit_permissions()
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_deduplicates_user_and_system_db_entries(self):
        """Same (service, client) in both DBs must appear only once."""
        shared = self._entry(service="kTCCServiceCamera", client="com.example.app")
        unique_sys = self._entry(service="kTCCServiceMicrophone", client="com.other.app",
                                 category="Microphone")

        def fake_read(db_path):
            if "Library/Application" in db_path and not db_path.startswith("/Library"):
                return [shared]
            return [shared, unique_sys]  # system DB has both

        with patch("mactools_macprivacy.engine._read_tcc_db", side_effect=fake_read), \
             patch("mactools_macprivacy.engine._resolve_app_exists", return_value=True):
            result = self.audit_permissions()

        pairs = [(e.service, e.client) for e in result]
        assert pairs.count(("kTCCServiceCamera", "com.example.app")) == 1
        assert any(e.service == "kTCCServiceMicrophone" for e in result)

    def test_falls_back_to_system_profiler_when_both_dbs_empty(self):
        from mactools_macprivacy.engine import PermissionEntry
        sp_entry = PermissionEntry(
            service="Camera", category="Camera",
            client="Zoom", auth_value=2, auth_reason="system_profiler",
        )
        with patch("mactools_macprivacy.engine._read_tcc_db", return_value=[]), \
             patch("mactools_macprivacy.engine._fallback_system_profiler", return_value=[sp_entry]), \
             patch("mactools_macprivacy.engine._resolve_app_exists", return_value=None):
            result = self.audit_permissions()
        assert len(result) == 1
        assert result[0].auth_reason == "system_profiler"

    def test_app_exists_is_resolved_for_every_entry(self):
        entries = [
            self._entry(client="com.bundle.one"),
            self._entry(client="/Applications/Two.app", service="kTCCServiceMicrophone",
                        category="Microphone"),
        ]
        with patch("mactools_macprivacy.engine._read_tcc_db", side_effect=[entries, []]), \
             patch("mactools_macprivacy.engine._resolve_app_exists", return_value=True) as mock_resolve:
            result = self.audit_permissions()
        assert mock_resolve.call_count == len(result)
        for e in result:
            assert e.app_exists is True

    def test_system_db_entries_added_when_user_db_empty(self):
        sys_entry = self._entry(service="kTCCServiceAccessibility",
                                client="com.sys.app", category="Accessibility",
                                risk_level="high")

        def fake_read(db_path):
            if db_path.startswith("/Library"):
                return [sys_entry]
            return []

        with patch("mactools_macprivacy.engine._read_tcc_db", side_effect=fake_read), \
             patch("mactools_macprivacy.engine._resolve_app_exists", return_value=True):
            result = self.audit_permissions()
        assert any(e.service == "kTCCServiceAccessibility" for e in result)


# ===========================================================================
# categorize_permissions
# ===========================================================================

class TestCategorizePermissions:
    def setup_method(self):
        from mactools_macprivacy.engine import categorize_permissions, PermissionEntry
        self.categorize_permissions = categorize_permissions
        self.PermissionEntry = PermissionEntry

    def _entry(self, category: str, client: str = "com.example.app",
               service: str = "kTCCServiceCamera") -> "PermissionEntry":
        return self.PermissionEntry(
            service=service, category=category, client=client,
            auth_value=2, auth_reason="4",
        )

    def test_returns_empty_dict_for_empty_list(self):
        result = self.categorize_permissions([])
        assert result == {}

    def test_groups_entries_by_category(self):
        entries = [
            self._entry("Camera", "com.zoom.xos"),
            self._entry("Camera", "com.google.meet"),
            self._entry("Microphone", "com.zoom.xos", "kTCCServiceMicrophone"),
        ]
        result = self.categorize_permissions(entries)
        assert "Camera" in result
        assert "Microphone" in result
        assert len(result["Camera"]) == 2
        assert len(result["Microphone"]) == 1

    def test_result_is_sorted_alphabetically(self):
        entries = [
            self._entry("Screen Recording"),
            self._entry("Accessibility"),
            self._entry("Camera"),
        ]
        result = self.categorize_permissions(entries)
        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_single_entry_single_category(self):
        entries = [self._entry("Full Disk Access")]
        result = self.categorize_permissions(entries)
        assert list(result.keys()) == ["Full Disk Access"]
        assert len(result["Full Disk Access"]) == 1

    def test_preserves_entry_objects_in_groups(self):
        entry = self._entry("Calendar")
        result = self.categorize_permissions([entry])
        assert result["Calendar"][0] is entry


# ===========================================================================
# identify_stale_permissions
# ===========================================================================

class TestIdentifyStalePermissions:
    def setup_method(self):
        from mactools_macprivacy.engine import identify_stale_permissions, PermissionEntry
        self.identify_stale_permissions = identify_stale_permissions
        self.PermissionEntry = PermissionEntry

    def _entry(self, auth_value: int, app_exists) -> "PermissionEntry":
        return self.PermissionEntry(
            service="kTCCServiceCamera", category="Camera",
            client="com.example.app", auth_value=auth_value,
            auth_reason="4", app_exists=app_exists,
        )

    def test_returns_empty_for_no_entries(self):
        assert self.identify_stale_permissions([]) == []

    def test_allowed_and_missing_app_is_stale(self):
        stale = self._entry(auth_value=2, app_exists=False)
        result = self.identify_stale_permissions([stale])
        assert stale in result

    def test_allowed_and_existing_app_is_not_stale(self):
        live = self._entry(auth_value=2, app_exists=True)
        result = self.identify_stale_permissions([live])
        assert result == []

    def test_denied_and_missing_app_is_not_stale(self):
        denied_missing = self._entry(auth_value=0, app_exists=False)
        result = self.identify_stale_permissions([denied_missing])
        assert result == []

    def test_allowed_and_unknown_existence_is_not_stale(self):
        unknown = self._entry(auth_value=2, app_exists=None)
        result = self.identify_stale_permissions([unknown])
        assert result == []

    def test_mixed_entries_only_stale_returned(self):
        from mactools_macprivacy.engine import PermissionEntry

        stale = PermissionEntry(
            service="kTCCServiceCamera", category="Camera",
            client="com.gone.app", auth_value=2, auth_reason="",
            app_exists=False,
        )
        live = PermissionEntry(
            service="kTCCServiceMicrophone", category="Microphone",
            client="com.alive.app", auth_value=2, auth_reason="",
            app_exists=True,
        )
        denied = PermissionEntry(
            service="kTCCServiceCalendar", category="Calendar",
            client="com.denied.app", auth_value=0, auth_reason="",
            app_exists=False,
        )
        unknown_exists = PermissionEntry(
            service="kTCCServicePhotos", category="Photos",
            client="com.unknown.app", auth_value=2, auth_reason="",
            app_exists=None,
        )

        result = self.identify_stale_permissions([stale, live, denied, unknown_exists])
        assert result == [stale]


# ===========================================================================
# _fallback_system_profiler
# ===========================================================================

class TestFallbackSystemProfiler:
    def setup_method(self):
        from mactools_macprivacy.engine import _fallback_system_profiler
        self._fallback_system_profiler = _fallback_system_profiler

    def test_returns_empty_for_none_data(self):
        with patch("mactools_core.runner.run_plist", return_value=None):
            result = self._fallback_system_profiler()
        assert result == []

    def test_returns_empty_for_empty_list(self):
        with patch("mactools_core.runner.run_plist", return_value=[]):
            result = self._fallback_system_profiler()
        assert result == []

    def test_parses_granted_permission(self):
        data = [{
            "_items": [{
                "_name": "kTCCServiceCamera",
                "spprivacy_category": "Camera",
                "spprivacy_apps": [
                    {"_name": "Zoom", "spprivacy_access": "Yes"},
                ],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert len(result) == 1
        assert result[0].auth_value == 2
        assert result[0].client == "Zoom"
        assert result[0].category == "Camera"

    def test_parses_denied_permission(self):
        data = [{
            "_items": [{
                "_name": "kTCCServiceMicrophone",
                "spprivacy_category": "Microphone",
                "spprivacy_apps": [
                    {"_name": "Discord", "spprivacy_access": "No"},
                ],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert result[0].auth_value == 0
        assert result[0].allowed is False

    def test_multiple_apps_per_service(self):
        data = [{
            "_items": [{
                "_name": "kTCCServiceCamera",
                "spprivacy_category": "Camera",
                "spprivacy_apps": [
                    {"_name": "Zoom", "spprivacy_access": "Yes"},
                    {"_name": "Teams", "spprivacy_access": "Yes"},
                    {"_name": "Skype", "spprivacy_access": "No"},
                ],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert len(result) == 3
        clients = {e.client for e in result}
        assert clients == {"Zoom", "Teams", "Skype"}

    def test_uses_name_as_category_when_spprivacy_category_missing(self):
        data = [{
            "_items": [{
                "_name": "Camera",
                "spprivacy_apps": [
                    {"_name": "Zoom", "spprivacy_access": "Yes"},
                ],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert result[0].category == "Camera"
        assert result[0].service == "Camera"

    def test_skips_items_with_no_apps(self):
        data = [{
            "_items": [{
                "_name": "kTCCServiceCamera",
                "spprivacy_category": "Camera",
                "spprivacy_apps": [],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert result == []

    def test_auth_reason_set_to_system_profiler(self):
        data = [{
            "_items": [{
                "_name": "kTCCServiceCamera",
                "spprivacy_category": "Camera",
                "spprivacy_apps": [{"_name": "App", "spprivacy_access": "Yes"}],
            }]
        }]
        with patch("mactools_core.runner.run_plist", return_value=data):
            result = self._fallback_system_profiler()
        assert result[0].auth_reason == "system_profiler"


# ===========================================================================
# Integration: TCC_SERVICE_NAMES and constant correctness
# ===========================================================================

class TestConstants:
    def test_high_risk_services_are_subset_of_tcc_service_names(self):
        from mactools_macprivacy.engine import HIGH_RISK_SERVICES, TCC_SERVICE_NAMES
        for svc in HIGH_RISK_SERVICES:
            assert svc in TCC_SERVICE_NAMES, f"{svc} not in TCC_SERVICE_NAMES"

    def test_medium_risk_services_are_subset_of_tcc_service_names(self):
        from mactools_macprivacy.engine import MEDIUM_RISK_SERVICES, TCC_SERVICE_NAMES
        for svc in MEDIUM_RISK_SERVICES:
            assert svc in TCC_SERVICE_NAMES, f"{svc} not in TCC_SERVICE_NAMES"

    def test_high_and_medium_risk_sets_are_disjoint(self):
        from mactools_macprivacy.engine import HIGH_RISK_SERVICES, MEDIUM_RISK_SERVICES
        overlap = HIGH_RISK_SERVICES & MEDIUM_RISK_SERVICES
        assert not overlap, f"Services in both risk sets: {overlap}"

    def test_auth_values_covers_denied_allowed_and_limited(self):
        from mactools_macprivacy.engine import AUTH_VALUES
        assert AUTH_VALUES[0] == "denied"
        assert AUTH_VALUES[2] == "allowed"
        assert AUTH_VALUES[3] == "limited"
