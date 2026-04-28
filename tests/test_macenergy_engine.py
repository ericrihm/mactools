"""Tests for mactools_macenergy.engine — energy issue detection and audit."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mactools_core.power import PowerSettings, ScheduledEvent, SleepPreventer, ThermalState
from mactools_macenergy.engine import (
    EnergyAudit,
    EnergyIssue,
    audit_energy,
    identify_energy_issues,
)


# ---------------------------------------------------------------------------
# Helpers / fixture factories
# ---------------------------------------------------------------------------

def _settings(
    sleep_timer: int = 15,
    display_sleep: int = 5,
    disk_sleep: int = 10,
    wake_on_lan: bool = False,
    power_nap: bool = False,
) -> PowerSettings:
    return PowerSettings(
        sleep_timer=sleep_timer,
        display_sleep=display_sleep,
        disk_sleep=disk_sleep,
        wake_on_lan=wake_on_lan,
        power_nap=power_nap,
    )


def _thermal(level: str = "nominal", cpu_speed_limit: int = 100, details: str = "") -> ThermalState:
    return ThermalState(level=level, cpu_speed_limit=cpu_speed_limit, details=details)


def _preventer(
    name: str = "myapp",
    pid: int = 1234,
    assertion_type: str = "PreventUserIdleSystemSleep",
    detail: str = "Doing work",
) -> SleepPreventer:
    return SleepPreventer(name=name, pid=pid, assertion_type=assertion_type, detail=detail)


# ===========================================================================
# identify_energy_issues
# ===========================================================================

class TestIdentifyEnergyIssues:
    """identify_energy_issues(settings, preventers, thermal) -> list[EnergyIssue]"""

    def test_nominal_thermal_no_issues_returns_ok(self):
        issues = identify_energy_issues(_settings(), [], _thermal("nominal", 100))
        assert len(issues) == 1
        assert issues[0].severity == "info"
        assert issues[0].category == "Overall"
        assert "healthy" in issues[0].title.lower()

    def test_critical_thermal_returns_critical_issue(self):
        issues = identify_energy_issues(_settings(), [], _thermal("critical", 40))
        thermal_issues = [i for i in issues if i.category == "Thermal"]
        assert len(thermal_issues) == 1
        assert thermal_issues[0].severity == "critical"
        assert "40%" in thermal_issues[0].detail

    def test_throttled_thermal_returns_warning(self):
        issues = identify_energy_issues(_settings(), [], _thermal("throttled", 75))
        thermal_issues = [i for i in issues if i.category == "Thermal"]
        assert len(thermal_issues) == 1
        assert thermal_issues[0].severity == "warning"
        assert "75%" in thermal_issues[0].title

    def test_sleep_disabled_returns_info(self):
        issues = identify_energy_issues(_settings(sleep_timer=0), [], _thermal())
        power_issues = [i for i in issues if i.category == "Power" and "sleep is disabled" in i.title.lower()]
        assert len(power_issues) == 1
        assert power_issues[0].severity == "info"

    def test_very_long_sleep_timer_returns_info(self):
        issues = identify_energy_issues(_settings(sleep_timer=120), [], _thermal())
        power_issues = [i for i in issues if i.category == "Power" and "120" in i.title]
        assert len(power_issues) == 1
        assert power_issues[0].severity == "info"

    def test_sleep_timer_at_boundary_60_does_not_trigger(self):
        """Sleep timer of exactly 60 minutes should not trigger the >60 warning."""
        issues = identify_energy_issues(_settings(sleep_timer=60), [], _thermal())
        assert not any("sleep timer set to 60" in i.title.lower() for i in issues)

    def test_display_sleep_disabled_returns_warning(self):
        issues = identify_energy_issues(_settings(display_sleep=0), [], _thermal())
        display_issues = [i for i in issues if "Display sleep is disabled" in i.title]
        assert len(display_issues) == 1
        assert display_issues[0].severity == "warning"

    def test_wake_on_lan_enabled_returns_info(self):
        issues = identify_energy_issues(_settings(wake_on_lan=True), [], _thermal())
        wol_issues = [i for i in issues if "Wake-on-LAN" in i.title]
        assert len(wol_issues) == 1
        assert wol_issues[0].severity == "info"

    def test_wake_on_lan_disabled_no_issue(self):
        issues = identify_energy_issues(_settings(wake_on_lan=False), [], _thermal())
        assert not any("Wake-on-LAN" in i.title for i in issues)

    def test_power_nap_enabled_returns_info(self):
        issues = identify_energy_issues(_settings(power_nap=True), [], _thermal())
        nap_issues = [i for i in issues if "Power Nap" in i.title]
        assert len(nap_issues) == 1
        assert nap_issues[0].severity == "info"

    def test_power_nap_disabled_no_issue(self):
        issues = identify_energy_issues(_settings(power_nap=False), [], _thermal())
        assert not any("Power Nap" in i.title for i in issues)

    def test_more_than_three_high_impact_preventers_triggers_warning(self):
        preventers = [
            _preventer(name=f"app{i}", pid=i, assertion_type="PreventUserIdleSystemSleep")
            for i in range(4)
        ]
        issues = identify_energy_issues(_settings(), preventers, _thermal())
        wake_issues = [i for i in issues if i.category == "Wake" and "preventing system sleep" in i.title]
        assert len(wake_issues) == 1
        assert wake_issues[0].severity == "warning"
        assert "4" in wake_issues[0].title

    def test_three_or_fewer_high_impact_preventers_no_count_warning(self):
        preventers = [
            _preventer(name=f"app{i}", pid=i, assertion_type="PreventSystemSleep")
            for i in range(3)
        ]
        issues = identify_energy_issues(_settings(), preventers, _thermal())
        assert not any("preventing system sleep" in i.title for i in issues)

    def test_known_unnecessary_waker_coreaudiod_flagged(self):
        p = _preventer(name="coreaudiod", pid=55, assertion_type="PreventUserIdleSystemSleep", detail="Audio idle")
        issues = identify_energy_issues(_settings(), [p], _thermal())
        audio_issues = [i for i in issues if "coreaudiod" in i.title]
        assert len(audio_issues) == 1
        assert audio_issues[0].severity == "info"
        assert "55" in audio_issues[0].title

    def test_known_unnecessary_waker_bluetoothd_flagged(self):
        p = _preventer(name="bluetoothd", pid=99, assertion_type="PreventSystemSleep", detail="BT active")
        issues = identify_energy_issues(_settings(), [p], _thermal())
        bt_issues = [i for i in issues if "bluetoothd" in i.title]
        assert len(bt_issues) == 1
        assert "bluetoothd" in bt_issues[0].title

    def test_known_waker_with_low_impact_assertion_not_flagged(self):
        """A known unnecessary waker is only flagged when using a HIGH_IMPACT assertion type."""
        p = _preventer(name="coreaudiod", pid=55, assertion_type="PreventUserIdleDisplaySleep")
        issues = identify_energy_issues(_settings(), [p], _thermal())
        assert not any("coreaudiod" in i.title for i in issues)

    def test_unknown_process_preventer_not_individually_flagged(self):
        p = _preventer(name="unknownapp", pid=777, assertion_type="PreventUserIdleSystemSleep")
        issues = identify_energy_issues(_settings(), [p], _thermal())
        # Unknown process should not get an individual per-process issue
        assert not any("unknownapp" in i.title for i in issues)

    def test_issue_to_dict_has_all_required_keys(self):
        issues = identify_energy_issues(_settings(wake_on_lan=True), [], _thermal())
        for issue in issues:
            d = issue.to_dict()
            assert "severity" in d
            assert "category" in d
            assert "title" in d
            assert "detail" in d

    def test_all_severities_are_valid(self):
        issues = identify_energy_issues(
            _settings(sleep_timer=0, display_sleep=0, wake_on_lan=True, power_nap=True),
            [_preventer(name="coreaudiod", assertion_type="PreventSystemSleep")],
            _thermal("critical", 30),
        )
        valid_severities = {"critical", "warning", "info", "ok"}
        for issue in issues:
            assert issue.severity in valid_severities, f"Invalid severity: {issue.severity}"


# ===========================================================================
# EnergyAudit.to_dict
# ===========================================================================

class TestEnergyAuditToDict:
    """EnergyAudit.to_dict() serialises all fields correctly."""

    def _audit(
        self,
        settings: PowerSettings | None = None,
        preventers: list[SleepPreventer] | None = None,
        thermal: ThermalState | None = None,
        schedule: list[ScheduledEvent] | None = None,
    ) -> EnergyAudit:
        s = settings or _settings()
        t = thermal or _thermal()
        issues = identify_energy_issues(s, preventers or [], t)
        return EnergyAudit(
            power_settings=s,
            preventers=preventers or [],
            thermal=t,
            schedule=schedule or [],
            issues=issues,
        )

    def test_to_dict_contains_required_top_level_keys(self):
        d = self._audit().to_dict()
        for key in ("power_settings", "sleep_preventers", "thermal", "schedule", "issues"):
            assert key in d, f"Missing key: {key}"

    def test_power_settings_fields_serialised(self):
        s = _settings(sleep_timer=20, display_sleep=10, wake_on_lan=True)
        d = self._audit(settings=s).to_dict()
        ps = d["power_settings"]
        assert ps["sleep_timer"] == 20
        assert ps["display_sleep"] == 10
        assert ps["wake_on_lan"] is True

    def test_thermal_level_serialised(self):
        t = _thermal("throttled", 70)
        d = self._audit(thermal=t).to_dict()
        assert d["thermal"]["level"] == "throttled"
        assert d["thermal"]["cpu_speed_limit"] == 70

    def test_sleep_preventers_serialised_as_list(self):
        p = _preventer(name="mds", pid=42, assertion_type="BackgroundTask", detail="indexing")
        d = self._audit(preventers=[p]).to_dict()
        assert isinstance(d["sleep_preventers"], list)
        assert len(d["sleep_preventers"]) == 1
        assert d["sleep_preventers"][0]["name"] == "mds"
        assert d["sleep_preventers"][0]["pid"] == 42

    def test_schedule_serialised_as_list(self):
        event = ScheduledEvent(event_type="wake", time="2026-04-27 08:00", owner="com.apple.backup")
        d = self._audit(schedule=[event]).to_dict()
        assert isinstance(d["schedule"], list)
        assert d["schedule"][0]["event_type"] == "wake"
        assert d["schedule"][0]["owner"] == "com.apple.backup"

    def test_issues_serialised_as_list_of_dicts(self):
        d = self._audit(settings=_settings(wake_on_lan=True)).to_dict()
        assert isinstance(d["issues"], list)
        for issue in d["issues"]:
            assert isinstance(issue, dict)


# ===========================================================================
# audit_energy (integration — mocked system calls)
# ===========================================================================

class TestAuditEnergy:
    """audit_energy() collects data and returns an EnergyAudit."""

    def test_returns_energy_audit_instance(self):
        with patch("mactools_macenergy.engine.get_power_settings", return_value=_settings()), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=_thermal()), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[]):
            result = audit_energy()
        assert isinstance(result, EnergyAudit)

    def test_audit_energy_propagates_settings(self):
        s = _settings(sleep_timer=30, wake_on_lan=True)
        with patch("mactools_macenergy.engine.get_power_settings", return_value=s), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=_thermal()), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[]):
            result = audit_energy()
        assert result.power_settings.sleep_timer == 30
        assert result.power_settings.wake_on_lan is True

    def test_audit_energy_propagates_thermal_state(self):
        t = _thermal("throttled", 80)
        with patch("mactools_macenergy.engine.get_power_settings", return_value=_settings()), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=t), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[]):
            result = audit_energy()
        assert result.thermal.level == "throttled"
        assert result.thermal.cpu_speed_limit == 80

    def test_audit_energy_issues_not_empty(self):
        with patch("mactools_macenergy.engine.get_power_settings", return_value=_settings()), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=_thermal()), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[]):
            result = audit_energy()
        # Healthy config → one "ok" issue
        assert len(result.issues) >= 1

    def test_audit_energy_propagates_preventers(self):
        p = _preventer(name="backupd", pid=500, assertion_type="BackgroundTask")
        with patch("mactools_macenergy.engine.get_power_settings", return_value=_settings()), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[p]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=_thermal()), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[]):
            result = audit_energy()
        assert len(result.preventers) == 1
        assert result.preventers[0].name == "backupd"

    def test_audit_energy_propagates_schedule(self):
        event = ScheduledEvent(event_type="sleep", time="22:00", owner="")
        with patch("mactools_macenergy.engine.get_power_settings", return_value=_settings()), \
             patch("mactools_macenergy.engine.get_sleep_preventers", return_value=[]), \
             patch("mactools_macenergy.engine.get_thermal_state", return_value=_thermal()), \
             patch("mactools_macenergy.engine.get_scheduled_events", return_value=[event]):
            result = audit_energy()
        assert len(result.schedule) == 1
        assert result.schedule[0].event_type == "sleep"
