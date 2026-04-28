"""Tests for mactools_maclaunch.engine — risk classification, audit, and statistics."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mactools_core.launchctl import LaunchService
from mactools_maclaunch.engine import (
    AuditFinding,
    audit_services,
    build_stats,
    classify_risk,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apple(label: str = "com.apple.foo", **kwargs) -> LaunchService:
    """Minimal Apple service."""
    return LaunchService(label=label, is_apple=True, **kwargs)


def _svc(
    label: str = "com.example.myapp",
    *,
    program: str | None = None,
    program_args: list[str] | None = None,
    run_at_load: bool = False,
    keep_alive: bool = False,
    source: str = "user",
    plist_path: str | None = "/Library/LaunchAgents/com.example.myapp.plist",
    running: bool = False,
) -> LaunchService:
    """Minimal non-Apple service with sensible defaults."""
    return LaunchService(
        label=label,
        is_apple=False,
        program=program,
        program_args=program_args or [],
        run_at_load=run_at_load,
        keep_alive=keep_alive,
        source=source,
        plist_path=plist_path,
        running=running,
    )


# ===========================================================================
# classify_risk
# ===========================================================================

class TestClassifyRisk:
    """classify_risk(service) -> 'safe' | 'low' | 'medium' | 'high'"""

    def test_apple_service_is_always_safe(self):
        assert classify_risk(_apple()) == "safe"

    def test_apple_service_safe_even_with_suspicious_program(self):
        svc = _apple(program="/tmp/malware.sh")
        assert classify_risk(svc) == "safe"

    def test_trusted_vendor_returns_low(self):
        # com.google. maps to vendor "Google" which is in _TRUSTED_VENDORS
        svc = _svc(label="com.google.keystone.agent", program="/Applications/GoogleUpdater.app/Contents/MacOS/Updater")
        assert classify_risk(svc) == "low"

    def test_unknown_vendor_returns_medium(self):
        svc = _svc(label="com.somerandomplugin.helper")
        assert classify_risk(svc) == "medium"

    def test_suspicious_tmp_path_returns_high(self):
        svc = _svc(program="/tmp/evil.sh")
        assert classify_risk(svc) == "high"

    def test_suspicious_private_tmp_returns_high(self):
        svc = _svc(program="/private/tmp/backdoor")
        assert classify_risk(svc) == "high"

    def test_shell_script_extension_returns_high(self):
        svc = _svc(program="/Users/alice/scripts/startup.sh")
        assert classify_risk(svc) == "high"

    def test_python_extension_returns_high(self):
        svc = _svc(program="/usr/local/bin/run.py")
        assert classify_risk(svc) == "high"

    def test_curl_in_program_returns_high(self):
        svc = _svc(program="/usr/bin/curl")
        assert classify_risk(svc) == "high"

    def test_wget_in_program_returns_high(self):
        svc = _svc(program="/usr/local/bin/wget")
        assert classify_risk(svc) == "high"

    def test_bash_in_program_returns_high(self):
        svc = _svc(program="/bin/bash")
        assert classify_risk(svc) == "high"

    def test_program_read_from_program_args_when_no_program(self):
        """classify_risk falls back to program_args[0] when program is None."""
        svc = _svc(program=None, program_args=["/tmp/run.sh", "--flag"])
        assert classify_risk(svc) == "high"

    def test_app_bundle_program_does_not_elevate_low_risk(self):
        # A Google-labelled service pointing to /Applications/ stays "low"
        svc = _svc(
            label="com.google.Chrome.helper",
            program="/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
        )
        result = classify_risk(svc)
        assert result in ("low", "medium")  # must NOT be high

    def test_uuid_style_label_returns_high(self):
        svc = _svc(label="ab12cd34-ef56-")
        assert classify_risk(svc) == "high"

    def test_telemetry_label_returns_high(self):
        svc = _svc(label="com.vendor.telemetry")
        assert classify_risk(svc) == "high"

    def test_tracker_label_returns_high(self):
        svc = _svc(label="com.ad.tracker.service")
        assert classify_risk(svc) == "high"

    def test_update_agent_label_returns_high(self):
        svc = _svc(label="com.vendor.updateagent")
        assert classify_risk(svc) == "high"

    def test_syslogd_label_not_flagged(self):
        # 'syslogd' should NOT match the suspicious label r"syslog(?!d)"
        svc = _svc(label="com.apple.syslogd")
        # Apple services return safe before label checking, but test the regex
        # logic with a non-Apple syslogd-styled label
        svc2 = LaunchService(label="com.vendor.syslogd", is_apple=False,
                             source="user", plist_path="/Library/LaunchAgents/x.plist")
        result = classify_risk(svc2)
        # 'syslogd' should NOT hit the syslog pattern (negative lookahead)
        assert result != "high"

    def test_syslog_without_d_label_returns_high(self):
        svc = _svc(label="com.vendor.syslog.ingest")
        assert classify_risk(svc) == "high"

    def test_no_program_medium_for_unknown_vendor(self):
        svc = _svc(label="com.unknown.thing", program=None, program_args=[])
        assert classify_risk(svc) == "medium"

    def test_homebrew_vendor_returns_low(self):
        svc = _svc(label="homebrew.mxcl.postgresql", program="/usr/local/opt/postgresql/bin/postgres")
        assert classify_risk(svc) == "low"

    def test_trusted_dir_program_does_not_elevate_low(self):
        # A trusted vendor whose binary is in /usr/bin/ should stay low
        svc = _svc(label="com.github.runner", program="/usr/bin/git")
        assert classify_risk(svc) == "low"


# ===========================================================================
# audit_services
# ===========================================================================

class TestAuditServices:
    """audit_services(services) -> list[AuditFinding]"""

    def test_empty_list_returns_no_findings(self):
        assert audit_services([]) == []

    def test_apple_services_are_skipped(self):
        services = [_apple(), _apple(label="com.apple.bar")]
        assert audit_services(services) == []

    def test_persistence_vector_generates_finding(self):
        svc = _svc(run_at_load=True, keep_alive=True)
        findings = audit_services([svc])
        categories = {f.category for f in findings}
        assert "persistence" in categories

    def test_persistence_finding_has_correct_label(self):
        svc = _svc(label="com.example.persistent", run_at_load=True, keep_alive=True)
        findings = audit_services([svc])
        pf = next(f for f in findings if f.category == "persistence")
        assert pf.label == "com.example.persistent"

    def test_persistence_requires_both_run_at_load_and_keep_alive(self):
        # Only RunAtLoad — not a persistence vector
        svc_ral = _svc(run_at_load=True, keep_alive=False)
        findings = audit_services([svc_ral])
        assert not any(f.category == "persistence" for f in findings)

        # Only KeepAlive — not a persistence vector
        svc_ka = _svc(run_at_load=False, keep_alive=True)
        findings = audit_services([svc_ka])
        assert not any(f.category == "persistence" for f in findings)

    def test_suspicious_program_path_generates_high_risk_finding(self):
        svc = _svc(program="/tmp/inject.sh")
        findings = audit_services([svc])
        sp = next((f for f in findings if f.category == "suspicious_path"), None)
        assert sp is not None
        assert sp.risk == "high"
        assert "/tmp/inject.sh" in sp.detail

    def test_suspicious_label_pattern_generates_finding(self):
        svc = _svc(label="com.vendor.telemetry.agent")
        findings = audit_services([svc])
        sl = next((f for f in findings if f.category == "suspicious_label"), None)
        assert sl is not None
        assert sl.risk == "high"

    def test_suspicious_label_finding_breaks_after_first_match(self):
        # Only one suspicious_label finding per service (break after first hit)
        svc = _svc(label="com.vendor.telemetry.tracker")
        findings = audit_services([svc])
        label_findings = [f for f in findings if f.category == "suspicious_label" and f.label == svc.label]
        assert len(label_findings) == 1

    def test_unknown_vendor_in_global_scope_generates_finding(self):
        svc = _svc(label="com.unknown.thing", source="global")
        findings = audit_services([svc])
        uv = next((f for f in findings if f.category == "unknown_vendor_global"), None)
        assert uv is not None
        assert uv.risk == "medium"

    def test_known_vendor_in_global_scope_does_not_generate_unknown_vendor_finding(self):
        svc = _svc(label="com.google.keystone.daemon", source="global")
        findings = audit_services([svc])
        assert not any(f.category == "unknown_vendor_global" for f in findings)

    def test_no_plist_generates_orphan_finding(self):
        svc = _svc(plist_path=None)
        findings = audit_services([svc])
        orphan = next((f for f in findings if f.category == "orphan"), None)
        assert orphan is not None
        assert orphan.risk == "medium"

    def test_ephemeral_app_agent_does_not_generate_orphan_finding(self):
        # Labels starting with 'application.' are runtime-registered and have no plist
        svc = _svc(label="application.com.apple.finder.12345", plist_path=None)
        findings = audit_services([svc])
        assert not any(f.category == "orphan" for f in findings)

    def test_apple_service_with_no_plist_does_not_generate_orphan(self):
        svc = _apple(plist_path=None)
        findings = audit_services([svc])
        assert not any(f.category == "orphan" for f in findings)

    def test_deduplication_prevents_duplicate_label_category_pairs(self):
        # Build a service that would trigger the same check twice (shouldn't happen
        # in normal flow, but deduplication guard should still hold)
        svc = _svc(label="com.vendor.telemetry", plist_path=None, source="global")
        findings = audit_services([svc])
        seen: set[tuple[str, str]] = set()
        for f in findings:
            key = (f.label, f.category)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

    def test_multiple_services_all_checked(self):
        svc1 = _svc(label="com.legit.app")
        svc2 = _svc(label="com.evil.tracker", program="/tmp/bad.sh")
        svc3 = _apple(label="com.apple.safe")
        findings = audit_services([svc1, svc2, svc3])
        # svc2 must generate at least one finding; svc3 (Apple) zero
        finding_labels = {f.label for f in findings}
        assert "com.evil.tracker" in finding_labels
        assert "com.apple.safe" not in finding_labels

    def test_findings_contain_program_when_available(self):
        svc = _svc(program="/tmp/run.sh")
        findings = audit_services([svc])
        sp = next(f for f in findings if f.category == "suspicious_path")
        assert sp.program == "/tmp/run.sh"

    def test_program_falls_back_to_program_args(self):
        svc = _svc(program=None, program_args=["/tmp/run.sh", "--flag"])
        findings = audit_services([svc])
        sp = next((f for f in findings if f.category == "suspicious_path"), None)
        assert sp is not None
        assert sp.program == "/tmp/run.sh"

    def test_clean_service_generates_no_findings(self):
        svc = _svc(
            label="com.google.keystone.agent",
            program="/Applications/GoogleUpdater.app/Contents/MacOS/Updater",
            run_at_load=False,
            keep_alive=False,
            source="user",
            plist_path="/Library/LaunchAgents/com.google.keystone.agent.plist",
        )
        findings = audit_services([svc])
        assert findings == []

    def test_audit_finding_dataclass_fields(self):
        svc = _svc(label="com.badactor.backdoor", program="/tmp/nc.sh")
        findings = audit_services([svc])
        for f in findings:
            assert isinstance(f, AuditFinding)
            assert f.label
            assert f.risk in ("safe", "low", "medium", "high")
            assert f.category
            assert f.title
            assert f.detail


# ===========================================================================
# build_stats
# ===========================================================================

class TestBuildStats:
    """build_stats(services) -> dict"""

    def test_empty_list_returns_zeroes(self):
        stats = build_stats([])
        assert stats["total"] == 0
        assert stats["running"] == 0
        assert stats["stopped"] == 0
        assert stats["apple"] == 0
        assert stats["third_party"] == 0
        assert stats["persistence_agents"] == 0
        assert stats["by_vendor"] == {}
        assert stats["by_source"] == {}

    def test_total_count(self):
        services = [_apple(), _svc(), _svc(label="com.example.other")]
        assert build_stats(services)["total"] == 3

    def test_running_vs_stopped(self):
        r1 = _svc(label="com.a.running", running=True)
        r2 = _svc(label="com.b.running", running=True)
        s1 = _svc(label="com.c.stopped", running=False)
        stats = build_stats([r1, r2, s1])
        assert stats["running"] == 2
        assert stats["stopped"] == 1

    def test_apple_vs_third_party_count(self):
        services = [_apple(), _apple(label="com.apple.bar"), _svc()]
        stats = build_stats(services)
        assert stats["apple"] == 2
        assert stats["third_party"] == 1

    def test_persistence_agents_count(self):
        p = _svc(label="com.a.persist", run_at_load=True, keep_alive=True)
        np1 = _svc(label="com.b.nope", run_at_load=True, keep_alive=False)
        np2 = _apple()  # Apple services ignored by _is_persistence_vector
        stats = build_stats([p, np1, np2])
        assert stats["persistence_agents"] == 1

    def test_by_vendor_aggregation(self):
        g1 = _svc(label="com.google.a")
        g2 = _svc(label="com.google.b")
        ms = _svc(label="com.microsoft.teams")
        stats = build_stats([g1, g2, ms])
        assert stats["by_vendor"]["Google"] == 2
        assert stats["by_vendor"]["Microsoft"] == 1

    def test_by_source_aggregation(self):
        u1 = _svc(label="com.a.u1", source="user")
        u2 = _svc(label="com.a.u2", source="user")
        g1 = _svc(label="com.a.g1", source="global")
        stats = build_stats([u1, u2, g1])
        assert stats["by_source"]["user"] == 2
        assert stats["by_source"]["global"] == 1

    def test_by_vendor_sorted_descending(self):
        """Most common vendors appear first."""
        services = (
            [_svc(label=f"com.google.{i}") for i in range(3)]
            + [_svc(label="com.microsoft.one")]
        )
        stats = build_stats(services)
        vendors = list(stats["by_vendor"].keys())
        assert vendors[0] == "Google"

    def test_by_source_sorted_descending(self):
        services = (
            [_svc(label=f"com.a.{i}", source="user") for i in range(4)]
            + [_svc(label="com.b.x", source="global")]
        )
        stats = build_stats(services)
        sources = list(stats["by_source"].keys())
        assert sources[0] == "user"

    def test_all_expected_keys_present(self):
        stats = build_stats([_svc()])
        for key in ("total", "running", "stopped", "apple", "third_party",
                    "persistence_agents", "by_vendor", "by_source"):
            assert key in stats, f"Missing key: {key}"

    def test_apple_persistence_not_counted(self):
        """Apple services with RunAtLoad+KeepAlive should NOT inflate persistence count."""
        a = LaunchService(
            label="com.apple.system.daemon",
            is_apple=True,
            run_at_load=True,
            keep_alive=True,
        )
        stats = build_stats([a])
        assert stats["persistence_agents"] == 0

    def test_third_party_persistence_counted(self):
        p = _svc(label="com.vendor.updater", run_at_load=True, keep_alive=True)
        stats = build_stats([p])
        assert stats["persistence_agents"] == 1

    def test_stopped_is_total_minus_running(self):
        services = [_svc(label=f"com.x.{i}", running=(i % 2 == 0)) for i in range(6)]
        stats = build_stats(services)
        assert stats["stopped"] == stats["total"] - stats["running"]
