"""Tests for mactools_opslog.engine — severity classification, triage grouping, report building."""

from __future__ import annotations

import pytest

from mactools_core.unified_log import LogEntry
from mactools_opslog.engine import (
    TriageGroup,
    TriageReport,
    build_triage_report,
    classify_severity,
    triage_errors,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(
    message: str = "",
    level: str = "error",
    process: str = "TestProcess",
    subsystem: str = "com.example.test",
    category: str = "test",
    pid: int = 1,
    timestamp: str = "2024-01-15 10:00:00.000000+0000",
) -> LogEntry:
    """Build a minimal LogEntry for testing."""
    return LogEntry(
        timestamp=timestamp,
        process=process,
        pid=pid,
        subsystem=subsystem,
        category=category,
        message=message,
        level=level,
    )


# ===========================================================================
# classify_severity — content-based rules
# ===========================================================================

class TestClassifySeverityContentRules:
    """Content rules take priority over log level."""

    def test_kernel_panic_is_critical(self):
        assert classify_severity(_entry("kernel panic detected")) == "critical"

    def test_panic_word_boundary_is_critical(self):
        assert classify_severity(_entry("panic: something happened")) == "critical"

    def test_out_of_memory_is_critical(self):
        assert classify_severity(_entry("out of memory condition")) == "critical"

    def test_oom_abbreviation_is_critical(self):
        assert classify_severity(_entry("OOM killer triggered")) == "critical"

    def test_low_memory_is_critical(self):
        assert classify_severity(_entry("low memory warning")) == "critical"

    def test_crash_is_critical(self):
        assert classify_severity(_entry("app crash detected")) == "critical"

    def test_crashed_is_critical(self):
        assert classify_severity(_entry("process crashed unexpectedly")) == "critical"

    def test_segfault_is_critical(self):
        assert classify_severity(_entry("segfault at address 0x0")) == "critical"

    def test_sigsegv_is_critical(self):
        assert classify_severity(_entry("received SIGSEGV signal")) == "critical"

    def test_sigabrt_is_critical(self):
        assert classify_severity(_entry("received SIGABRT signal")) == "critical"

    def test_disk_full_is_critical(self):
        assert classify_severity(_entry("disk is full, cannot write")) == "critical"

    def test_no_space_left_is_critical(self):
        assert classify_severity(_entry("no space left on device")) == "critical"

    def test_enospc_is_critical(self):
        assert classify_severity(_entry("write failed: ENOSPC")) == "critical"

    def test_fault_word_boundary_is_critical(self):
        assert classify_severity(_entry("a fault occurred here")) == "critical"

    def test_sandbox_violation_is_warning(self):
        assert classify_severity(_entry("sandbox violation for process")) == "warning"

    def test_deny_sandbox_is_warning(self):
        assert classify_severity(_entry("deny sandbox file-read-data")) == "warning"

    def test_sandbox_deny_is_warning(self):
        assert classify_severity(_entry("sandbox deny mach-lookup")) == "warning"

    def test_codesign_fail_is_warning(self):
        assert classify_severity(_entry("codesign fail: invalid")) == "warning"

    def test_invalid_signature_is_warning(self):
        assert classify_severity(_entry("invalid signature on bundle")) == "warning"

    def test_signature_invalid_is_warning(self):
        assert classify_severity(_entry("signature invalid for app")) == "warning"

    def test_timeout_is_warning(self):
        assert classify_severity(_entry("operation timeout exceeded")) == "warning"

    def test_timed_out_is_warning(self):
        assert classify_severity(_entry("request timed out after 30s")) == "warning"

    def test_permission_denied_is_warning(self):
        assert classify_severity(_entry("permission denied opening file")) == "warning"

    def test_not_permitted_is_warning(self):
        assert classify_severity(_entry("operation not permitted")) == "warning"

    def test_eperm_is_warning(self):
        assert classify_severity(_entry("syscall failed EPERM")) == "warning"

    def test_eacces_is_warning(self):
        assert classify_severity(_entry("open failed EACCES")) == "warning"

    def test_failed_keyword_is_warning(self):
        assert classify_severity(_entry("connection failed to host")) == "warning"

    def test_failure_keyword_is_warning(self):
        assert classify_severity(_entry("authentication failure")) == "warning"

    def test_error_word_boundary_is_warning(self):
        assert classify_severity(_entry("an error occurred")) == "warning"

    def test_xpc_error_is_info(self):
        assert classify_severity(_entry("xpc error: connection interrupted")) == "info"

    def test_error_xpc_is_info(self):
        assert classify_severity(_entry("error xpc connection lost")) == "info"

    def test_connection_invalidated_is_info(self):
        assert classify_severity(_entry("connection invalidated by peer")) == "info"

    def test_invalidated_connection_is_info(self):
        assert classify_severity(_entry("invalidated connection to service")) == "info"

    def test_case_insensitive_matching(self):
        assert classify_severity(_entry("KERNEL PANIC now")) == "critical"
        assert classify_severity(_entry("Sandbox Violation detected")) == "warning"
        assert classify_severity(_entry("XPC Error occurred")) == "info"

    def test_first_rule_wins_over_later_rules(self):
        # "kernel panic" matches rule 0 (critical), not any warning rules
        entry = _entry("kernel panic error failure")
        assert classify_severity(entry) == "critical"

    def test_content_overrides_level(self):
        # message triggers critical, but level is "info" — content wins
        entry = _entry(message="kernel panic in driver", level="info")
        assert classify_severity(entry) == "critical"

    def test_panic_not_word_boundary_skips_critical(self):
        # "panicking" has \b after "panic" since 'king' follows — \b is between 'c' and 'k'?
        # Actually "panic\b" matches at the start of "panicking" boundary check:
        # The \b rule for "panic" should NOT match "panicking" since there is no word boundary
        # after "panic" inside "panicking".
        # But note: "panic" pattern uses \b, so "panicking" should not match.
        entry = _entry("panicking about memory", level="info")
        # Falls through to level-based: "info" -> "info"
        assert classify_severity(entry) == "info"


# ===========================================================================
# classify_severity — level fallback
# ===========================================================================

class TestClassifySeverityLevelFallback:
    """When no content rule matches, severity is derived from the log level."""

    def test_fault_level_is_critical(self):
        assert classify_severity(_entry("normal message", level="fault")) == "critical"

    def test_error_level_is_warning(self):
        assert classify_severity(_entry("normal message", level="error")) == "warning"

    def test_warning_level_is_warning(self):
        assert classify_severity(_entry("normal message", level="warning")) == "warning"

    def test_info_level_is_info(self):
        assert classify_severity(_entry("normal message", level="info")) == "info"

    def test_debug_level_is_info(self):
        assert classify_severity(_entry("normal message", level="debug")) == "info"

    def test_default_level_is_info(self):
        assert classify_severity(_entry("normal message", level="default")) == "info"

    def test_unknown_level_falls_back_to_info(self):
        assert classify_severity(_entry("normal message", level="unknown_level")) == "info"

    def test_level_comparison_is_case_insensitive(self):
        # The engine calls entry.level.lower() before the dict lookup
        assert classify_severity(_entry("normal message", level="FAULT")) == "critical"
        assert classify_severity(_entry("normal message", level="ERROR")) == "warning"

    def test_empty_message_uses_level(self):
        assert classify_severity(_entry("", level="fault")) == "critical"
        assert classify_severity(_entry("", level="info")) == "info"


# ===========================================================================
# triage_errors — grouping and counting
# ===========================================================================

class TestTriageErrorsGrouping:
    def test_empty_input_returns_empty_list(self):
        assert triage_errors([]) == []

    def test_single_entry_creates_one_group(self):
        groups = triage_errors([_entry("app crashed", level="error")])
        assert len(groups) == 1

    def test_same_process_subsystem_grouped_together(self):
        entries = [
            _entry("error one", process="Safari", subsystem="com.apple.safari"),
            _entry("error two", process="Safari", subsystem="com.apple.safari"),
            _entry("error three", process="Safari", subsystem="com.apple.safari"),
        ]
        groups = triage_errors(entries)
        assert len(groups) == 1
        assert groups[0].count == 3

    def test_different_process_creates_separate_groups(self):
        entries = [
            _entry("err", process="Safari", subsystem="com.apple.safari"),
            _entry("err", process="Finder", subsystem="com.apple.finder"),
        ]
        groups = triage_errors(entries)
        assert len(groups) == 2
        procs = {g.process for g in groups}
        assert procs == {"Safari", "Finder"}

    def test_same_process_different_subsystem_creates_separate_groups(self):
        entries = [
            _entry("err", process="launchd", subsystem="com.apple.xpc"),
            _entry("err", process="launchd", subsystem="com.apple.boot"),
        ]
        groups = triage_errors(entries)
        assert len(groups) == 2

    def test_group_key_format(self):
        entry = _entry("err", process="MyApp", subsystem="com.example.myapp")
        groups = triage_errors([entry])
        assert groups[0].key == "MyApp|com.example.myapp"

    def test_group_stores_correct_process_and_subsystem(self):
        entry = _entry("err", process="Notes", subsystem="com.apple.notes")
        groups = triage_errors([entry])
        assert groups[0].process == "Notes"
        assert groups[0].subsystem == "com.apple.notes"


# ===========================================================================
# triage_errors — severity escalation
# ===========================================================================

class TestTriageErrorsSeverityEscalation:
    def test_group_severity_starts_from_first_entry(self):
        entries = [_entry("normal message", level="info")]
        groups = triage_errors(entries)
        assert groups[0].severity == "info"

    def test_severity_escalates_when_worse_entry_seen(self):
        entries = [
            _entry("info message", level="info"),
            _entry("kernel panic", level="error"),  # triggers critical via content rule
        ]
        groups = triage_errors(entries)
        assert groups[0].severity == "critical"

    def test_severity_never_de_escalates(self):
        entries = [
            _entry("kernel panic", level="error"),   # critical
            _entry("info message", level="info"),    # info — should not downgrade
            _entry("info again", level="info"),
        ]
        groups = triage_errors(entries)
        assert groups[0].severity == "critical"

    def test_warning_escalates_to_critical(self):
        entries = [
            _entry("permission denied", level="warning"),  # warning
            _entry("app crashed", level="error"),           # critical
        ]
        groups = triage_errors(entries)
        assert groups[0].severity == "critical"

    def test_info_escalates_to_warning(self):
        entries = [
            _entry("normal info", level="info"),
            _entry("connection failed", level="error"),  # 'failed' -> warning
        ]
        groups = triage_errors(entries)
        assert groups[0].severity == "warning"


# ===========================================================================
# triage_errors — sample messages
# ===========================================================================

class TestTriageErrorsSampleMessages:
    def test_first_message_collected(self):
        entry = _entry("first error message")
        groups = triage_errors([entry])
        assert "first error message" in groups[0].sample_messages

    def test_at_most_three_sample_messages(self):
        entries = [_entry(f"unique message {i}") for i in range(10)]
        groups = triage_errors(entries)
        assert len(groups[0].sample_messages) <= 3

    def test_duplicate_messages_not_repeated_in_samples(self):
        entries = [_entry("same error") for _ in range(5)]
        groups = triage_errors(entries)
        assert groups[0].sample_messages.count("same error") == 1

    def test_distinct_messages_all_collected_up_to_three(self):
        entries = [
            _entry("first unique"),
            _entry("second unique"),
            _entry("third unique"),
            _entry("fourth unique"),  # should be dropped
        ]
        groups = triage_errors(entries)
        samples = groups[0].sample_messages
        assert len(samples) == 3
        assert "first unique" in samples
        assert "second unique" in samples
        assert "third unique" in samples
        assert "fourth unique" not in samples

    def test_long_messages_truncated_to_200_chars(self):
        long_msg = "x" * 300
        entry = _entry(long_msg)
        groups = triage_errors([entry])
        assert len(groups[0].sample_messages[0]) == 200

    def test_empty_message_not_added_to_samples(self):
        entries = [_entry("")]
        groups = triage_errors(entries)
        assert groups[0].sample_messages == []

    def test_whitespace_only_message_stripped_to_empty_and_skipped(self):
        entries = [_entry("   ")]
        groups = triage_errors(entries)
        assert groups[0].sample_messages == []

    def test_messages_from_different_groups_are_isolated(self):
        entries = [
            _entry("safari error", process="Safari", subsystem="com.apple.safari"),
            _entry("finder error", process="Finder", subsystem="com.apple.finder"),
        ]
        groups = triage_errors(entries)
        safari_group = next(g for g in groups if g.process == "Safari")
        finder_group = next(g for g in groups if g.process == "Finder")
        assert "safari error" in safari_group.sample_messages
        assert "finder error" in finder_group.sample_messages
        assert "finder error" not in safari_group.sample_messages


# ===========================================================================
# triage_errors — level distribution tracking
# ===========================================================================

class TestTriageErrorsLevelTracking:
    def test_level_counts_tracked_per_group(self):
        entries = [
            _entry("e1", level="error"),
            _entry("e2", level="error"),
            _entry("e3", level="fault"),
        ]
        groups = triage_errors(entries)
        assert groups[0].levels["error"] == 2
        assert groups[0].levels["fault"] == 1

    def test_levels_normalized_to_lowercase(self):
        entries = [
            _entry("e", level="ERROR"),
            _entry("e", level="Error"),
        ]
        groups = triage_errors(entries)
        assert "error" in groups[0].levels
        assert groups[0].levels["error"] == 2

    def test_multiple_level_types_tracked(self):
        entries = [
            _entry("a", level="error"),
            _entry("b", level="info"),
            _entry("c", level="warning"),
        ]
        groups = triage_errors(entries)
        lvls = groups[0].levels
        assert lvls.get("error") == 1
        assert lvls.get("info") == 1
        assert lvls.get("warning") == 1


# ===========================================================================
# triage_errors — sort order
# ===========================================================================

class TestTriageErrorsSortOrder:
    def test_critical_groups_sorted_before_warning(self):
        entries = [
            _entry("permission denied", process="A", subsystem="s.a"),  # warning
            _entry("kernel panic", process="B", subsystem="s.b"),        # critical
        ]
        groups = triage_errors(entries)
        assert groups[0].process == "B"  # critical first
        assert groups[1].process == "A"

    def test_warning_sorted_before_info(self):
        entries = [
            _entry("normal message", level="info", process="A", subsystem="s.a"),
            _entry("connection failed", process="B", subsystem="s.b"),   # warning
        ]
        groups = triage_errors(entries)
        assert groups[0].process == "B"
        assert groups[1].process == "A"

    def test_higher_count_sorted_before_lower_count_within_same_severity(self):
        entries = (
            [_entry("xpc error: lost", process="A", subsystem="s.a")] * 1 +  # info, count=1
            [_entry("xpc error: lost", process="B", subsystem="s.b")] * 5    # info, count=5
        )
        groups = triage_errors(entries)
        assert groups[0].process == "B"
        assert groups[0].count == 5

    def test_critical_with_low_count_beats_info_with_high_count(self):
        entries = (
            [_entry("xpc error: x", process="A", subsystem="s.a")] * 100 +  # info, count=100
            [_entry("kernel panic", process="B", subsystem="s.b")]           # critical, count=1
        )
        groups = triage_errors(entries)
        assert groups[0].process == "B"

    def test_empty_input_returns_empty_sorted_list(self):
        assert triage_errors([]) == []

    def test_single_group_is_returned_as_list_of_one(self):
        groups = triage_errors([_entry("err")])
        assert len(groups) == 1


# ===========================================================================
# triage_errors — large dataset
# ===========================================================================

class TestTriageErrorsLargeDataset:
    def test_handles_1000_entries_across_many_groups(self):
        entries = []
        for i in range(50):
            proc = f"Process{i}"
            sub = f"com.example.proc{i}"
            for _ in range(20):
                entries.append(_entry("error message", process=proc, subsystem=sub))
        groups = triage_errors(entries)
        assert len(groups) == 50
        for g in groups:
            assert g.count == 20

    def test_all_same_process_collapses_to_one_group(self):
        entries = [_entry(f"msg {i}") for i in range(500)]
        groups = triage_errors(entries)
        assert len(groups) == 1
        assert groups[0].count == 500

    def test_large_dataset_samples_capped_at_three(self):
        entries = [_entry(f"unique msg {i}") for i in range(100)]
        groups = triage_errors(entries)
        assert len(groups[0].sample_messages) == 3


# ===========================================================================
# triage_errors — malformed / edge-case entries
# ===========================================================================

class TestTriageErrorsEdgeCases:
    def test_empty_process_and_subsystem(self):
        entry = _entry("some error", process="", subsystem="")
        groups = triage_errors([entry])
        assert len(groups) == 1
        assert groups[0].process == ""
        assert groups[0].subsystem == ""

    def test_entry_with_special_chars_in_process_name(self):
        entry = _entry("err", process="com.example.app (123)", subsystem="com.example")
        groups = triage_errors([entry])
        assert groups[0].process == "com.example.app (123)"

    def test_single_character_process_name(self):
        entry = _entry("err", process="X", subsystem="")
        groups = triage_errors([entry])
        assert groups[0].key == "X|"

    def test_mixed_severity_entries_large_group(self):
        entries = (
            [_entry("info msg", level="info")] * 50 +
            [_entry("warning msg", level="warning")] * 30 +
            [_entry("kernel panic")] * 1
        )
        groups = triage_errors(entries)
        assert groups[0].severity == "critical"
        assert groups[0].count == 81


# ===========================================================================
# build_triage_report
# ===========================================================================

class TestBuildTriageReport:
    def test_empty_groups_produces_zero_report(self):
        report = build_triage_report([])
        assert report.total_entries == 0
        assert report.total_groups == 0
        assert report.critical_count == 0
        assert report.warning_count == 0
        assert report.info_count == 0
        assert report.groups == []

    def test_total_entries_is_sum_of_counts(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="critical", count=10),
            TriageGroup(process="B", subsystem="s", severity="warning", count=5),
            TriageGroup(process="C", subsystem="s", severity="info", count=3),
        ]
        report = build_triage_report(groups)
        assert report.total_entries == 18

    def test_total_groups_matches_list_length(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="info", count=1),
            TriageGroup(process="B", subsystem="s", severity="info", count=1),
        ]
        report = build_triage_report(groups)
        assert report.total_groups == 2

    def test_critical_count_counts_only_critical_groups(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="critical", count=5),
            TriageGroup(process="B", subsystem="s", severity="critical", count=3),
            TriageGroup(process="C", subsystem="s", severity="warning", count=10),
            TriageGroup(process="D", subsystem="s", severity="info", count=2),
        ]
        report = build_triage_report(groups)
        assert report.critical_count == 2
        assert report.warning_count == 1
        assert report.info_count == 1

    def test_warning_count_accuracy(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="warning", count=1),
            TriageGroup(process="B", subsystem="s", severity="warning", count=1),
            TriageGroup(process="C", subsystem="s", severity="warning", count=1),
        ]
        report = build_triage_report(groups)
        assert report.warning_count == 3
        assert report.critical_count == 0
        assert report.info_count == 0

    def test_info_count_accuracy(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="info", count=100),
        ]
        report = build_triage_report(groups)
        assert report.info_count == 1
        assert report.critical_count == 0
        assert report.warning_count == 0

    def test_groups_list_preserved_in_report(self):
        groups = [
            TriageGroup(process="Finder", subsystem="com.apple.finder", severity="warning", count=7),
        ]
        report = build_triage_report(groups)
        assert report.groups is groups

    def test_report_is_triage_report_instance(self):
        report = build_triage_report([])
        assert isinstance(report, TriageReport)

    def test_single_critical_group(self):
        groups = [
            TriageGroup(process="crashd", subsystem="com.apple.crash", severity="critical", count=42),
        ]
        report = build_triage_report(groups)
        assert report.total_entries == 42
        assert report.total_groups == 1
        assert report.critical_count == 1
        assert report.warning_count == 0
        assert report.info_count == 0

    def test_all_severity_types_counted_correctly(self):
        groups = [
            TriageGroup(process="A", subsystem="s", severity="critical", count=1),
            TriageGroup(process="B", subsystem="s", severity="warning", count=1),
            TriageGroup(process="C", subsystem="s", severity="info", count=1),
        ]
        report = build_triage_report(groups)
        assert report.critical_count == 1
        assert report.warning_count == 1
        assert report.info_count == 1
        assert report.total_groups == 3
        assert report.total_entries == 3


# ===========================================================================
# TriageGroup — dataclass behavior
# ===========================================================================

class TestTriageGroupDataclass:
    def test_key_property_format(self):
        g = TriageGroup(process="Safari", subsystem="com.apple.safari", severity="warning", count=1)
        assert g.key == "Safari|com.apple.safari"

    def test_key_with_empty_subsystem(self):
        g = TriageGroup(process="kernel", subsystem="", severity="critical", count=3)
        assert g.key == "kernel|"

    def test_default_sample_messages_is_empty_list(self):
        g = TriageGroup(process="A", subsystem="s", severity="info", count=0)
        assert g.sample_messages == []

    def test_default_levels_is_empty_dict(self):
        g = TriageGroup(process="A", subsystem="s", severity="info", count=0)
        assert g.levels == {}

    def test_sample_messages_not_shared_between_instances(self):
        g1 = TriageGroup(process="A", subsystem="s", severity="info", count=0)
        g2 = TriageGroup(process="B", subsystem="s", severity="info", count=0)
        g1.sample_messages.append("msg")
        assert g2.sample_messages == []

    def test_levels_not_shared_between_instances(self):
        g1 = TriageGroup(process="A", subsystem="s", severity="info", count=0)
        g2 = TriageGroup(process="B", subsystem="s", severity="info", count=0)
        g1.levels["error"] = 5
        assert "error" not in g2.levels


# ===========================================================================
# Integration: triage_errors -> build_triage_report pipeline
# ===========================================================================

class TestTriagePipeline:
    def test_full_pipeline_with_mixed_entries(self):
        entries = [
            _entry("kernel panic in driver", process="kernel", subsystem="com.apple.kernel"),
            _entry("kernel panic again",     process="kernel", subsystem="com.apple.kernel"),
            _entry("permission denied",      process="Finder", subsystem="com.apple.finder"),
            _entry("xpc error: reset",       process="launchd", subsystem="com.apple.xpc"),
            _entry("xpc error: lost",        process="launchd", subsystem="com.apple.xpc"),
            _entry("normal info log",        process="mds", subsystem="com.apple.mds", level="info"),
        ]
        groups = triage_errors(entries)
        report = build_triage_report(groups)

        assert report.total_entries == 6
        assert report.total_groups == 4
        assert report.critical_count == 1   # kernel
        assert report.warning_count == 1    # Finder
        assert report.info_count == 2       # launchd(xpc) + mds

    def test_pipeline_empty_produces_empty_report(self):
        report = build_triage_report(triage_errors([]))
        assert report.total_entries == 0
        assert report.total_groups == 0

    def test_pipeline_critical_group_appears_first_in_report(self):
        entries = [
            _entry("info message", level="info", process="A", subsystem="s.a"),
            _entry("kernel panic",              process="B", subsystem="s.b"),
            _entry("permission denied",         process="C", subsystem="s.c"),
        ]
        groups = triage_errors(entries)
        report = build_triage_report(groups)
        assert report.groups[0].severity == "critical"

    def test_pipeline_report_entries_total_equals_input_count(self):
        n = 75
        entries = [_entry(f"msg {i}", process=f"Proc{i % 5}", subsystem=f"sub.{i % 5}") for i in range(n)]
        groups = triage_errors(entries)
        report = build_triage_report(groups)
        assert report.total_entries == n
