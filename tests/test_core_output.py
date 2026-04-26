"""Tests for mactools_core.output — md_table, severity coloring, print helpers."""

from __future__ import annotations

import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest

from mactools_core.output import (
    SEVERITY_COLORS,
    color,
    md_table,
    print_findings,
    print_json,
    severity_icon,
)


# ---------------------------------------------------------------------------
# color()
# ---------------------------------------------------------------------------

class TestColor:
    def test_returns_plain_text_when_not_tty(self):
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = color("hello", "critical")
        assert result == "hello"

    def test_wraps_with_ansi_when_tty(self):
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = color("hello", "critical")
        assert "\033[91m" in result
        assert "hello" in result
        assert "\033[0m" in result  # reset

    def test_unknown_level_returns_plain_text_when_tty(self):
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = color("hi", "nonexistent_level")
        # No ANSI codes for unknown level
        assert result == "hi"

    @pytest.mark.parametrize("level,code", [
        ("critical", "\033[91m"),
        ("warning", "\033[93m"),
        ("info", "\033[94m"),
        ("ok", "\033[92m"),
        ("dim", "\033[90m"),
    ])
    def test_each_severity_level_has_correct_code(self, level, code):
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = color("x", level)
        assert code in result


# ---------------------------------------------------------------------------
# severity_icon()
# ---------------------------------------------------------------------------

class TestSeverityIcon:
    def test_critical(self):
        assert severity_icon("critical") == "!!!"

    def test_warning(self):
        assert severity_icon("warning") == "!!"

    def test_info(self):
        assert severity_icon("info") == "--"

    def test_ok(self):
        assert severity_icon("ok") == "OK"

    def test_unknown_returns_question_marks(self):
        assert severity_icon("unknown_level") == "??"


# ---------------------------------------------------------------------------
# md_table()
# ---------------------------------------------------------------------------

class TestMdTable:
    def test_produces_header_separator_and_rows(self):
        headers = ["Name", "Value"]
        rows = [["foo", "bar"], ["baz", "qux"]]
        result = md_table(headers, rows)
        lines = result.splitlines()
        assert len(lines) == 4  # header + separator + 2 rows
        assert "Name" in lines[0]
        assert "Value" in lines[0]
        assert "---" in lines[1]
        assert "foo" in lines[2]
        assert "bar" in lines[2]

    def test_column_widths_padded_to_widest_cell(self):
        headers = ["A"]
        rows = [["short"], ["a much longer value"]]
        result = md_table(headers, rows)
        lines = result.splitlines()
        # All rows should be padded to the same width
        widths = [len(l) for l in lines]
        assert len(set(widths)) == 1  # all same length

    def test_empty_rows(self):
        headers = ["Col1", "Col2"]
        result = md_table(headers, [])
        lines = result.splitlines()
        assert len(lines) == 2  # header + separator only

    def test_single_column(self):
        result = md_table(["Status"], [["ok"], ["fail"]])
        assert "Status" in result
        assert "ok" in result

    def test_row_with_fewer_cells_than_headers(self):
        headers = ["A", "B", "C"]
        rows = [["only_a"]]
        result = md_table(headers, rows)
        # Should not raise, missing cells get spaces
        assert "only_a" in result

    def test_numeric_values_converted_to_string(self):
        result = md_table(["Count"], [[42], [100]])
        assert "42" in result
        assert "100" in result


# ---------------------------------------------------------------------------
# print_json()
# ---------------------------------------------------------------------------

class TestPrintJson:
    def test_prints_valid_json(self, capsys):
        data = {"key": "value", "num": 1}
        print_json(data)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data

    def test_prints_list(self, capsys):
        data = [1, 2, 3]
        print_json(data)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == [1, 2, 3]

    def test_uses_indent_2(self, capsys):
        data = {"a": 1}
        print_json(data)
        captured = capsys.readouterr()
        assert "\n  " in captured.out  # indented

    def test_handles_non_serializable_with_default_str(self, capsys):
        from datetime import datetime
        data = {"ts": datetime(2024, 1, 1)}
        # Should not raise — default=str handles it
        print_json(data)
        captured = capsys.readouterr()
        assert "2024" in captured.out


# ---------------------------------------------------------------------------
# print_findings()
# ---------------------------------------------------------------------------

class TestPrintFindings:
    def test_json_mode_outputs_json(self, capsys):
        findings = [
            {"severity": "critical", "title": "SIP disabled", "detail": "bad"},
        ]
        print_findings(findings, as_json=True)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed[0]["title"] == "SIP disabled"

    def test_text_mode_shows_icon_and_title(self, capsys):
        findings = [
            {"severity": "ok", "title": "All good", "detail": ""},
        ]
        with patch.object(sys.stdout, "isatty", return_value=False):
            print_findings(findings)
        captured = capsys.readouterr()
        assert "OK" in captured.out
        assert "All good" in captured.out

    def test_text_mode_shows_detail(self, capsys):
        findings = [
            {"severity": "warning", "title": "Firewall off", "detail": "Enable it"},
        ]
        with patch.object(sys.stdout, "isatty", return_value=False):
            print_findings(findings)
        captured = capsys.readouterr()
        assert "Enable it" in captured.out

    def test_empty_findings_produces_no_output(self, capsys):
        print_findings([])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_missing_detail_doesnt_print_blank_line(self, capsys):
        findings = [{"severity": "info", "title": "Note", "detail": ""}]
        with patch.object(sys.stdout, "isatty", return_value=False):
            print_findings(findings)
        captured = capsys.readouterr()
        # detail is empty, so only title line should appear
        lines = [l for l in captured.out.splitlines() if l.strip()]
        assert len(lines) == 1
