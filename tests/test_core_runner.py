"""Tests for mactools_core.runner — RunResult, run, run_json, run_plist."""

from __future__ import annotations

import json
import plistlib
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mactools_core.runner import RunResult, run, run_json, run_plist


# ---------------------------------------------------------------------------
# RunResult dataclass
# ---------------------------------------------------------------------------

class TestRunResult:
    def test_ok_true_when_returncode_zero(self):
        r = RunResult(stdout="hello", stderr="", returncode=0, ok=True)
        assert r.ok is True
        assert r.returncode == 0

    def test_ok_false_when_returncode_nonzero(self):
        r = RunResult(stdout="", stderr="bad", returncode=1, ok=False)
        assert r.ok is False

    def test_fields_accessible(self):
        r = RunResult(stdout="out", stderr="err", returncode=42, ok=False)
        assert r.stdout == "out"
        assert r.stderr == "err"
        assert r.returncode == 42


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------

class TestRun:
    def _make_completed(self, stdout="", stderr="", returncode=0):
        mock = MagicMock()
        mock.stdout = stdout
        mock.stderr = stderr
        mock.returncode = returncode
        return mock

    def test_success(self):
        with patch("subprocess.run", return_value=self._make_completed(stdout="hello\n")) as mock_sub:
            result = run(["echo", "hello"])
        assert result.ok is True
        assert result.stdout == "hello\n"
        assert result.returncode == 0

    def test_failure_returncode(self):
        with patch("subprocess.run", return_value=self._make_completed(stderr="oops", returncode=1)):
            result = run(["false"])
        assert result.ok is False
        assert result.returncode == 1
        assert "oops" in result.stderr

    def test_timeout_returns_failure(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["ls"], timeout=1)):
            result = run(["ls"], timeout=1)
        assert result.ok is False
        assert result.returncode == -1
        assert "timeout" in result.stderr

    def test_file_not_found_returns_failure(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run(["nonexistent_command_xyz"])
        assert result.ok is False
        assert result.returncode == -1
        assert "command not found" in result.stderr

    def test_sudo_flag_prepends_sudo(self):
        with patch("subprocess.run", return_value=self._make_completed()) as mock_sub:
            run(["id"], sudo=True)
        called_cmd = mock_sub.call_args[0][0]
        assert called_cmd[:2] == ["sudo", "-n"]
        assert "id" in called_cmd

    def test_capture_output_and_text_flags(self):
        """subprocess.run must be called with capture_output=True, text=True."""
        with patch("subprocess.run", return_value=self._make_completed()) as mock_sub:
            run(["ls"])
        kwargs = mock_sub.call_args[1]
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True


# ---------------------------------------------------------------------------
# run_json()
# ---------------------------------------------------------------------------

class TestRunJson:
    def test_returns_parsed_dict(self):
        payload = {"key": "value", "num": 42}
        with patch("mactools_core.runner.run", return_value=RunResult(
            stdout=json.dumps(payload), stderr="", returncode=0, ok=True
        )):
            result = run_json(["cmd"])
        assert result == payload

    def test_returns_list(self):
        payload = [1, 2, 3]
        with patch("mactools_core.runner.run", return_value=RunResult(
            stdout=json.dumps(payload), stderr="", returncode=0, ok=True
        )):
            result = run_json(["cmd"])
        assert result == [1, 2, 3]

    def test_returns_none_on_run_failure(self):
        with patch("mactools_core.runner.run", return_value=RunResult(
            stdout="", stderr="err", returncode=1, ok=False
        )):
            result = run_json(["cmd"])
        assert result is None

    def test_returns_none_on_invalid_json(self):
        with patch("mactools_core.runner.run", return_value=RunResult(
            stdout="not json {{}", stderr="", returncode=0, ok=True
        )):
            result = run_json(["cmd"])
        assert result is None

    def test_returns_none_on_empty_output(self):
        with patch("mactools_core.runner.run", return_value=RunResult(
            stdout="", stderr="", returncode=0, ok=True
        )):
            result = run_json(["cmd"])
        assert result is None


# ---------------------------------------------------------------------------
# run_plist()
# ---------------------------------------------------------------------------

class TestRunPlist:
    def _make_plist_bytes(self, data: dict) -> bytes:
        return plistlib.dumps(data)

    def _make_completed_bytes(self, data: dict, returncode: int = 0):
        mock = MagicMock()
        mock.stdout = self._make_plist_bytes(data)
        mock.stderr = b""
        mock.returncode = returncode
        return mock

    def test_returns_parsed_dict(self):
        data = {"hello": "world", "count": 3}
        with patch("subprocess.run", return_value=self._make_completed_bytes(data)):
            result = run_plist(["cmd"])
        assert result == data

    def test_returns_none_on_nonzero_returncode(self):
        mock = MagicMock()
        mock.stdout = b""
        mock.stderr = b"error"
        mock.returncode = 1
        with patch("subprocess.run", return_value=mock):
            result = run_plist(["cmd"])
        assert result is None

    def test_returns_none_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["x"], timeout=1)):
            result = run_plist(["cmd"])
        assert result is None

    def test_returns_none_on_file_not_found(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = run_plist(["cmd"])
        assert result is None

    def test_returns_none_on_invalid_plist(self):
        mock = MagicMock()
        mock.stdout = b"not a plist"
        mock.stderr = b""
        mock.returncode = 0
        with patch("subprocess.run", return_value=mock):
            result = run_plist(["cmd"])
        assert result is None
