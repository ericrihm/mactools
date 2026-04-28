"""Tests for mactools_macsec.engine — security posture audit and scoring."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mactools_core.runner import RunResult
from mactools_core.security import SIPStatus, GatekeeperStatus, FileVaultStatus
from mactools_core.system_profiler import FirewallInfo


# ---------------------------------------------------------------------------
# RunResult helpers
# ---------------------------------------------------------------------------

def _ok(stdout: str = "", stderr: str = "") -> RunResult:
    return RunResult(stdout=stdout, stderr=stderr, returncode=0, ok=True)


def _fail(stderr: str = "error") -> RunResult:
    return RunResult(stdout="", stderr=stderr, returncode=1, ok=False)


# ---------------------------------------------------------------------------
# Firewall factory helpers
# ---------------------------------------------------------------------------

def _fw(enabled: bool = True, stealth: bool = True, mode: str = "on") -> FirewallInfo:
    return FirewallInfo(enabled=enabled, stealth=stealth, mode=mode)


# ---------------------------------------------------------------------------
# Shared "all green" patch context
# ---------------------------------------------------------------------------

def _all_secure_patches():
    """Return a dict of patches for a fully-hardened Mac."""
    return {
        "mactools_macsec.engine.get_sip_status": SIPStatus(enabled=True, details="enabled"),
        "mactools_macsec.engine.get_gatekeeper_status": GatekeeperStatus(enabled=True),
        "mactools_macsec.engine.get_filevault_status": FileVaultStatus(enabled=True, details="FileVault is On."),
        "mactools_macsec.engine.get_firewall": _fw(enabled=True, stealth=True),
    }


# ===========================================================================
# SecurityFinding.as_dict
# ===========================================================================

class TestSecurityFindingAsDict:
    def test_all_fields_present(self):
        from mactools_macsec.engine import SecurityFinding
        f = SecurityFinding(
            title="Test Finding",
            severity="warning",
            detail="Some detail",
            fix_command="sudo fix it",
            category="Remote",
        )
        d = f.as_dict()
        assert d["title"] == "Test Finding"
        assert d["severity"] == "warning"
        assert d["detail"] == "Some detail"
        assert d["fix_command"] == "sudo fix it"
        assert d["category"] == "Remote"

    def test_fix_command_defaults_to_none(self):
        from mactools_macsec.engine import SecurityFinding
        f = SecurityFinding(title="OK check", severity="ok", detail="All good")
        assert f.as_dict()["fix_command"] is None

    def test_category_defaults_to_empty_string(self):
        from mactools_macsec.engine import SecurityFinding
        f = SecurityFinding(title="Info", severity="info", detail="Detail")
        assert f.as_dict()["category"] == ""


# ===========================================================================
# _check_auto_login
# ===========================================================================

class TestCheckAutoLogin:
    def test_auto_login_enabled(self):
        from mactools_macsec.engine import _check_auto_login
        with patch("mactools_macsec.engine.run", return_value=_ok("admin\n")):
            assert _check_auto_login() is True

    def test_auto_login_disabled_zero(self):
        from mactools_macsec.engine import _check_auto_login
        with patch("mactools_macsec.engine.run", return_value=_ok("0")):
            assert _check_auto_login() is False

    def test_auto_login_disabled_empty(self):
        from mactools_macsec.engine import _check_auto_login
        with patch("mactools_macsec.engine.run", return_value=_ok("")):
            assert _check_auto_login() is False

    def test_auto_login_command_fails(self):
        from mactools_macsec.engine import _check_auto_login
        with patch("mactools_macsec.engine.run", return_value=_fail("key not found")):
            assert _check_auto_login() is False


# ===========================================================================
# _check_screen_sharing
# ===========================================================================

class TestCheckScreenSharing:
    def test_screen_sharing_on(self):
        from mactools_macsec.engine import _check_screen_sharing
        with patch("mactools_macsec.engine.run", return_value=_ok("com.apple.screensharing")):
            assert _check_screen_sharing() is True

    def test_screen_sharing_off(self):
        from mactools_macsec.engine import _check_screen_sharing
        with patch("mactools_macsec.engine.run", return_value=_fail("Could not find service")):
            assert _check_screen_sharing() is False


# ===========================================================================
# _check_remote_management
# ===========================================================================

class TestCheckRemoteManagement:
    def test_ard_running(self):
        from mactools_macsec.engine import _check_remote_management
        with patch("mactools_macsec.engine.run", return_value=_ok("com.apple.RemoteDesktop.agent")):
            assert _check_remote_management() is True

    def test_ard_not_running(self):
        from mactools_macsec.engine import _check_remote_management
        with patch("mactools_macsec.engine.run", return_value=_fail("Could not find service")):
            assert _check_remote_management() is False


# ===========================================================================
# _check_remote_apple_events
# ===========================================================================

class TestCheckRemoteAppleEvents:
    def test_rae_enabled_stdout(self):
        from mactools_macsec.engine import _check_remote_apple_events
        with patch("mactools_macsec.engine.run", return_value=_ok("Remote Apple Events: on\n")):
            assert _check_remote_apple_events() is True

    def test_rae_enabled_stderr(self):
        from mactools_macsec.engine import _check_remote_apple_events
        with patch("mactools_macsec.engine.run", return_value=RunResult(stdout="", stderr="Remote Apple Events: On", returncode=0, ok=True)):
            assert _check_remote_apple_events() is True

    def test_rae_disabled(self):
        from mactools_macsec.engine import _check_remote_apple_events
        with patch("mactools_macsec.engine.run", return_value=_ok("Remote Apple Events: off\n")):
            assert _check_remote_apple_events() is False

    def test_rae_command_fails(self):
        from mactools_macsec.engine import _check_remote_apple_events
        with patch("mactools_macsec.engine.run", return_value=_fail("not available")):
            assert _check_remote_apple_events() is False


# ===========================================================================
# audit_security — all checks passing (fully hardened)
# ===========================================================================

class TestAuditSecurityAllPass:
    def _run_audit(self, ssh_stdout="Remote Login: Off\n", screen_on=False, ard_on=False, auto_login=False, rae_on=False):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=True, details="enabled")), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True, details="FileVault is On.")), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=True)), \
             patch("mactools_macsec.engine.run", return_value=_ok(ssh_stdout)), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=screen_on), \
             patch("mactools_macsec.engine._check_remote_management", return_value=ard_on), \
             patch("mactools_macsec.engine._check_auto_login", return_value=auto_login), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=rae_on):
            return audit_security()

    def test_returns_list(self):
        findings = self._run_audit()
        assert isinstance(findings, list)

    def test_no_critical_findings_when_fully_hardened(self):
        findings = self._run_audit()
        criticals = [f for f in findings if f.severity == "critical"]
        assert criticals == []

    def test_no_warnings_when_fully_hardened(self):
        findings = self._run_audit()
        warnings = [f for f in findings if f.severity == "warning"]
        assert warnings == []

    def test_sip_ok_finding(self):
        findings = self._run_audit()
        sip = next(f for f in findings if f.category == "SIP")
        assert sip.severity == "ok"
        assert "enabled" in sip.detail.lower()

    def test_gatekeeper_ok_finding(self):
        findings = self._run_audit()
        gk = next(f for f in findings if f.category == "Gatekeeper")
        assert gk.severity == "ok"

    def test_filevault_ok_finding(self):
        findings = self._run_audit()
        fv = next(f for f in findings if f.category == "FileVault")
        assert fv.severity == "ok"
        assert "FileVault is On." in fv.detail

    def test_firewall_ok_finding(self):
        findings = self._run_audit()
        fw_findings = [f for f in findings if f.category == "Firewall"]
        assert any(f.severity == "ok" for f in fw_findings)

    def test_firewall_stealth_ok_finding(self):
        findings = self._run_audit()
        stealth = next((f for f in findings if "stealth" in f.title.lower()), None)
        assert stealth is not None
        assert stealth.severity == "ok"

    def test_ssh_ok_when_off(self):
        findings = self._run_audit(ssh_stdout="Remote Login: Off\n")
        ssh = next(f for f in findings if "SSH" in f.title or "Remote Login" in f.title)
        assert ssh.severity == "ok"

    def test_all_findings_have_category(self):
        findings = self._run_audit()
        for f in findings:
            assert f.category != "", f"Missing category on: {f.title}"


# ===========================================================================
# audit_security — all checks failing (worst-case)
# ===========================================================================

class TestAuditSecurityAllFail:
    def _run_audit_all_bad(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=False, details="disabled")), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=False)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=False)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=False, stealth=False, mode="off")), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: on\n")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=True), \
             patch("mactools_macsec.engine._check_remote_management", return_value=True), \
             patch("mactools_macsec.engine._check_auto_login", return_value=True), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=True):
            return audit_security()

    def test_sip_disabled_is_critical(self):
        findings = self._run_audit_all_bad()
        sip = next(f for f in findings if f.category == "SIP")
        assert sip.severity == "critical"
        assert "disabled" in sip.title.lower()

    def test_sip_fix_command_present(self):
        findings = self._run_audit_all_bad()
        sip = next(f for f in findings if f.category == "SIP")
        assert "csrutil enable" in sip.fix_command

    def test_gatekeeper_disabled_is_critical(self):
        findings = self._run_audit_all_bad()
        gk = next(f for f in findings if f.category == "Gatekeeper")
        assert gk.severity == "critical"
        assert "spctl --master-enable" in gk.fix_command

    def test_filevault_disabled_is_critical(self):
        findings = self._run_audit_all_bad()
        fv = next(f for f in findings if f.category == "FileVault")
        assert fv.severity == "critical"
        assert "fdesetup enable" in fv.fix_command

    def test_firewall_disabled_is_critical(self):
        findings = self._run_audit_all_bad()
        fw = next(f for f in findings if f.category == "Firewall" and "disabled" in f.title.lower())
        assert fw.severity == "critical"
        assert "socketfilterfw" in fw.fix_command

    def test_no_stealth_finding_when_firewall_off(self):
        """Stealth mode finding only appears when firewall is enabled."""
        findings = self._run_audit_all_bad()
        stealth = [f for f in findings if "stealth" in f.title.lower()]
        assert stealth == []

    def test_ssh_on_is_warning(self):
        findings = self._run_audit_all_bad()
        ssh = next(f for f in findings if "SSH" in f.title or "Remote Login" in f.title)
        assert ssh.severity == "warning"
        assert "systemsetup -setremotelogin off" in ssh.fix_command

    def test_screen_sharing_on_is_warning(self):
        findings = self._run_audit_all_bad()
        ss = next(f for f in findings if "Screen Sharing" in f.title and f.severity == "warning")
        assert "launchctl disable" in ss.fix_command

    def test_ard_on_is_warning(self):
        findings = self._run_audit_all_bad()
        ard = next(f for f in findings if "Remote Management" in f.title and f.severity == "warning")
        assert "kickstart" in ard.fix_command

    def test_auto_login_on_is_critical(self):
        findings = self._run_audit_all_bad()
        al = next(f for f in findings if "Auto-login" in f.title and f.severity == "critical")
        assert "autoLoginUser" in al.fix_command

    def test_remote_apple_events_on_is_warning(self):
        findings = self._run_audit_all_bad()
        rae = next(f for f in findings if "Remote Apple Events" in f.title and f.severity == "warning")
        assert "setremoteappleevents off" in rae.fix_command

    def test_sip_detail_includes_details_field(self):
        findings = self._run_audit_all_bad()
        sip = next(f for f in findings if f.category == "SIP")
        assert "disabled" in sip.detail


# ===========================================================================
# audit_security — mixed states
# ===========================================================================

class TestAuditSecurityMixed:
    def test_firewall_enabled_no_stealth_yields_warning(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=False, mode="on")), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: Off")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=False), \
             patch("mactools_macsec.engine._check_remote_management", return_value=False), \
             patch("mactools_macsec.engine._check_auto_login", return_value=False), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=False):
            findings = audit_security()
        stealth = next(f for f in findings if "stealth" in f.title.lower())
        assert stealth.severity == "warning"
        assert "socketfilterfw --setstealthmode on" in stealth.fix_command

    def test_remote_apple_events_off_not_in_findings(self):
        """When RAE is off, no finding is emitted for it (it's the expected state)."""
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=True)), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: Off")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=False), \
             patch("mactools_macsec.engine._check_remote_management", return_value=False), \
             patch("mactools_macsec.engine._check_auto_login", return_value=False), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=False):
            findings = audit_security()
        rae = [f for f in findings if "Remote Apple Events" in f.title]
        assert rae == []

    def test_sip_disabled_detail_includes_sip_details(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=False, details="Custom SIP detail")), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=True)), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: Off")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=False), \
             patch("mactools_macsec.engine._check_remote_management", return_value=False), \
             patch("mactools_macsec.engine._check_auto_login", return_value=False), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=False):
            findings = audit_security()
        sip = next(f for f in findings if f.category == "SIP")
        assert "Custom SIP detail" in sip.detail

    def test_firewall_mode_included_in_ok_detail(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=True, mode="limit")), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: Off")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=False), \
             patch("mactools_macsec.engine._check_remote_management", return_value=False), \
             patch("mactools_macsec.engine._check_auto_login", return_value=False), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=False):
            findings = audit_security()
        fw = next(f for f in findings if f.category == "Firewall" and f.severity == "ok")
        assert "limit" in fw.detail


# ===========================================================================
# compute_security_score — all ok
# ===========================================================================

class TestComputeSecurityScoreAllOk:
    def _make_findings(self, categories, severity="ok"):
        from mactools_macsec.engine import SecurityFinding
        return [
            SecurityFinding(title=f"{cat} check", severity=severity, detail="", category=cat)
            for cat in categories
        ]

    def test_perfect_score_when_all_ok(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        # One ok finding per scored category
        findings = [
            SecurityFinding(title="SIP", severity="ok", detail="", category="SIP"),
            SecurityFinding(title="GK", severity="ok", detail="", category="Gatekeeper"),
            SecurityFinding(title="FV", severity="ok", detail="", category="FileVault"),
            SecurityFinding(title="FW", severity="ok", detail="", category="Firewall"),
            SecurityFinding(title="Stealth", severity="ok", detail="Stealth mode", category="Firewall"),
            SecurityFinding(title="Remote", severity="ok", detail="", category="Remote"),
            SecurityFinding(title="Auth", severity="ok", detail="", category="Auth"),
        ]
        result = compute_security_score(findings)
        assert result["score"] == 100
        assert result["max"] == 100
        assert result["percent"] == 100

    def test_returns_breakdown_dict(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="SIP", severity="ok", detail="", category="SIP"),
        ]
        result = compute_security_score(findings)
        assert "breakdown" in result
        assert isinstance(result["breakdown"], dict)

    def test_breakdown_has_all_categories(self):
        from mactools_macsec.engine import compute_security_score
        result = compute_security_score([])
        expected_cats = {"SIP", "Gatekeeper", "FileVault", "Firewall", "Remote", "Stealth", "Auth"}
        assert set(result["breakdown"].keys()) == expected_cats

    def test_breakdown_entry_has_weight_severity_earned(self):
        from mactools_macsec.engine import compute_security_score
        result = compute_security_score([])
        for cat, entry in result["breakdown"].items():
            assert "weight" in entry, f"Missing 'weight' in {cat}"
            assert "severity" in entry, f"Missing 'severity' in {cat}"
            assert "earned" in entry, f"Missing 'earned' in {cat}"


# ===========================================================================
# compute_security_score — all critical
# ===========================================================================

class TestComputeSecurityScoreAllCritical:
    def test_zero_score_when_all_critical(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="SIP disabled", severity="critical", detail="", category="SIP"),
            SecurityFinding(title="GK disabled", severity="critical", detail="", category="Gatekeeper"),
            SecurityFinding(title="FV disabled", severity="critical", detail="", category="FileVault"),
            SecurityFinding(title="FW disabled", severity="critical", detail="", category="Firewall"),
            SecurityFinding(title="Auth fail", severity="critical", detail="", category="Auth"),
        ]
        result = compute_security_score(findings)
        # Missing Remote and Stealth → defaults to "ok" (no penalty)
        # The explicitly critical ones should reduce score significantly
        assert result["score"] < 50

    def test_critical_category_earns_zero(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="SIP disabled", severity="critical", detail="", category="SIP"),
        ]
        result = compute_security_score(findings)
        assert result["breakdown"]["SIP"]["earned"] == 0.0
        assert result["breakdown"]["SIP"]["severity"] == "critical"

    def test_all_categories_critical_score_is_zero(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="X", severity="critical", detail="", category="SIP"),
            SecurityFinding(title="X", severity="critical", detail="", category="Gatekeeper"),
            SecurityFinding(title="X", severity="critical", detail="", category="FileVault"),
            SecurityFinding(title="X", severity="critical", detail="", category="Firewall"),
            SecurityFinding(title="X", severity="critical", detail="", category="Stealth"),
            SecurityFinding(title="X", severity="critical", detail="", category="Remote"),
            SecurityFinding(title="X", severity="critical", detail="", category="Auth"),
        ]
        result = compute_security_score(findings)
        assert result["score"] == 0


# ===========================================================================
# compute_security_score — warning severity
# ===========================================================================

class TestComputeSecurityScoreWarnings:
    def test_warning_gives_half_penalty(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="Remote SSH on", severity="warning", detail="", category="Remote"),
        ]
        result = compute_security_score(findings)
        remote = result["breakdown"]["Remote"]
        assert remote["severity"] == "warning"
        expected_earned = remote["weight"] * 0.5
        assert remote["earned"] == round(expected_earned, 1)

    def test_warning_score_between_zero_and_perfect(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        # All ok except one warning
        findings = [
            SecurityFinding(title="SIP", severity="ok", detail="", category="SIP"),
            SecurityFinding(title="GK", severity="ok", detail="", category="Gatekeeper"),
            SecurityFinding(title="FV", severity="ok", detail="", category="FileVault"),
            SecurityFinding(title="FW", severity="ok", detail="", category="Firewall"),
            SecurityFinding(title="Stealth", severity="ok", detail="stealth mode", category="Firewall"),
            SecurityFinding(title="Remote SSH", severity="warning", detail="", category="Remote"),
            SecurityFinding(title="Auth", severity="ok", detail="", category="Auth"),
        ]
        result = compute_security_score(findings)
        assert 0 < result["score"] < 100


# ===========================================================================
# compute_security_score — stealth mode sub-category routing
# ===========================================================================

class TestComputeSecurityScoreStealthRouting:
    def test_stealth_finding_routed_to_stealth_category(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        # A Firewall-category finding whose title contains "stealth" → routed to "Stealth"
        findings = [
            SecurityFinding(
                title="Firewall stealth mode disabled",
                severity="warning",
                detail="",
                category="Firewall",
            ),
        ]
        result = compute_security_score(findings)
        # Stealth category should reflect the warning
        assert result["breakdown"]["Stealth"]["severity"] == "warning"
        # Main Firewall category should still be "ok" (no other Firewall findings)
        assert result["breakdown"]["Firewall"]["severity"] == "ok"

    def test_non_stealth_firewall_finding_stays_in_firewall(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="Firewall disabled", severity="critical", detail="", category="Firewall"),
        ]
        result = compute_security_score(findings)
        assert result["breakdown"]["Firewall"]["severity"] == "critical"
        # Stealth not mentioned → defaults to ok
        assert result["breakdown"]["Stealth"]["severity"] == "ok"


# ===========================================================================
# compute_security_score — worst severity wins per category
# ===========================================================================

class TestComputeSecurityScoreWorstSeverityWins:
    def test_critical_beats_ok_in_same_category(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="Remote ok", severity="ok", detail="", category="Remote"),
            SecurityFinding(title="Remote bad", severity="critical", detail="", category="Remote"),
        ]
        result = compute_security_score(findings)
        assert result["breakdown"]["Remote"]["severity"] == "critical"

    def test_warning_beats_ok_in_same_category(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="SSH ok", severity="ok", detail="", category="Remote"),
            SecurityFinding(title="Screen Sharing on", severity="warning", detail="", category="Remote"),
        ]
        result = compute_security_score(findings)
        assert result["breakdown"]["Remote"]["severity"] == "warning"

    def test_critical_beats_warning(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="A", severity="warning", detail="", category="Auth"),
            SecurityFinding(title="B", severity="critical", detail="", category="Auth"),
        ]
        result = compute_security_score(findings)
        assert result["breakdown"]["Auth"]["severity"] == "critical"


# ===========================================================================
# compute_security_score — findings with empty category are ignored
# ===========================================================================

class TestComputeSecurityScoreIgnoresUncategorized:
    def test_no_category_finding_does_not_affect_score(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        # All defaults → perfect score
        perfect_findings: list = []
        score_baseline = compute_security_score(perfect_findings)["score"]

        # Add a critical finding with no category
        findings_with_uncategorized = [
            SecurityFinding(title="Uncategorized critical", severity="critical", detail="", category=""),
        ]
        result = compute_security_score(findings_with_uncategorized)
        assert result["score"] == score_baseline


# ===========================================================================
# compute_security_score — empty findings list
# ===========================================================================

class TestComputeSecurityScoreEmpty:
    def test_empty_findings_returns_perfect_score(self):
        from mactools_macsec.engine import compute_security_score
        result = compute_security_score([])
        assert result["score"] == 100

    def test_empty_findings_all_categories_ok(self):
        from mactools_macsec.engine import compute_security_score
        result = compute_security_score([])
        for cat, entry in result["breakdown"].items():
            assert entry["severity"] == "ok", f"{cat} should be ok when no findings"

    def test_score_structure_always_present(self):
        from mactools_macsec.engine import compute_security_score
        result = compute_security_score([])
        assert "score" in result
        assert "max" in result
        assert "percent" in result
        assert "breakdown" in result

    def test_score_equals_percent(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="SIP disabled", severity="critical", detail="", category="SIP"),
        ]
        result = compute_security_score(findings)
        assert result["score"] == result["percent"]


# ===========================================================================
# compute_security_score — weight totals to 100
# ===========================================================================

class TestComputeSecurityScoreWeights:
    def test_weights_sum_to_100(self):
        from mactools_macsec.engine import _WEIGHTS
        assert sum(_WEIGHTS.values()) == 100

    def test_info_severity_no_penalty(self):
        from mactools_macsec.engine import compute_security_score, SecurityFinding
        findings = [
            SecurityFinding(title="Info finding", severity="info", detail="", category="SIP"),
        ]
        result = compute_security_score(findings)
        # info has 0.0 penalty, so SIP earns its full weight
        sip_weight = result["breakdown"]["SIP"]["weight"]
        assert result["breakdown"]["SIP"]["earned"] == sip_weight


# ===========================================================================
# Integration: audit + score pipeline
# ===========================================================================

class TestAuditThenScorePipeline:
    def _audit_with_all_secure(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=True, details="enabled")), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=True)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=True, details="On")), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=True, stealth=True)), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: Off")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=False), \
             patch("mactools_macsec.engine._check_remote_management", return_value=False), \
             patch("mactools_macsec.engine._check_auto_login", return_value=False), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=False):
            return audit_security()

    def _audit_with_all_bad(self):
        from mactools_macsec.engine import audit_security
        with patch("mactools_macsec.engine.get_sip_status", return_value=SIPStatus(enabled=False, details="disabled")), \
             patch("mactools_macsec.engine.get_gatekeeper_status", return_value=GatekeeperStatus(enabled=False)), \
             patch("mactools_macsec.engine.get_filevault_status", return_value=FileVaultStatus(enabled=False)), \
             patch("mactools_macsec.engine.get_firewall", return_value=_fw(enabled=False, stealth=False, mode="off")), \
             patch("mactools_macsec.engine.run", return_value=_ok("Remote Login: on")), \
             patch("mactools_macsec.engine._check_screen_sharing", return_value=True), \
             patch("mactools_macsec.engine._check_remote_management", return_value=True), \
             patch("mactools_macsec.engine._check_auto_login", return_value=True), \
             patch("mactools_macsec.engine._check_remote_apple_events", return_value=True):
            return audit_security()

    def test_secure_audit_yields_perfect_score(self):
        from mactools_macsec.engine import compute_security_score
        findings = self._audit_with_all_secure()
        result = compute_security_score(findings)
        assert result["score"] == 100

    def test_insecure_audit_yields_low_score(self):
        from mactools_macsec.engine import compute_security_score
        findings = self._audit_with_all_bad()
        result = compute_security_score(findings)
        assert result["score"] < 50

    def test_findings_as_dict_serializable(self):
        """All findings can be serialized via as_dict without error."""
        import json
        findings = self._audit_with_all_secure()
        dicts = [f.as_dict() for f in findings]
        # Should not raise
        serialized = json.dumps(dicts)
        assert len(serialized) > 0
