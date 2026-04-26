"""opsmac CLI — holistic Mac health assessment."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

import click

from mactools_core.output import color, severity_icon, print_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_badge(score: int) -> str:
    if score >= 85:
        return color(f"{score}/100", "ok")
    elif score >= 65:
        return color(f"{score}/100", "warning")
    else:
        return color(f"{score}/100", "critical")


def _status_badge(ok: bool, warn: bool = False) -> str:
    if ok and not warn:
        return color("[OK]", "ok")
    elif warn:
        return color("[--]", "info")
    else:
        return color("[!!]", "warning")


def _fmt_bytes(b: int) -> str:
    if b >= 1e12:
        return f"{b / 1e12:.1f}TB"
    if b >= 1e9:
        return f"{b / 1e9:.1f}GB"
    if b >= 1e6:
        return f"{b / 1e6:.1f}MB"
    return f"{b}B"


def _print_findings(findings: list[dict]) -> None:
    if not findings:
        print(color("  No findings.", "ok"))
        return
    for f in findings:
        sev = f.get("severity", "info")
        icon = severity_icon(sev)
        title = f.get("title", "")
        detail = f.get("detail", "")
        if sev in ("critical", "warning"):
            icon_str = f"[{color(icon, sev)}]"
        elif sev == "info":
            icon_str = f"[{color(icon, 'info')}]"
        else:
            icon_str = f"[{color(icon, 'ok')}]"
        print(f"  {icon_str} {title}")
        if detail:
            print(f"       {color(detail, 'dim')}")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """opsmac — holistic Mac health assessment."""
    pass


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--analyze", is_flag=True, help="AI-powered analysis and recommendations")
def health(as_json: bool, analyze: bool):
    """Full health report: hardware, storage, security, power, network."""
    from mactools_opsmac.engine import collect_health_data, compute_score_breakdown

    report = collect_health_data()

    if as_json:
        breakdown = compute_score_breakdown(report)
        data = {
            "hardware": {
                "model": report.hardware.model,
                "chip": report.hardware.chip,
                "memory_gb": report.hardware.memory_gb,
                "os_version": report.hardware.os_version,
                "hostname": report.hardware.hostname,
            },
            "storage": {
                "total_gb": round(report.storage.total_gb, 1),
                "free_gb": round(report.storage.free_gb, 1),
                "used_pct": round(report.storage.used_pct, 1),
                "smart_status": report.storage.smart_status,
            },
            "security": {
                "sip_enabled": report.security.sip.enabled,
                "gatekeeper_enabled": report.security.gatekeeper.enabled,
                "filevault_enabled": report.security.filevault.enabled,
                "firewall_enabled": report.security.firewall_enabled,
                "firewall_stealth": report.security.firewall_stealth,
                "remote_login": report.security.remote_login,
            },
            "power": {
                "sleep_preventers": len(report.sleep_preventers),
                "thermal_level": report.thermal.level,
                "cpu_speed_limit": report.thermal.cpu_speed_limit,
            },
            "services": asdict(report.services),
            "network": asdict(report.network),
            "score": breakdown,
            "findings": report.findings,
        }
        print_json(data)
        if analyze:
            _ai_health_analysis(report)
        return

    # Human-readable summary
    hw = report.hardware
    st = report.storage
    sec = report.security
    fw = report.firewall
    preventers = report.sleep_preventers
    score = report.score or 0

    hostname = hw.hostname or hw.model or "Mac"
    print()
    print(color(f"  opsmac health report — {hostname}", "info"))
    print()

    # Hardware line
    mem = f"{hw.memory_gb}GB" if hw.memory_gb else "?GB"
    os_ver = hw.os_version or ""
    hw_label = f"{hw.model} {hw.chip} / {mem}"
    if os_ver:
        hw_label += f" / {os_ver}"
    thermal_warn = report.thermal.level != "nominal"
    hw_badge = _status_badge(not thermal_warn)
    print(f"  {'Hardware:':<12} {hw_label:<45} {hw_badge}")

    # Storage line
    if st.total_bytes:
        used_pct = round(st.used_pct)
        st_label = f"{_fmt_bytes(st.free_bytes)} free / {_fmt_bytes(st.total_bytes)} ({used_pct}% used)"
        if st.smart_status.lower() not in ("", "unknown"):
            st_label += f" SMART:{st.smart_status}"
        st_ok = used_pct < 85 and st.smart_status.upper() not in ("FAILED", "FAILING")
        st_badge = _status_badge(st_ok)
    else:
        st_label = "unavailable"
        st_badge = _status_badge(False)
    print(f"  {'Storage:':<12} {st_label:<45} {st_badge}")

    # Security line
    sip_icon = color("SIP ✓", "ok") if sec.sip.enabled else color("SIP ✗", "critical")
    gk_icon = color("GK ✓", "ok") if sec.gatekeeper.enabled else color("GK ✗", "warning")
    fv_icon = color("FV ✓", "ok") if sec.filevault.enabled else color("FV ✗", "warning")
    if fw.enabled and fw.block_all:
        fw_str = color("FW: BLOCK-ALL", "ok")
    elif fw.enabled and fw.stealth:
        fw_str = color("FW: STEALTH", "ok")
    elif fw.enabled:
        fw_str = color("FW: ON", "ok")
    else:
        fw_str = color("FW: OFF", "warning")
    sec_label = f"{sip_icon} | {gk_icon} | {fv_icon} | {fw_str}"
    sec_ok = sec.sip.enabled and sec.gatekeeper.enabled
    sec_warn = not sec.filevault.enabled or not fw.enabled
    if not sec_ok:
        sec_badge = color("[!!]", "critical")
    elif sec_warn:
        sec_badge = color("[!!]", "warning")
    else:
        sec_badge = color("[OK]", "ok")
    # sec_label has ANSI codes so can't ljust reliably — print without padding
    print(f"  {'Security:':<12} {sec_label}")
    print(f"  {'':<12} {'':45} {sec_badge}")

    # Power line
    n_prev = len(preventers)
    if n_prev == 0:
        pw_label = "No sleep preventers"
        pw_badge = color("[OK]", "ok")
    elif n_prev == 1:
        pw_label = f"1 sleep preventer ({preventers[0].name})"
        pw_badge = color("[--]", "info")
    else:
        names = ", ".join(p.name for p in preventers[:2])
        pw_label = f"{n_prev} sleep preventers ({names}{'...' if n_prev > 2 else ''})"
        pw_badge = color("[--]", "info")
    if report.thermal.level != "nominal":
        pw_label += f" | Thermal: {report.thermal.level}"
        pw_badge = color("[!!]", "warning")
    print(f"  {'Power:':<12} {pw_label:<45} {pw_badge}")

    # Score line
    print(f"  {'Score:':<12} {_score_badge(score)}")
    print()

    # Findings
    if report.findings:
        print(color("  Findings:", "info"))
        _print_findings(report.findings)
        print()

    if analyze:
        _ai_health_analysis(report)


# ---------------------------------------------------------------------------
# hardware
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def hardware(as_json: bool):
    """Hardware summary: model, chip, memory, macOS version."""
    from mactools_core.system_profiler import get_hardware
    from mactools_opsmac.engine import collect_health_data

    hw = get_hardware()

    if as_json:
        print_json({
            "model": hw.model,
            "chip": hw.chip,
            "cores_total": hw.cores_total,
            "cores_performance": hw.cores_performance,
            "cores_efficiency": hw.cores_efficiency,
            "memory_gb": hw.memory_gb,
            "serial": hw.serial,
            "os_version": hw.os_version,
            "hostname": hw.hostname,
        })
        return

    print()
    print(color("  Hardware Summary", "info"))
    print()
    rows = [
        ("Model",       hw.model or "—"),
        ("Chip",        hw.chip or "—"),
        ("Cores",       f"{hw.cores_total} total"
                        + (f" ({hw.cores_performance}P + {hw.cores_efficiency}E)"
                           if hw.cores_performance else "")),
        ("Memory",      f"{hw.memory_gb} GB" if hw.memory_gb else "—"),
        ("macOS",       hw.os_version or "—"),
        ("Hostname",    hw.hostname or "—"),
        ("Serial",      hw.serial or "—"),
    ]
    for label, value in rows:
        print(f"  {color(label + ':', 'dim'):<20} {value}")
    print()


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def storage(as_json: bool):
    """Storage report: APFS volumes, capacity, SMART status."""
    from mactools_core.diskutil import list_apfs_containers, list_disks, get_smart_status
    from mactools_core.system_profiler import get_storage

    volumes = get_storage()
    containers = list_apfs_containers()
    disks = list_disks()
    smart = "unknown"
    if disks:
        first = next((d for d in disks if d.internal), disks[0])
        smart = get_smart_status(first.identifier)

    if as_json:
        print_json({
            "volumes": [
                {
                    "name": v.name,
                    "mount_point": v.mount_point,
                    "filesystem": v.filesystem,
                    "size_gb": round(v.size_bytes / 1e9, 1),
                    "free_gb": round(v.free_bytes / 1e9, 1),
                    "used_pct": round((v.size_bytes - v.free_bytes) / v.size_bytes * 100, 1)
                                if v.size_bytes else 0,
                    "writable": v.writable,
                    "encrypted": v.encrypted,
                }
                for v in volumes
            ],
            "apfs_containers": [
                {
                    "identifier": c.identifier,
                    "capacity_gb": round(c.capacity_bytes / 1e9, 1),
                    "free_gb": round(c.free_bytes / 1e9, 1),
                    "volumes": [
                        {
                            "name": v.name,
                            "identifier": v.identifier,
                            "role": v.role,
                            "used_gb": round(v.used_bytes / 1e9, 1),
                            "encrypted": v.encrypted,
                            "mounted": v.mounted,
                            "mount_point": v.mount_point,
                        }
                        for v in c.volumes
                    ],
                }
                for c in containers
            ],
            "disks": [
                {
                    "identifier": d.identifier,
                    "name": d.name,
                    "size_gb": round(d.size_bytes / 1e9, 1),
                    "protocol": d.protocol,
                    "internal": d.internal,
                    "smart_status": d.smart_status,
                }
                for d in disks
            ],
            "smart_status": smart,
        })
        return

    print()
    print(color("  Storage Report", "info"))
    print()

    # Volumes from system_profiler
    for v in volumes:
        if v.size_bytes == 0:
            continue
        used = v.size_bytes - v.free_bytes
        pct = round(used / v.size_bytes * 100)
        bar_width = 20
        filled = round(bar_width * pct / 100)
        bar_color = "ok" if pct < 70 else "warning" if pct < 85 else "critical"
        bar = color("█" * filled, bar_color) + color("░" * (bar_width - filled), "dim")
        enc = color(" [encrypted]", "ok") if v.encrypted else ""
        label = f"{v.name or v.mount_point}"
        print(f"  {color(label, 'info')}")
        print(f"    {bar} {pct}%  {_fmt_bytes(v.free_bytes)} free of {_fmt_bytes(v.size_bytes)}{enc}")
        print()

    # APFS containers
    if containers:
        print(color("  APFS Containers:", "dim"))
        for c in containers:
            pct = round((c.capacity_bytes - c.free_bytes) / c.capacity_bytes * 100) if c.capacity_bytes else 0
            print(f"  {c.identifier}  {_fmt_bytes(c.capacity_bytes)} total, {_fmt_bytes(c.free_bytes)} free ({pct}% used)")
            for v in c.volumes:
                role = f" [{v.role}]" if v.role else ""
                mp = f" → {v.mount_point}" if v.mount_point else ""
                enc = color(" enc", "ok") if v.encrypted else ""
                print(f"    {color('·', 'dim')} {v.name or v.identifier}{role}{mp}  {_fmt_bytes(v.used_bytes)} used{enc}")
        print()

    # SMART status
    smart_color = "ok" if smart.upper() in ("PASSED", "OK", "VERIFIED") else \
                  "critical" if smart.upper() in ("FAILED", "FAILING") else "dim"
    print(f"  {'SMART Status:':<18} {color(smart, smart_color)}")
    print()


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--analyze", is_flag=True, help="AI-powered security analysis")
def security(as_json: bool, analyze: bool):
    """Security posture: SIP, Gatekeeper, FileVault, firewall, remote access."""
    from mactools_core.security import get_security_posture
    from mactools_core.system_profiler import get_firewall

    posture = get_security_posture()
    fw = get_firewall()

    if as_json:
        data = {
            "sip": {"enabled": posture.sip.enabled, "details": posture.sip.details},
            "gatekeeper": {"enabled": posture.gatekeeper.enabled, "details": posture.gatekeeper.details},
            "filevault": {"enabled": posture.filevault.enabled, "details": posture.filevault.details},
            "firewall": {
                "enabled": fw.enabled,
                "mode": fw.mode,
                "stealth": fw.stealth,
                "block_all": fw.block_all,
                "allow_signed": fw.allow_signed,
                "allowed_apps_count": len(fw.allowed_apps),
            },
            "remote_login": posture.remote_login,
        }
        print_json(data)
        if analyze:
            _ai_security_analysis(posture, fw)
        return

    print()
    print(color("  Security Posture", "info"))
    print()

    checks = [
        ("SIP",         posture.sip.enabled,         posture.sip.details.split("\n")[0]),
        ("Gatekeeper",  posture.gatekeeper.enabled,   posture.gatekeeper.details.split("\n")[0]),
        ("FileVault",   posture.filevault.enabled,    posture.filevault.details.split("\n")[0]),
        ("Firewall",    fw.enabled,                   _fw_detail(fw)),
        ("Remote Login",not posture.remote_login,     "SSH disabled" if not posture.remote_login else "SSH enabled"),
    ]

    for label, ok, detail in checks:
        icon = color("✓", "ok") if ok else color("✗", "warning" if label != "SIP" else "critical")
        badge = color("[OK]", "ok") if ok else color("[!!]", "warning" if label != "SIP" else "critical")
        print(f"  {icon} {color(label + ':', 'dim'):<22} {detail:<40} {badge}")

    if fw.enabled:
        extra = []
        if fw.stealth:
            extra.append(color("stealth mode on", "ok"))
        if fw.block_all:
            extra.append(color("block all", "ok"))
        if fw.allow_signed:
            extra.append("allow signed apps")
        if fw.allowed_apps:
            extra.append(f"{len(fw.allowed_apps)} app rules")
        if extra:
            print(f"  {'':3} {'Firewall details:':<22} {', '.join(extra)}")

    print()

    # Summary
    issues = [label for label, ok, _ in checks if not ok]
    if not issues:
        print(color("  All security checks passed.", "ok"))
    else:
        print(color(f"  {len(issues)} issue(s) found: {', '.join(issues)}", "warning"))
    print()

    if analyze:
        _ai_security_analysis(posture, fw)


def _fw_detail(fw) -> str:
    if not fw.enabled:
        return "disabled"
    if fw.block_all:
        return "block all incoming"
    if fw.stealth:
        return "on (stealth mode)"
    return "on"


# ---------------------------------------------------------------------------
# power
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def power(as_json: bool):
    """Power settings, sleep preventers, and thermal state."""
    from mactools_core.power import get_power_settings, get_sleep_preventers, get_thermal_state, get_scheduled_events

    settings = get_power_settings()
    preventers = get_sleep_preventers()
    thermal = get_thermal_state()
    scheduled = get_scheduled_events()

    if as_json:
        print_json({
            "settings": {
                "sleep_timer": settings.sleep_timer,
                "display_sleep": settings.display_sleep,
                "disk_sleep": settings.disk_sleep,
                "wake_on_lan": settings.wake_on_lan,
                "power_nap": settings.power_nap,
            },
            "sleep_preventers": [
                {
                    "name": p.name,
                    "pid": p.pid,
                    "assertion_type": p.assertion_type,
                    "detail": p.detail,
                }
                for p in preventers
            ],
            "thermal": {
                "level": thermal.level,
                "cpu_speed_limit": thermal.cpu_speed_limit,
            },
            "scheduled_events": [
                {"type": e.event_type, "time": e.time, "owner": e.owner}
                for e in scheduled
            ],
        })
        return

    print()
    print(color("  Power Report", "info"))
    print()

    # Thermal
    thermal_color = "ok" if thermal.level == "nominal" else \
                    "warning" if thermal.level == "throttled" else "critical"
    print(f"  {color('Thermal State:', 'dim'):<22} {color(thermal.level, thermal_color)}", end="")
    if thermal.cpu_speed_limit < 100:
        print(f"  (CPU at {thermal.cpu_speed_limit}%)", end="")
    print()
    print()

    # Power settings
    print(color("  Power Settings:", "dim"))
    ps_rows = [
        ("System sleep",   f"{settings.sleep_timer} min" if settings.sleep_timer else "never"),
        ("Display sleep",  f"{settings.display_sleep} min" if settings.display_sleep else "never"),
        ("Disk sleep",     f"{settings.disk_sleep} min" if settings.disk_sleep else "never"),
        ("Wake on LAN",    "on" if settings.wake_on_lan else "off"),
        ("Power Nap",      "on" if settings.power_nap else "off"),
    ]
    for label, val in ps_rows:
        print(f"  {color(label + ':', 'dim'):<24} {val}")
    print()

    # Sleep preventers
    if preventers:
        print(color(f"  Sleep Preventers ({len(preventers)}):", "dim"))
        for p in preventers:
            print(f"  {color('·', 'dim')} {color(p.name, 'warning')} (pid {p.pid})"
                  f"  {p.assertion_type}")
            if p.detail:
                print(f"    {color(p.detail, 'dim')}")
    else:
        print(color("  No sleep preventers.", "ok"))
    print()

    # Scheduled events
    if scheduled:
        print(color("  Scheduled Events:", "dim"))
        for e in scheduled:
            owner = f" by {e.owner}" if e.owner else ""
            print(f"  {color('·', 'dim')} {e.event_type} at {e.time}{owner}")
        print()


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def score(as_json: bool):
    """Compute overall health score (0-100) with category breakdowns."""
    from mactools_opsmac.engine import collect_health_data, compute_score_breakdown

    report = collect_health_data()
    breakdown = compute_score_breakdown(report)

    if as_json:
        print_json({
            "score": breakdown["total"],
            "categories": {
                "hardware":  {"score": breakdown["hardware"],  "max": breakdown["hardware_max"]},
                "storage":   {"score": breakdown["storage"],   "max": breakdown["storage_max"]},
                "security":  {"score": breakdown["security"],  "max": breakdown["security_max"]},
                "power":     {"score": breakdown["power"],     "max": breakdown["power_max"]},
                "services":  {"score": breakdown["services"],  "max": breakdown["services_max"]},
            },
            "findings": report.findings,
        })
        return

    total = breakdown["total"]
    print()
    print(color("  Health Score", "info"))
    print()
    print(f"  Overall:  {_score_badge(total)}")
    print()

    categories = [
        ("Hardware",  "hardware",  breakdown["hardware"],  breakdown["hardware_max"]),
        ("Storage",   "storage",   breakdown["storage"],   breakdown["storage_max"]),
        ("Security",  "security",  breakdown["security"],  breakdown["security_max"]),
        ("Power",     "power",     breakdown["power"],     breakdown["power_max"]),
        ("Services",  "services",  breakdown["services"],  breakdown["services_max"]),
    ]

    bar_width = 20
    for label, key, pts, max_pts in categories:
        filled = round(bar_width * pts / max_pts) if max_pts else 0
        pct = pts / max_pts if max_pts else 0
        bar_color = "ok" if pct >= 0.85 else "warning" if pct >= 0.6 else "critical"
        bar = color("█" * filled, bar_color) + color("░" * (bar_width - filled), "dim")
        score_str = f"{pts}/{max_pts}"
        deduction = max_pts - pts
        note = ""
        if deduction > 0:
            # Pull a relevant finding for the category
            cat_findings = [f for f in report.findings if f.get("category") == key]
            if cat_findings:
                note = f"  {color('↳ ' + cat_findings[0]['title'][:60], 'dim')}"
        print(f"  {label:<12} {bar} {score_str:>6}{note}")

    print()

    if report.findings:
        print(color("  Top Issues:", "dim"))
        for f in report.findings[:5]:
            sev = f.get("severity", "info")
            icon = severity_icon(sev)
            print(f"  [{color(icon, sev)}] {f['title']}")
        if len(report.findings) > 5:
            print(f"       {color(f'... and {len(report.findings) - 5} more', 'dim')}")
    print()


# ---------------------------------------------------------------------------
# AI helpers (internal)
# ---------------------------------------------------------------------------

def _ai_health_analysis(report) -> None:
    from mactools_core.ai import analyze
    from mactools_opsmac.ai import HEALTH_ANALYSIS_SYSTEM_PROMPT

    context = _build_health_context(report)
    click.echo()
    click.echo(color("  AI Analysis", "info"))
    click.echo()
    result = analyze(HEALTH_ANALYSIS_SYSTEM_PROMPT, context)
    if result.ok:
        for line in result.text.splitlines():
            click.echo(f"  {line}")
    else:
        click.echo(color(f"  {result.text}", "dim"))
    click.echo()


def _ai_security_analysis(posture, fw) -> None:
    from mactools_core.ai import analyze
    from mactools_opsmac.ai import SECURITY_ANALYSIS_SYSTEM_PROMPT

    context = (
        f"SIP: {'enabled' if posture.sip.enabled else 'DISABLED'}\n"
        f"Gatekeeper: {'enabled' if posture.gatekeeper.enabled else 'DISABLED'}\n"
        f"FileVault: {'enabled' if posture.filevault.enabled else 'DISABLED'}\n"
        f"Firewall: {'enabled' if fw.enabled else 'DISABLED'} "
        f"(stealth={fw.stealth}, block_all={fw.block_all})\n"
        f"Remote Login (SSH): {'enabled' if posture.remote_login else 'disabled'}\n"
    )
    click.echo()
    click.echo(color("  AI Security Analysis", "info"))
    click.echo()
    result = analyze(SECURITY_ANALYSIS_SYSTEM_PROMPT, context)
    if result.ok:
        for line in result.text.splitlines():
            click.echo(f"  {line}")
    else:
        click.echo(color(f"  {result.text}", "dim"))
    click.echo()


def _build_health_context(report) -> str:
    hw = report.hardware
    st = report.storage
    sec = report.security
    fw = report.firewall
    lines = [
        f"Host: {hw.hostname or hw.model}",
        f"Hardware: {hw.model} / {hw.chip} / {hw.memory_gb}GB / {hw.os_version}",
        f"Storage: {st.free_gb:.1f}GB free of {st.total_gb:.1f}GB ({st.used_pct:.0f}% used), SMART: {st.smart_status}",
        f"SIP: {'enabled' if sec.sip.enabled else 'DISABLED'}",
        f"Gatekeeper: {'enabled' if sec.gatekeeper.enabled else 'DISABLED'}",
        f"FileVault: {'enabled' if sec.filevault.enabled else 'DISABLED'}",
        f"Firewall: {'enabled' if fw.enabled else 'DISABLED'} (stealth={fw.stealth}, block_all={fw.block_all})",
        f"Remote Login: {'enabled' if sec.remote_login else 'disabled'}",
        f"Sleep preventers: {len(report.sleep_preventers)} ({', '.join(p.name for p in report.sleep_preventers)})",
        f"Thermal: {report.thermal.level} (CPU limit: {report.thermal.cpu_speed_limit}%)",
        f"Services: {report.services.running} running, {report.services.failed} failed",
        f"Score: {report.score}/100",
        "",
        "Findings:",
    ]
    for f in report.findings:
        lines.append(f"  [{f['severity'].upper()}] {f['title']}: {f.get('detail', '')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cli()
