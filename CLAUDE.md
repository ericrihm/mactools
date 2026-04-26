# mactools — macOS-Native Claude-Powered CLI Suite

12 tools that wrap macOS system CLI tools with Claude AI as the interpretation layer. Part of the ctools ecosystem. macOS (Darwin) only.

## Architecture

```
mactools/
  mactools_core/         — shared macOS platform primitives (11 modules)
    runner.py            — safe subprocess runner + plist parser
    ai.py                — Claude API + CLI fallback
    output.py            — severity coloring, markdown tables, JSON output
    unified_log.py       — log show/stream/stats parser
    system_profiler.py   — all 48 system_profiler data types
    launchctl.py         — service enumeration + plist enrichment
    security.py          — SIP, Gatekeeper, FileVault, codesign, posture
    defaults.py          — preference domains + key search
    network.py           — networksetup, scutil DNS/proxy
    diskutil.py          — APFS containers, volumes, SMART
    power.py             — pmset settings, sleep preventers, thermal
    spotlight.py         — mdutil, mdfind, mdls
    shortcuts.py         — Shortcuts.app CLI
  mactools_opslog/       — Unified Log intelligence
  mactools_opsmac/       — holistic Mac health + scoring
  mactools_maclaunch/    — LaunchAgent/Daemon auditor
  mactools_macsec/       — security posture audit (CIS-style)
  mactools_macsign/      — code signing + entitlement intelligence
  mactools_macprivacy/   — TCC privacy permissions auditor
  mactools_macdefaults/  — defaults system intelligence
  mactools_macnet/       — network configuration intelligence
  mactools_macenergy/    — energy + thermal intelligence
  mactools_macspot/      — Spotlight intelligence
  mactools_macdisk/      — disk + APFS intelligence
  mactools_macshortcuts/ — Shortcuts.app intelligence
```

## Running

```bash
# All tools are pip-installed entry points
opslog triage --last 15m --analyze    # AI-triaged error log
opsmac health                          # full health report with score
opsmac score                           # 0-100 health score breakdown
maclaunch list --third-party           # non-Apple launch services
maclaunch audit --analyze              # security audit with Claude
macsec audit                           # security posture check
macsec score                           # CIS-style security score
macsign check /Applications/App.app   # code signature verification
macsign scan --dir /Applications       # bulk signature scan
macprivacy audit                       # TCC permissions audit
macdefaults audit                      # modified-from-factory settings
macdefaults recommend --analyze        # Claude power-user recommendations
macnet status                          # network overview
macnet diagnose --analyze              # network issue diagnosis
macenergy wake                         # what's preventing sleep
macenergy thermal                      # throttling status
macspot search "PDFs modified this week"  # NL Spotlight search
macdisk status                         # APFS layout + health
macshortcuts suggest "compress all PNGs in Downloads"
```

## Conventions

- `--json` on every command for machine output
- `--analyze` invokes Claude AI for interpretation
- All wrapped tools are macOS builtins (no extra installs needed)
- Python 3.12+, click for CLI, optional anthropic for AI
- Each tool has: cli.py (Click), engine.py (pure logic), ai.py (prompts)

## Key Design Decisions

- Single repo with shared core (mactools_core) — macOS tools share so much infrastructure that separate repos would be wasteful
- Never execute destructive commands — `macsec fix`, `maclaunch disable`, `macprivacy revoke` all PRINT the command, never run it
- Graceful degradation — if a system tool needs elevated privileges, return partial data rather than crash
- Pure functions in engine.py — all side effects (subprocess calls) isolated in mactools_core
