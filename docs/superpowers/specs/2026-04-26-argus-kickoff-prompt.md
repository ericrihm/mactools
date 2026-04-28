# Argus — Kickoff Prompt

Paste this into a fresh Claude Code session after creating the `argus` repo.

---

## Kickoff Prompt

```
You are bootstrapping Argus — a self-improving autonomic network intelligence system. The full design spec is at docs/superpowers/specs/2026-04-26-argus-design.md (I will provide it).

Argus is a dual-node system:
- SENTINEL (lightweight, runs on a 2015 MacBook) — MQTT broker (Mosquitto), event router, EWMA anomaly detection, decision engine with graduated autonomy, FastAPI+htmx dashboard, SQLite event store
- FORGE (Proxmox VM) — Suricata IDS, OpenCanary honeypot, Isolation Forest ML, Claude deep analysis, self-improvement pipeline (code generation + ephemeral Docker testing + feature branch staging), threat intel aggregation, Proxmox API controller

It consumes existing tools as data feeds (never reimplements them):
- netdiscovery (network sensing, device fingerprinting, CVE correlation — REST API + SQLite)
- mcp-infrastate (host state: containers, services, ports, processes — MCP tools)
- mcp-syslog (log anomalies: bursts, priority shifts, error spikes — MCP tools)
- mactools (macOS security posture, code signing, TCC, disk, thermal — CLI --json)
- orchestrate (lane registry, Telegram approval flow, self-improving classifier — REST/SSE + JSONL)
- interop (system health, system changes, agent routing — MCP tools)
- Wazuh (FIM, auth failures, vulnerabilities — REST API or webhook)

Core loop is MAPE-K (Monitor → Analyze → Plan → Execute → Knowledge) with:
- Event-sourced SQLite store (every observation/decision/action is immutable)
- Graduated autonomy: Tier 0 (notify only) → Tier 1 (auto reversible) → Tier 2 (approval with timeout) → Tier 3 (earned full auto)
- Three-level self-improvement: threshold tuning (continuous), strategy evolution (daily), code self-modification (gated)
- MQTT (Mosquitto) as the nervous system connecting all devices
- Compute delegation via MQTT bid/assign for heavy tasks

Tech stack: Python 3.12+, Mosquitto, SQLite WAL, FastAPI+htmx+Alpine.js, Suricata, OpenCanary, scikit-learn IsolationForest, Claude API (Sonnet routine / Opus complex), Telegram notifications via orchestrate, YAML playbooks + TOML config, Docker on Forge for sandboxing, Git + Proxmox snapshots for rollback.

Start with Phase 1 — Skeleton + MQTT + Event Store:
1. Initialize the repo with pyproject.toml, CLAUDE.md, and the module structure
2. Build argus_core/ — mqtt.py (Mosquitto client wrapper), events.py (SQLite event store with immutable append), config.py (TOML loader), models.py (Device, Incident, Action, TrustScore dataclasses)
3. Build basic argus_sentinel/monitor/heartbeat.py — MQTT heartbeat listener with LWT detection
4. Build argus_agent/heartbeat.py — cross-platform MQTT heartbeat publisher
5. Add tests for core modules
6. Write CLAUDE.md with full project context

Key conventions (match the mactools/ctools ecosystem):
- --json on every CLI command for machine output
- --analyze invokes Claude AI for interpretation
- Pure functions in engine modules, side effects isolated
- Click for CLI, FastAPI for web, paho-mqtt for MQTT
- Never execute destructive commands — print remediation commands, never run them
- Graceful degradation — partial data over crashes
```

## CLAUDE.md Template for Argus Repo

```markdown
# Argus — Self-Improving Autonomic Network Intelligence

Dual-node system (Sentinel + Forge) that coordinates a heterogeneous network through a MAPE-K autonomic loop with graduated autonomy and three-level self-improvement.

## Architecture

Sentinel (2015 laptop) — lightweight coordinator:
- Mosquitto MQTT broker, event router, EWMA anomaly detection
- Decision engine with graduated autonomy (4 tiers)
- FastAPI + htmx dashboard, SQLite event store

Forge (Proxmox VM) — analytical powerhouse:
- Suricata IDS, OpenCanary honeypot, Isolation Forest ML
- Claude deep analysis, self-improvement pipeline
- Threat intel aggregation, Proxmox API controller

## Module Layout

argus_core/       — shared: MQTT, events, config, models
argus_sentinel/   — laptop: monitor, analyze, plan, execute, dashboard
argus_forge/      — Proxmox VM: deep analyze, security, compute, self-improve
argus_agent/      — lightweight device agent: heartbeat, collector, responder
playbooks/        — YAML response playbooks

## Conventions

- `--json` on every command for machine output
- `--analyze` invokes Claude AI for interpretation
- Pure functions in engine modules, side effects isolated in core
- Click for CLI, FastAPI for web, paho-mqtt for MQTT
- Never execute destructive commands — print remediation, never run
- Graceful degradation — partial data over crashes
- Python 3.12+, SQLite WAL mode, TOML config, YAML playbooks

## Key Design Decisions

- Event-sourced: every observation, decision, and action is immutable in SQLite
- Graduated autonomy: per-action-class trust scores, earned through track record
- Self-improvement: threshold tuning (continuous) → strategy evolution (daily) → code self-mod (gated)
- Dual-node with graceful degradation: either node operates independently
- Consumes existing ecosystem (netdiscovery, mactools, mcp-infrastate, mcp-syslog, orchestrate, interop) — never reimplements
- MQTT (Mosquitto) connects all devices; only delegate when benefit > latency cost
- All auto-generated commits tagged [argus-auto]
- Proxmox snapshots before any self-modification promotion

## Running

# Sentinel
argus sentinel start              # start MQTT broker + event loop + dashboard
argus sentinel status             # show connected devices, open incidents, trust scores
argus sentinel incidents          # list open incidents with severity
argus sentinel trust              # show graduated autonomy trust ledger

# Forge
argus forge start                 # start Suricata, OpenCanary, threat intel, compute worker
argus forge analyze               # trigger deep analysis cycle
argus forge improve               # trigger self-improvement cycle (normally daily cron)

# Agent (on managed devices)
argus agent start                 # start heartbeat + collector + responder
argus agent status                # show local metrics and connection state

## Phases

1. Skeleton + MQTT + Event Store (argus_core, heartbeat)
2. Feed Integration (netdiscovery, mcp-infrastate, mcp-syslog, mactools)
3. MAPE-K Monitor + Analyze (EWMA, event bucketing, correlation)
4. Plan + Execute (playbooks, graduated autonomy, Telegram approval)
5. Forge Deployment (Proxmox VM, Suricata, OpenCanary, threat intel)
6. Self-Improvement (threshold tuning, strategy evolution, code self-mod)
7. Dashboard + Polish (web UI, incident timeline, device map)
```
