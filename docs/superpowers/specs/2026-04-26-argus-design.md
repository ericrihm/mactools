# Argus — Self-Improving Autonomic Network Intelligence

**Repo:** `argus`
**Date:** 2026-04-26
**Status:** Design approved, ready for implementation planning

---

## Overview

Argus is a dual-node autonomic network intelligence system that coordinates a heterogeneous home/office network (Macs, Linux, Windows, IoT, network appliances, Proxmox VMs). It consumes existing tools (netdiscovery, mactools, mcp-infrastate, mcp-syslog, orchestrate, interop, Wazuh) as data feeds and adds a self-improving MAPE-K decision loop with graduated autonomy.

Named for Argus Panoptes — the all-seeing guardian of Greek mythology.

## Constraints

- **Sentinel** runs on a 2015 laptop (~8-16GB RAM, dual-core). Must stay lightweight.
- **Forge** runs as a Proxmox VM (recommended: 4 vCPU, 8GB RAM, 50GB disk). Has server-class resources but is not unlimited.
- Heavy processing (ML, Claude API, IDS, code generation) runs on Forge or cloud.
- Only integrate systems where the link provides measurable benefit.
- Self-modification must be safe, auditable, and rollback-capable.

## Dual-Node Architecture

### Sentinel (2015 Laptop) — Fast-Path Coordinator

Responsibilities:
- Mosquitto MQTT broker (~4MB RAM) — the nervous system for all device communication
- Event router — receives all observations, routes to appropriate handler
- EWMA anomaly detection — O(1) memory, real-time, per-device per-metric
- Decision engine — rule-based playbook matching + graduated autonomy gates
- Web dashboard — FastAPI + htmx + Alpine.js, lightweight status/control surface
- SQLite (WAL mode) — world model, baselines, event store, trust ledger, incident history

### Forge (Proxmox VM) — Analytical Powerhouse

Responsibilities:
- Suricata IDS — EVE JSON output, EmergingThreats ruleset, mirror port or span capture
- OpenCanary honeypot — SSH/HTTP/SMB/FTP/RDP emulation for lateral movement detection
- Isolation Forest — multi-dimensional anomaly re-scoring from Sentinel's EWMA flags
- Claude deep analysis — complex incident correlation, natural language reports (Sonnet routine, Opus complex)
- Self-improvement pipeline — code generation, ephemeral Docker container testing, feature branch staging
- Threat intel aggregator — 6-hour cron: OTX, Abuse.ch (URLhaus, SSLBL, Feodo), EmergingThreats, Spamhaus DROP
- Proxmox API controller — snapshot sibling VMs, manage own infrastructure, query cluster metrics
- Wazuh integration — consume FIM events, auth failures, vulnerability detections, rootcheck findings

### Degradation Modes

- Forge down → Sentinel continues with rule-based decisions, EWMA anomaly detection, and existing feed consumption. Deep analysis and self-improvement are paused.
- Sentinel down → Forge detects missing heartbeat, enters autonomous safety mode (alert-only, no actions), sends Telegram notification.

## Data Feeds & Integration

### Existing Ecosystem (consumed, not reimplemented)

| Source | Data | Integration Method |
|---|---|---|
| netdiscovery | Device inventory, CVEs, threat hunt findings, rogue APs, health score | REST API (`/api/devices`, `/api/findings`, `/api/health`, `/api/cves`) + SQLite |
| mcp-infrastate | Host state: containers, services, ports, processes, network interfaces | MCP tool calls or CLI `--json` |
| mcp-syslog | Log anomalies: bursts, priority shifts, error spikes, new units | MCP tools (`recent_errors`, `log_stats`, `log_timeline`) |
| mactools | macOS security posture, code signing, TCC, disk health, thermal | CLI `--json` output |
| orchestrate | Lane states, active Claude sessions, approval queue, classification metrics | Lane registry JSONL + FastAPI REST/SSE |
| interop | System health, system changes, guardian status | MCP tools (`system_health`, `system_changes`) |

### New Components (deployed by Argus)

| Source | Data | Integration Method |
|---|---|---|
| Wazuh | FIM, auth failures, vulnerabilities, rootcheck, active responses | REST API polling or integrator webhook |
| Suricata | IDS alerts, flows, DNS/HTTP/TLS metadata, anomaly events | EVE JSON tail on Forge |
| OpenCanary | Lateral movement alerts (any connection = high-confidence intrusion) | JSON log on Forge |
| Proxmox API | VM status, resource usage, RRD history, cluster health | REST API (`/api2/json/`) with scoped API tokens |
| DNS monitor | Query logs, DGA candidates, tunneling indicators | Log tail or Pi-hole API |
| Threat intel feeds | IOCs: malicious IPs, domains, JA3, C2 addresses | 6-hour cron: OTX, Abuse.ch, ET, Feodo, Spamhaus |
| Device heartbeats | Liveness, resource usage, local observations | MQTT `argus/heartbeat/{device_id}` with LWT |

### MQTT Topic Hierarchy

```
argus/
  heartbeat/{device_id}        — device liveness + basic metrics
  observation/{source}/{type}   — raw observations from any feed
  event/{severity}/{category}   — correlated events (Sentinel produces)
  incident/{id}                 — open incidents
  decision/{id}                 — proposed actions (graduated autonomy)
  action/{id}/status            — action execution status
  compute/request/{task_id}     — quorum compute delegation
  compute/bid/{task_id}/{node}  — capability bids from nodes
  self/improvement/{id}         — self-modification proposals
```

## MAPE-K Autonomic Loop

### Monitor (Sentinel, fast path)

- Subscribe to all MQTT topics
- Poll external feeds on staggered intervals: netdiscovery 30s, Proxmox 30s, Wazuh 60s, threat intel 6h
- Time-window event bucketing: events within 30 seconds grouped into candidate incidents
- Device heartbeat tracking with MQTT LWT-based "device offline" detection
- Every observation becomes an immutable event in SQLite

### Analyze (split Sentinel/Forge)

**Sentinel (fast):**
- EWMA on per-device metrics (CPU, memory, latency, packet loss, error rate). Alpha 0.1-0.3.
- Z-score on 10-minute rolling window. Flags anomalies instantly.

**Forge (deep):**
- Isolation Forest re-scoring of Sentinel's EWMA flags (scikit-learn, n_estimators=50, ~2GB RAM)
- Claude correlation analysis on incident bundles
- Suricata alert enrichment with threat intel IOC matching
- Cross-source event correlation: network event + system log + security alert → coherent incident

### Plan (Sentinel)

- Match incidents against YAML playbook library
- Select response actions based on incident type and severity
- Check graduated autonomy gate: does this action class have sufficient trust score?
- Enforce cooldown: require 3 consecutive anomalous readings before triggering, 5-minute lockout after action
- Anti-oscillation: will not reverse a recent action within cooldown window

### Execute (Graduated Autonomy)

Four tiers with per-action-class trust tracking:

- **Tier 0:** Always notify via Telegram, never act. 5-minute approval window, dropped on timeout.
- **Tier 1:** Auto-execute for read-only/reversible operations (restart service, flush cache, DNS lookup).
- **Tier 2:** Approval required via Telegram with 60-second window. Auto-executes on timeout (earned trust).
- **Tier 3:** Fully autonomous with 15-second veto window on `argus/proposed`.

Every action tagged with UUID, pre-action metrics recorded, post-action verification at 10m, 30m, 2h, 24h.

### Knowledge (SQLite)

Baselines, trust scores, incident history, decision outcomes, device behavioral profiles, threat intel IOCs, playbook effectiveness rankings.

## Graduated Autonomy Engine

### Trust Ledger (SQLite)

```sql
CREATE TABLE trust_ledger (
    action_class    TEXT PRIMARY KEY,
    executions      INTEGER DEFAULT 0,
    successes       INTEGER DEFAULT 0,
    last_failure    TIMESTAMP,
    trust_tier      INTEGER DEFAULT 0,
    auto_promoted_at TIMESTAMP
);
```

### Promotion Rules

- Tier 0 → 1: `success_rate >= 0.90 AND n >= 10`
- Tier 1 → 2: `success_rate >= 0.95 AND n >= 20 AND last_failure > 14 days ago`
- Tier 2 → 3: `success_rate >= 0.98 AND n >= 50 AND last_failure > 30 days ago`
- Demotion: any failure drops tier by 1, resets promotion counter
- Circuit breaker: 3 failures in any action class within 24h → freeze ALL auto-actions until human review

### Approval Integration

Reuses orchestrate's existing Telegram notification + approval button flow (`notify.send()`, `pretooluse_approval.py` pattern).

## Self-Improvement Pipeline

### Level 1: Threshold Tuning (Sentinel, continuous)

- EWMA baselines drift with network patterns naturally
- Per-device, per-metric thresholds auto-adjust based on time-of-day / day-of-week profiles
- False positive tracking: anomaly without incident within 30min → widen threshold 5%
- False negative tracking: incident without prior anomaly → tighten threshold 10%

### Level 2: Strategy Evolution (Forge, daily)

Adapted from orchestrate's `daily_optimizer.py`:

1. **Outcome scoring** — paired before/after comparison on 5-minute rolling averages for every action in last 24h
2. **Regression analysis** — identify action classes with declining success rates
3. **Playbook ranking** — A/B test which playbooks resolve incident types faster and more reliably
4. **Confidence calibration** — track human approval/denial rates for Tier 2 actions
5. **Shadow testing** — new heuristics run alongside current ones, promote only if outperforming

### Level 3: Code Self-Modification (Forge, gated)

1. **Trigger:** Level 2 identifies persistent gap (unrecognized device type, recurring false positive, missing playbook)
2. **Generate:** Claude writes fix — new parser, adjusted heuristic, new playbook YAML, new integration
3. **Sandbox:** Ephemeral Docker container on Forge, full test suite execution
4. **Snapshot:** Proxmox snapshot of Forge VM before any promotion
5. **Stage:** Feature branch `self-improvement/{description}`, max 200 lines per auto-commit
6. **Notify:** Telegram notification with diff and test results
7. **Promote:** Human approval (or auto-promote at Tier 3 trust) → merge to main, redeploy
8. **Circuit breaker:** >3 auto-commits fail tests in 24h → freeze Level 3 until human review

All auto-commits tagged with `[argus-auto]` prefix.

## Compute Delegation / Quorum

### When to Delegate (benefit must exceed latency cost)

- Claude deep analysis → always Forge or cloud
- Isolation Forest re-scoring → Forge
- Suricata pcap analysis → Forge
- Full network scan → Forge or dedicated device
- Self-improvement code gen + testing → always Forge

### When NOT to Delegate (local is faster)

- EWMA threshold checking (O(1), microseconds)
- MQTT routing (Sentinel IS the broker)
- Heartbeat tracking (timestamp comparison)
- Playbook matching (dictionary lookup)
- Dashboard serving (<1MB memory)

### Protocol

```json
// Sentinel publishes to argus/compute/request/{task_id}
{
  "type": "vulnerability_scan",
  "target": "192.168.1.0/24",
  "resource_needs": {"cpu_cores": 2, "ram_mb": 1024},
  "priority": "medium",
  "deadline": "2026-04-26T22:00:00Z"
}

// Capable nodes bid on argus/compute/bid/{task_id}/{node_id}
{
  "available_cores": 4,
  "available_ram_mb": 6144,
  "estimated_completion": "8m",
  "load_score": 0.3
}

// Sentinel assigns to lowest load_score meeting resource_needs
```

## Security Stack

### On Forge

- **Suricata IDS** — EVE JSON (alerts, flows, DNS, HTTP, TLS, anomaly). EmergingThreats ruleset. Mirror port capture.
- **OpenCanary** — Python honeypot emulating SSH/HTTP/SMB/FTP/RDP/MySQL. Any connection = high-confidence lateral movement.
- **Threat intel aggregation** — 6-hour cron pulling AlienVault OTX (REST API), Abuse.ch URLhaus/SSLBL/Feodo (CSV/JSON), EmergingThreats Open (Suricata rules), Spamhaus DROP (CIDR list).
- **Wazuh consumer** — FIM events, auth failures, vulnerability detections, rootcheck findings via REST API or integrator webhook.
- **TLS/cert monitor** — parse Suricata TLS events for cert expiry (<30 days), MITM detection (self-signed on non-local, issuer changes).

### On Sentinel

- **netdiscovery consumption** — device inventory, CVE correlation, rogue AP detection, health scoring
- **mactools consumption** — macOS security posture, code signing, TCC audit
- **DNS monitoring** — DGA entropy scoring + bigram model, tunneling detection (query length >50, TXT/NULL abuse)
- **Event correlation** — 30-second time-window bucketing, rule-based enrichment into coherent incidents

## Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| Language | Python 3.12+ | Matches ecosystem (mactools, netdiscovery, orchestrate) |
| MQTT | Mosquitto | ~4MB RAM, QoS/LWT, universal client support |
| State | SQLite (WAL mode) | Zero-config, full-text search, handles event volume |
| Dashboard | FastAPI + htmx + Alpine.js | Same as netdiscovery, lightweight, no build step |
| IDS | Suricata | EVE JSON, EmergingThreats, lighter than Zeek |
| Honeypot | OpenCanary | Python, multi-protocol, JSON logs |
| ML | EWMA (Sentinel) + IsolationForest (Forge) | O(1) vs. scikit-learn with n_estimators=50 |
| AI | Claude API (Sonnet routine, Opus complex) | Tiered model routing per orchestrate pattern |
| Notifications | Telegram via orchestrate | Already built with approval buttons |
| Config | YAML playbooks + TOML system config | Human-readable, version-controllable |
| Containers | Docker on Forge | Ephemeral sandboxes for self-modification testing |
| Rollback | Git branches + Proxmox snapshot API | Feature branches for auto-code, VM snapshots for nuclear rollback |

## Module Structure

```
argus/
  argus_core/
    mqtt.py                — Mosquitto client wrapper, topic routing, QoS
    events.py              — event schema, SQLite event store, immutable append
    config.py              — TOML config loader, YAML playbook loader
    models.py              — Device, Incident, Action, TrustScore dataclasses

  argus_sentinel/
    monitor/
      feed_poller.py       — staggered polling of external feeds
      heartbeat.py         — device liveness via MQTT + LWT
      event_bucketer.py    — 30-second window grouping into candidate incidents
    analyze/
      ewma.py              — per-device per-metric EWMA anomaly detection
      correlator.py        — cross-source event correlation into incidents
      dns_analyzer.py      — DGA entropy scoring, tunneling detection
    plan/
      playbook_engine.py   — YAML playbook matching + action selection
      autonomy_gate.py     — trust ledger check, tier enforcement, cooldown
      anti_oscillation.py  — prevents flip-flop decisions
    execute/
      action_runner.py     — dispatch actions at appropriate tier
      approval.py          — Telegram approval flow (reuses orchestrate)
      verifier.py          — post-action verification at 10m/30m/2h/24h
    dashboard/
      app.py               — FastAPI + htmx dashboard
      api.py               — REST endpoints: status, incidents, devices, trust

  argus_forge/
    analyze/
      isolation_forest.py  — multi-dimensional anomaly re-scoring
      claude_analyst.py    — deep incident analysis, NL reports
      threat_intel.py      — feed aggregation + IOC matching
    security/
      suricata_ingest.py   — EVE JSON tail + alert normalization
      opencanary_ingest.py — honeypot alert normalization
      tls_monitor.py       — cert expiry + MITM detection
      wazuh_ingest.py      — Wazuh API/webhook consumer
    compute/
      task_worker.py       — bid on and execute delegated compute tasks
      proxmox_api.py       — Proxmox REST client: snapshots, VMs, metrics
    self_improve/
      outcome_scorer.py    — paired before/after metric comparison
      regression.py        — declining success rate detection
      playbook_ranker.py   — A/B test playbook effectiveness
      code_generator.py    — Claude-powered code improvement proposals
      sandbox.py           — ephemeral Docker container test runner
      promoter.py          — feature branch → main with snapshot safety
      circuit_breaker.py   — freeze self-modification on repeated failures

  argus_agent/
    heartbeat.py           — MQTT heartbeat publisher (cross-platform)
    collector.py           — local metrics collection
    responder.py           — execute actions from Sentinel

  playbooks/
    network_degradation.yml
    unauthorized_device.yml
    service_down.yml
    lateral_movement.yml
    cert_expiry.yml
    high_resource_usage.yml
    rogue_ap.yml
    failed_auth_spike.yml

  tests/
  docs/
```

## Decomposition Strategy

This is a large system. Build in phases:

1. **Phase 1 — Skeleton + MQTT + Event Store:** argus_core, Mosquitto setup, SQLite event schema, MQTT topic hierarchy, basic device heartbeat. The nervous system.
2. **Phase 2 — Feed Integration:** Connect netdiscovery, mcp-infrastate, mcp-syslog, mactools as data sources. The eyes.
3. **Phase 3 — MAPE-K Loop (Monitor + Analyze):** EWMA anomaly detection, event bucketing, incident correlation. The pattern recognition.
4. **Phase 4 — Plan + Execute:** Playbook engine, graduated autonomy, Telegram approval flow. The decision-making.
5. **Phase 5 — Forge Deployment:** Proxmox VM setup, Suricata, OpenCanary, threat intel aggregation. The heavy artillery.
6. **Phase 6 — Self-Improvement:** Threshold tuning, strategy evolution, code self-modification. The brain that grows.
7. **Phase 7 — Dashboard + Polish:** Web UI, incident timeline, trust score visualization, device map.
