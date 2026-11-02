# ddosguard — DDoS Detection, Mitigation & Monitoring Toolkit

**Ctf writeup / documentation repo for the ddosguard project.**

This repository contains a complete, self-contained Python toolkit for real-time DDoS detection, automated mitigation, and live monitoring — built end-to-end as a single in-process pipeline.

---

## Table of Contents

1. [What This Project Is](#what-this-project-is)
2. [Original Task Requirements](#original-task-requirements)
3. [Architecture Overview](#architecture-overview)
4. [Deliverables](#deliverables)
5. [Project Structure](#project-structure)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Usage — CLI](#usage--cli)
9. [Usage — Dashboard](#usage--dashboard)
10. [Detection Pipeline Walkthrough](#detection-pipeline-walkthrough)
11. [Mitigation System](#mitigation-system)
12. [Alerting & Escalation](#alerting--escalation)
13. [Baseline System](#baseline-system)
14. [Testing](#testing)
15. [Security Considerations](#security-considerations)
16. [Original Prompt / Instructions](#original-prompt--instructions)

---

## What This Project Is

`ddosguard` is a Python 3.14+ toolkit that watches network traffic in real time, learns what "normal" looks like via a statistical baseline, detects anomalies using multiple weighted signals, and automatically mitigates attacks through rate limiting and firewall rule generation — all while presenting a live web dashboard and escalating alerts to administrators.

It is designed as a **single in-process pipeline**, not a distributed system. A `MonitorRunner` drives the whole loop:

```
packet source  →  window aggregator  →  baseline store  →  composite scorer
                                                              ↓
                                                    mitigation policy
                                                              ↓
                                                    alert manager  →  dashboard
```

The project was built to satisfy a demanding multi-deliverable CTF-style task requiring **7 separate functional areas** to be implemented, tested, and demonstrated — all without network access during tests, all in Python 3.14 on Windows, with no root privileges.

---

## Original Task Requirements

The original assignment (preserved verbatim at the end of this document) asked for a DDoS detection & mitigation solution covering **7 deliverables**:

1. **Baseline establishment** — statistical models of normal traffic, keyed by diurnal buckets (weekday/weekend × hour), persisted to disk.
2. **Real-time monitoring** — live capture from multiple source types (synthetic, pcap replay, scapy live sniff), windowed aggregation.
3. **Anomaly detection** — multiple weighted signals (volume, protocol, source, port, SYN) feeding a composite scorer with severity bands.
4. **Automated rate limiting** — token bucket rate limiter with per-key buckets, whitelist support, and admission stats.
5. **Firewall rule generation & management** — iptables-style rule generation per severity stage (0–4), whitelist-aware, dry-run by default.
6. **Alerting with escalation** — signature-based deduplication, cooldown, per-minute caps, multi-channel notifiers, severity-based escalation ladder.
7. **Admin dashboard & controls** — live FastAPI web dashboard with real-time read endpoints, whitelist management, mitigation controls, pause/resume.

Additional constraints:
- Python 3.14 on Windows
- pip available; no root privileges
- No `create_file` tool — must use `write_file` / `apply_patch` / `run_terminal_command`
- Tests must be **unit tests with no network/permissions required**; pytest is installed
- Deliver all 7 deliverables, completely

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ddosguard — single in-process pipeline             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────┐ │
│  │ PacketSource │───▶│ WindowAggregator │───▶│ TrafficStats             │ │
│  │ (synthetic   │    │ / RollingWindow  │    │ (per-window snapshot)    │ │
│  │  pcap, scapy)│    │                  │    └────────────┬─────────────┘ │
│  └──────────────┘    └──────────────────┘                 │               │
│                                                            ▼               │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────┐ │
│  │              │◀───│ BaselineStore    │◀───│ CompositeScorer          │ │
│  │              │    │ (diurnal buckets,│    │ (volume/protocol/src/    │ │
│  │  MonitorRunner│   │  reservoir samp.)│    │  port/syn signals)       │ │
│  └──────┬───────┘    └──────────────────┘    └────────────┬─────────────┘ │
│         │                                                  │               │
│         ▼                                                  ▼               │
│  ┌──────────────┐                         ┌──────────────────────────┐ │
│  │              │◀────────────────────────│ MitigationPolicy          │ │
│  │  Dashboard   │                         │ (escalation ladder 0–4)  │ │
│  │  (FastAPI)   │                         └────────────┬─────────────┘ │
│  └──────┬───────┘                                      │               │
│         │                                              ▼               │
│         │                              ┌──────────────────────────┐ │
│         │                              │ AlertManager             │ │
│         │                              │ (dedup/cooldown/notify)  │ │
│         │                              └──────────────────────────┘ │
│         │                                                              │
│         ▼                                                              │
│  ┌──────────────┐                                                     │
│  │ MonitorState │◀── thread-safe snapshot for dashboard reads         │
│  └──────────────┘                                                     │
│                                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key design decisions

- **Pluggable packet sources**: `SyntheticGenerator` (normal diurnal traffic + attack families: volumetric UDP, SYN flood, application-layer), `PcapSource` (offline replay), `ScapySource` (live sniff — requires libpcap).
- **Windowing**: `WindowAggregator` maintains per-window counters, top-talkers, SYN/RST counts. `RollingAggregator` is a ring-buffer variant with sample-rate support and auto-commit on window threshold.
- **Baseline**: diurnal buckets keyed `weekday-HH` / `weekend-HH`, reservoir sampling (size 500), persisted as JSON. `BaselineStats` tracks mean/stdev/percentiles.
- **Detection**: 5 signals — volume, protocol, source, port, SYN — each producing a `SignalResult` (name + score 0..1 + detail). `CompositeScorer` weights them, applies confirmation damping, and produces a `CompositeScore` with severity band and classification (none/volumetric/protocol/application/mixed).
- **Mitigation**: `MitigationPolicy` is an escalation ladder — stage 0 (no mitigation) through stage 4 (full DROP + scrubbing hint). Each stage maps to a severity. `TokenBucket` (rate/burst, analytical refill) and `RateLimiter` (per-key buckets + whitelist) enforce rate limits. `FirewallManager` generates iptables-style rule sets per stage.
- **Alerting**: `AlertManager` does signature-based dedup, cooldown, `max_per_minute` cap, and supports console/file/desktop/slack/email notifiers. `AlertDirector` ranks alerts and surfaces urgent CRITICAL-only items.
- **Dashboard**: FastAPI app on `127.0.0.1:8080` with live JS polling. Shared `MonitorState` (thread-safe) holds live baseline, mitigations, alerts, stats.

---

## Deliverables

All 7 required deliverables are implemented and verified:

| # | Deliverable | Module(s) | Status |
|---|-------------|-----------|--------|
| 1 | Baseline establishment | `ddosguard/baseline/store.py` | ✅ Statistical diurnal baseline, reservoir sampling, JSON persistence, observe/expected/save/load |
| 2 | Real-time monitoring | `ddosguard/metrics/window.py`, `ddosguard/capture/` | ✅ WindowAggregator + RollingAggregator, 3 pluggable sources (synthetic/pcap/scapy), MonitorRunner loop |
| 3 | Anomaly detection | `ddosguard/detect/signals.py`, `ddosguard/detect/scorer.py` | ✅ 5 weighted signals + composite scorer, severity bands, classification |
| 4 | Automated rate limiting | `ddosguard/mitigate/ratelimit.py` | ✅ TokenBucket (rate/burst, analytical refill), RateLimiter (per-key, whitelist, admission stats) |
| 5 | Firewall rule generation/management | `ddosguard/mitigate/firewall.py` | ✅ iptables-style rule generation per stage 0–4, whitelist permit rules, generate/apply/clear, dry-run default |
| 6 | Alerting with escalation | `ddosguard/alert/manager.py`, `ddosguard/alert/director.py` | ✅ Signature dedup, cooldown, max_per_minute, multi-channel notifiers, severity-based escalation |
| 7 | Admin dashboard & controls | `ddosguard/dashboard/app.py`, `ddosguard/monitor.py` | ✅ FastAPI dashboard, live read endpoints, whitelist/mitigation controls, pause/resume, thread-safe MonitorState |

**Tests**: 19 unit tests, all passing (no network, no permissions required).

---

## Project Structure

```
ddosguard/
├── __init__.py          # package version + public API note
├── __main__.py          # entry point for `python -m ddosguard`
├── cli.py               # CLI: baseline, monitor, replay, simulate, alert, dashboard
├── core.py              # dataclasses: PacketRecord, TrafficWindow, TrafficStats,
│                        #   BaselineStats, SignalResult, CompositeScore, Alert,
│                        #   WhitelistedIp, MitigationAction, Protocol, Severity
├── config.py            # Config dataclass, YAML load/save, find_rate_limit, is_enabled
├── monitor.py           # MonitorState (thread-safe), WhitelistStore, MonitorRunner
│
├── capture/             # packet sources
│   ├── __init__.py
│   ├── base.py          # PacketSource ABC + SyntheticGenerator
│   ├── pcap_source.py  # PcapSource (offline replay)
│   └── scapy_source.py # ScapySource (live sniff)
│
├── metrics/
│   └── window.py        # WindowAggregator + RollingAggregator
│
├── baseline/
│   ├── __init__.py
│   └── store.py         # BaselineStore + BaselineStats (diurnal buckets, reservoir)
│
├── detect/
│   ├── __init__.py
│   ├── signals.py       # volume/protocol/source/port/syn signals
│   └── scorer.py        # CompositeScorer
│
├── mitigate/
│   ├── __init__.py
│   ├── ratelimit.py     # TokenBucket + RateLimiter
│   ├── firewall.py      # FirewallManager (iptables-style rule gen)
│   └── policy.py        # MitigationPolicy (escalation ladder)
│
├── alert/
│   ├── __init__.py
│   ├── manager.py       # AlertManager (dedup/cooldown/notifiers)
│   └── director.py      # AlertDirector (ranking, urgent)
│
└── dashboard/
    ├── app.py           # FastAPI dashboard app + endpoints
    └── static/
        └── index.html   # live JS polling UI
```

Supporting files:
- `tests/` — pytest unit tests
- `requirements.txt` — Python dependencies
- `pyproject.toml` — project metadata

---

## Installation

### Prerequisites

- Python 3.14+ on Windows (or Linux/macOS)
- pip available
- No root privileges required (firewall apply requires sudo/admin on the target host — the toolkit defaults to **dry-run** mode)

### Install dependencies

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install scapy>=2.5.0 fastapi>=0.110.0 "uvicorn[standard]>=0.30.0" pyyaml>=6.0.2 pytest>=8.0.0
```

> **Note for Windows users**: Scapy's live packet capture (`ScapySource`) requires Npcap/WinPcap. Without it, you'll see a warning (`No libpcap provider available`) but the synthetic source and pcap replay still work fine. For demos and tests, the synthetic source is sufficient.

### Verify installation

```bash
# Check CLI
python -m ddosguard --help

# Run tests
python -m pytest tests/ -q
```

Expected: CLI shows 6 subcommands; 19 tests pass.

---

## Configuration

The toolkit uses a YAML configuration file (`config.yaml` by default). The `Config` dataclass reads this and provides typed access to all sections.

### Configuration sections

| Section | Purpose | Key fields |
|---------|---------|------------|
| `capture` | Packet source settings | `source` (synthetic/pcap/scapy), `window_seconds`, `pcap_file`, `interface`, `sample_rate` |
| `baseline` | Baseline model settings | `data_dir`, `window_seconds`, `observe_interval`, `ready` |
| `detection` | Detection thresholds | signal weights, severity thresholds, confirmation damping |
| `mitigation` | Rate limiting & firewall | `dry_run`, `rate_limits` (per-stage), `max_rate`, `burst`, `whitelist` |
| `alerting` | Alerting settings | `cooldown`, `max_per_minute`, notifier configs (console/file/desktop/slack/email) |
| `dashboard` | Dashboard settings | `host`, `port`, `enabled` |

### Default configuration

If no `config.yaml` exists, `Config.load()` falls back to built-in defaults (`DEFAULT_CONFIG`) which use:
- Synthetic packet source
- Dry-run mitigation (no real firewall changes)
- Console alerting
- Dashboard on 127.0.0.1:8080

### Creating a config.yaml

A demonstration `config.yaml` looks like:

```yaml
capture:
  source: synthetic        # synthetic | pcap | scapy
  window_seconds: 10
  pcap_file: data/live.pcap
  interface: any
  sample_rate: 1.0

baseline:
  data_dir: data
  window_seconds: 10
  observe_interval: 10.0
  ready: true

detection:
  weights:
    volume: 0.30
    protocol: 0.20
    source: 0.20
    port: 0.15
    syn: 0.15
  severity_thresholds:
    low: 0.3
    medium: 0.5
    high: 0.7
    critical: 0.85
  confirmation_damping: 0.8

mitigation:
  dry_run: true           # set false to apply real iptables rules (requires sudo)
  rate_limits:
    - stage: 0
      rate: 0
      burst: 0
    - stage: 1
      rate: 100
      burst: 200
    - stage: 2
      rate: 50
      burst: 100
    - stage: 3
      rate: 20
      burst: 50
    - stage: 4
      rate: 5
      burst: 10
  max_rate: 1000
  whitelist:
    - 192.168.1.1
    - 10.0.0.0/8

alerting:
  cooldown: 60            # seconds between repeated alerts for same signature
  max_per_minute: 10
  notifiers:
    console: true
    file: false
    file_path: data/alerts.jsonl
    desktop: false
    slack: false
    slack_webhook: ""
    email: false
    smtp_host: ""
    smtp_port: 587
    email_from: ""
    email_to: ""

dashboard:
  host: 127.0.0.1
  port: 8080
  enabled: true
```

---

## Usage — CLI

The CLI is invoked as a Python module:

```bash
python -m ddosguard <subcommand> [options]
```

### Subcommands

#### `baseline` — Train the baseline model

Observes traffic for a period and builds the statistical baseline.

```bash
# Train on synthetic normal traffic for 10 minutes
python -m ddosguard baseline --seconds 600

# Train for 2 minutes
python -m ddosguard baseline --seconds 120

# Use a pcap file as source
python -m ddosguard baseline --source pcap --pcap data/live.pcap --seconds 600

# Use live scapy capture
python -m ddosguard baseline --source scapy --seconds 600
```

Options:
- `--seconds` — observation duration (default 600)
- `--config` — config file path (default `config.yaml`)
- `--source` — packet source: `synthetic`, `scapy`, `pcap` (default `synthetic`)
- `--pcap` — pcap file path (for `--source pcap`)
- `--interval` — logging interval in seconds (default 10.0)

#### `monitor` — Live monitor with dashboard

Runs the full detection + mitigation pipeline with a live dashboard.

```bash
# Start live monitor + dashboard on default port 8080
python -m ddosguard monitor

# Start without dashboard (headless)
python -m ddosguard monitor --no-dashboard

# Custom host/port
python -m ddosguard monitor --host 0.0.0.0 --port 9090

# Use a specific config
python -m ddosguard monitor --config my-config.yaml
```

Options:
- `--config` — config file (default `config.yaml`)
- `--no-dashboard` — run without web UI
- `--host` — dashboard bind address (default `127.0.0.1`)
- `--port` — dashboard port (default `8080`)

#### `replay` — Offline pcap analysis

Analyzes a pcap trace without live capture.

```bash
python -m ddosguard replay trace.pcap
python -m ddosguard replay data/live.pcap --window 10.0
```

Options:
- `pcap` (positional) — pcap file to replay
- `--window` — window size in seconds (default 10.0)

#### `simulate` — Synthetic attack demo

Generates synthetic attack traffic for demonstration/testing.

```bash
# Volumetric UDP flood
python -m ddosguard simulate --family volumetric --duration 45

# SYN flood
python -m ddosguard simulate --family syn_flood --duration 30

# Application-layer attack (single port)
python -m ddosguard simulate --family application --duration 30

# Custom packet count
python -m ddosguard simulate --family volumetric --packets 50000
```

Options:
- `--family` — attack type: `volumetric`, `syn_flood`, `application` (default `volumetric`)
- `--duration` — attack duration in seconds (default 45.0)
- `--packets` — total packets to generate (default 20000)

#### `alert` — View alerts

Displays persisted alerts from a JSONL file.

```bash
python -m ddosguard alert --file data/alerts.jsonl
python -m ddosguard alert --file data/alerts.jsonl --limit 10
```

Options:
- `--file` — alerts JSONL file (default `data/alerts.jsonl`)
- `--limit` — max alerts to show (default 20)

#### `dashboard` — Run dashboard only

Starts just the FastAPI dashboard (requires a separate monitor process for data).

```bash
python -m ddosguard dashboard
python -m ddosguard dashboard --port 9090
```

Options:
- `--host` — bind address (default `127.0.0.1`)
- `--port` — port (default `8080`)
- `--config` — config file (default `config.yaml`)

---

## Usage — Dashboard

Once the monitor is running with the dashboard enabled, open:

```
http://127.0.0.1:8080
```

### Dashboard endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard UI (HTML + live JS) |
| `/api/status` | GET | Pipeline status, current severity, mitigation stage, packet rate |
| `/api/stats` | GET | Latest traffic stats (packet rate, byte rate, protocol breakdown, top talkers) |
| `/api/baseline` | GET | Current baseline models (diurnal buckets) |
| `/api/alerts` | GET | Recent alerts timeline |
| `/api/mitigations` | GET | Active mitigation actions |
| `/api/whitelist` | GET | Current whitelist |
| `/api/whitelist` | POST | Add IP to whitelist (JSON body: `{"ip": "...", "reason": "..."}`) |
| `/api/whitelist/<ip>` | POST | Remove IP from whitelist |
| `/api/rate-limit` | GET | Current rate limit configuration |
| `/api/mitigate` | POST | Trigger mitigation action |
| `/api/mitigations/clear` | POST | Clear all active mitigations |
| `/api/control/pause` | POST | Pause the monitoring pipeline |
| `/api/control/resume` | POST | Resume the monitoring pipeline |

The dashboard polls `/api/status` and `/api/stats` every 2 seconds for live updates, and renders sparkline-style charts of traffic volume, protocol distribution, and alert history.

---

## Detection Pipeline Walkthrough

Here's how a packet flows through the system from capture to alert:

### Step 1 — Capture
A `PacketSource` yields `PacketRecord` objects:
```python
for pkt in source.iter_packets(window_seconds):
    aggregator.add(pkt)
```

Each `PacketRecord` has: timestamp, src/dst IP, protocol (TCP/UDP/ICMP/etc.), src/dst port, length, TCP flags.

### Step 2 — Window aggregation
`WindowAggregator` accumulates packets into fixed-length windows. When a window is full (or `finalize()` is called), it emits a `TrafficStats`:

```python
stats = aggregator.finalize()
# stats.packet_rate  — packets per second
# stats.byte_rate    — bytes per second
# stats.per_proto    — {6: tcp_count, 17: udp_count, ...}
# stats.syn_ratio    — fraction of packets with SYN flag
# stats.unique_sources, stats.unique_dests
# stats.top_srcs, stats.top_ports
```

### Step 3 — Baseline observation
During training, `BaselineStore.observe(stats, timestamp)` records each window's metrics into diurnal buckets:

```python
baseline.observe(stats, datetime.now())
```

Buckets are keyed like `weekday-14` (weekday, 14:00 hour) or `weekend-3` (weekend, 03:00 hour). Each bucket gets a `BaselineStats` with mean/stdev/percentiles computed from a reservoir sample.

### Step 4 — Scoring
`CompositeScorer.score(stats, baseline)` runs 5 signals:

| Signal | What it detects | Score |
|--------|-----------------|-------|
| **Volume** | Packet/byte rate vs baseline mean + stdev | How far above normal |
| **Protocol** | Deviation in protocol distribution | Unusual protocol mix |
| **Source** | Number of unique sources, top-talker concentration | Source dispersion |
| **Port** | Unusual destination port concentration | Port targeting |
| **SYN** | SYN packet ratio | SYN flood indicator |

Each signal returns a `SignalResult` with a 0..1 score. The scorer weights them, applies confirmation damping (repeated high scores are damped to avoid oscillation), and computes a total 0..1 score.

### Step 5 — Classification & severity
Based on which signals fired and the total score, the scorer classifies the event:

- **none** — score below threshold
- **volumetric** — high volume signal
- **protocol** — unusual protocol distribution
- **application** — port-targeted attack
- **mixed** — multiple signal types

Severity bands: INFO, LOW, MEDIUM, HIGH, CRITICAL (based on score thresholds from config).

### Step 6 — Mitigation decision
`MitigationPolicy.decide(score, stats)` maps the severity to a mitigation stage (0–4) and applies the appropriate rate limits / firewall rules via `RateLimiter` and `FirewallManager`.

### Step 7 — Alert
`AlertManager.generate()` creates an `Alert` with the score details, mitigation actions, and affected sources. It deduplicates by signature, respects cooldown, and delivers to configured notifiers.

### Step 8 — Dashboard update
`MonitorRunner` updates `MonitorState` (thread-safe snapshot), which the FastAPI dashboard reads via its API endpoints.

---

## Mitigation System

### TokenBucket (rate limiting)

```python
from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter

# Strict rate limiting: 100 tokens/sec, no burst allowance
bucket = TokenBucket(rate=100, burst=0)

# With burst: start with 200 tokens, refill at 100/sec
bucket = TokenBucket(rate=100, burst=200)

# Check if a request is allowed
allowed = bucket.consume(tokens=1)  # returns True/False
```

Key semantics:
- `burst=0` → starts empty (strict rate limiting from the first request)
- `burst>0` → starts with burst tokens available immediately
- Refill is computed analytically (not tick-based), so it's accurate regardless of call frequency

### RateLimiter (per-key)

```python
from ddosguard.mitigate.ratelimit import RateLimiter

limiter = RateLimiter(default_rate=100, default_burst=200)
limiter.add_whitelist("192.168.1.1")  # whitelisted IPs bypass limiting

# Check/admit a packet from a source
admitted = limiter.admit(key="10.0.0.1", tokens=1)
stats = limiter.stats(key="10.0.0.1")  # admission stats for a key
```

### FirewallManager (iptables-style rule generation)

```python
from ddosguard.mitigate.firewall import FirewallManager

fw = FirewallManager(dry_run=True)  # dry_run=True = don't execute, just generate

# Generate rules for stage 2 mitigation
rules = fw.generate_rules(stage=2, severity="HIGH", config=config)

# Rules are iptables-format strings with comment metadata:
# # ddosguard: stage=2 severity=HIGH
# -A INPUT -p udp -m recent --set --name DDOSGUARD
# -A INPUT -p udp -m recent --update --seconds 10 --hitcount 50 --name DDOSGUARD -j DROP
# ...

# Apply (executes iptables commands — requires root)
# fw.apply(rules)

# Clear all ddosguard rules
# fw.clear()
```

Stages:
| Stage | Severity | Action |
|-------|----------|--------|
| 0 | — | No mitigation |
| 1 | LOW/MEDIUM | Lenient per-IP rate limit |
| 2 | MEDIUM/HIGH | Strict per-IP + recent module tracking |
| 3 | HIGH | Service-port rate limits |
| 4 | CRITICAL | Full DROP + scrubbing hint |

Whitelisted IPs always get permit rules before any DROP rules.

### MitigationPolicy (escalation ladder)

```python
from ddosguard.mitigate.policy import MitigationPolicy

policy = MitigationPolicy(config)
action = policy.decide(score, stats)       # decide what stage to apply
policy.apply(action)                        # apply the mitigation
```

The policy reads `config.mitigation.rate_limits` to map stages to rate/burst values, respects the whitelist, and enforces safeguards (e.g., don't escalate to stage 4 without a critical score).

---

## Alerting & Escalation

### AlertManager

```python
from ddosguard.alert import AlertManager

manager = AlertManager(config)
manager.register_notifier("console", enabled=True)
manager.register_notifier("file", enabled=True, path="data/alerts.jsonl")

# Generate and deliver an alert
alert = Alert(
    alert_id="uuid",
    severity=Severity.HIGH,
    title="Volumetric DDoS detected",
    summary="...",
    ...
)
manager.generate(alert)     # dedup + cooldown check
manager.deliver(alert)      # send to all enabled notifiers
```

Features:
- **Signature-based dedup**: alerts with the same signature within the cooldown window are suppressed
- **Cooldown**: configurable per-signature cooldown (default 60s)
- **Max per minute**: caps the number of alerts delivered per minute (default 10)
- **Multi-channel**: console (default), file (JSONL), desktop notifications, Slack webhook, email/SMTP

### AlertDirector

```python
from ddosguard.alert import AlertDirector

director = AlertDirector()
director.add_alert(alert)
urgent = director.get_urgent()   # CRITICAL alerts only, ranked by severity
timeline = director.get_timeline()  # all alerts, ranked by severity
```

---

## Baseline System

### How baselines work

The baseline models "normal" traffic by time of day and day of week. It uses **diurnal buckets**:

- **Weekday buckets**: `weekday-0` through `weekday-23` (hour of day, Mon–Fri)
- **Weekend buckets**: `weekend-0` through `weekend-23` (hour of day, Sat–Sun)

Each bucket stores a `BaselineStats` — mean, stdev, count, and percentiles (p5, p25, p75, p95, p99) — computed from observed traffic metrics (packet rate, byte rate, protocol mix, etc.).

### Reservoir sampling

To bound memory, each bucket keeps a **reservoir sample of at most 1000 values**. When a new value arrives and the reservoir is full, the oldest value is evicted (FIFO). Statistics are recomputed from the reservoir on each observation.

### Using the baseline

```python
from ddosguard.baseline import BaselineStore
from ddosguard.config import Config

config = Config.load("config.yaml")
baseline = BaselineStore(config, data_dir="data")
baseline.load()             # load persisted baseline from disk
baseline.set_ready(True)    # mark as ready for detection

# Observe a window of traffic
baseline.observe(stats, datetime.now())

# Get expected value for current bucket
expected = baseline.expected("packet_rate", datetime.now())

# Save to disk
baseline.save()

# List all buckets
for key, stats in baseline.all().items():
    print(f"{key}: mean={stats.mean:.2f}, stdev={stats.stdev:.2f}")
```

---

## Testing

All tests are unit tests — no network, no permissions, no live capture required.

```bash
python -m pytest tests/ -v
```

Current test coverage (19 tests):

| Test file | What it tests |
|-----------|---------------|
| `test_metrics_window.py` | WindowAggregator, RollingAggregator — packet counting, window finalization, top-talkers, SYN/RST tracking, sample-rate support, auto-commit |
| `test_baseline.py` | BaselineStore — diurnal bucketing, reservoir sampling, observe/expected/save/load, BaselineStats percentiles |
| `test_detection.py` | Signals (volume/protocol/source/port/syn) and CompositeScorer — scoring, severity bands, classification |
| `test_ratelimit.py` | TokenBucket — rate/burst semantics, analytical refill, consume; RateLimiter — per-key buckets, whitelist, admission stats |
| `test_firewall.py` | FirewallManager — rule generation per stage, whitelist permit rules, generate/apply/clear |
| `test_alert.py` | AlertManager — signature dedup, cooldown, max_per_minute, multi-channel notifiers; AlertDirector — ranking, urgent |

Run a specific test file:
```bash
python -m pytest tests/test_ratelimit.py -v
```

---

## Security Considerations

- **Dry-run by default**: `mitigation.dry_run = true` in the default config. Real iptables commands are NOT executed unless you explicitly set `dry_run: false` and run with appropriate privileges. This is critical — the toolkit can generate DROP rules that would block traffic.
- **Whitelist first**: Whitelist permit rules are always generated before DROP rules. Add your admin IPs to the whitelist before enabling real mitigation.
- **No secrets in code**: Alert notifiers (Slack webhooks, SMTP credentials) should be set via environment variables or a secrets manager, not committed to the repo.
- **localhost only**: The dashboard binds to `127.0.0.1` by default. Do not expose it to the network without authentication.
- **Alert file**: The alerts JSONL file (`data/alerts.jsonl`) may contain IP addresses and attack details. Treat it as sensitive.
- **Synthetic source is safe**: The `SyntheticGenerator` generates fake traffic for demos/tests — it never touches the network. The `PcapSource` reads pcap files offline. Only `ScapySource` does live capture, and only if you explicitly choose it.

---

## Original Prompt / Instructions

The following is the original task description that this project was built to satisfy:

---

**Project**: DDoS Detection & Mitigation Toolkit (CTF writeup)

**Environment**:
- Python 3.14 on Windows
- pip available
- No root privileges
- No `create_file` tool — use `write_file` / `apply_patch` / `run_terminal_command` (heredocs)

**Required deliverables** (all 7 must be implemented):

1. **Baseline establishment** — Statistical baseline of normal traffic, persisted, keyed by diurnal buckets.
2. **Real-time monitoring** — Live packet capture from multiple sources, windowed aggregation.
3. **Anomaly detection** — Multiple weighted signals → composite scorer → severity classification.
4. **Automated rate limiting** — Token bucket rate limiter, per-key, with whitelist.
5. **Firewall rule generation & management** — iptables-style rules per severity stage, dry-run default.
6. **Alerting with escalation** — Dedup, cooldown, multi-channel notifiers, severity-based escalation.
7. **Admin dashboard & controls** — Live FastAPI web dashboard, controls, pause/resume.

**Constraints**:
- Tests must be unit tests with no network/permissions required.
- pytest is installed.
- Deliver all 7 deliverables completely.

---

## License

This project was built as a CTF writeup / educational demonstration. See the repository for full source code and tests.

---

*Built with Python 3.14, scapy, FastAPI, uvicorn, PyYAML, pytest.*
