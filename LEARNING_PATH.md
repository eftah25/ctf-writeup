# Learning Path: Build DDoS Detection & Mitigation From Scratch

**A complete beginner-to-advanced guide that turns building this project into a structured learning journey.**

> This guide assumes you know almost nothing about network security or Python packaging. Each step tells you:
> - **What to build** (concrete task)
> - **What you'll learn** (concepts gained)
> - **Why it matters** (bigger picture)
> - **How to verify** (test/checkpoint)
> - **Estimated time** (for a beginner)
>
> Follow the steps in order. Do not skip ahead. Each step depends on the previous one.

---

## Table of Contents

1. [Before You Start — Prerequisites & Setup](#before-you-start)
2. [Phase 1: Foundations (Steps 1–3)](#phase-1-foundations)
3. [Phase 2: Data Models & Traffic (Steps 4–6)](#phase-2-data-models--traffic)
4. [Phase 3: Windowing & Metrics (Steps 7–9)](#phase-3-windowing--metrics)
5. [Phase 4: Baseline System (Steps 10–12)](#phase-4-baseline-system)
6. [Phase 5: Anomaly Detection (Steps 13–15)](#phase-5-anomaly-detection)
7. [Phase 6: Rate Limiting & Mitigation (Steps 16–18)](#phase-6-rate-limiting--mitigation)
8. [Phase 7: Firewall Rules (Step 19)](#phase-7-firewall-rules)
9. [Phase 8: Alerting & Escalation (Steps 20–22)](#phase-8-alerting--escalation)
10. [Phase 9: Dashboard & Controls (Steps 23–25)](#phase-9-dashboard--controls)
11. [Phase 10: CLI & Packaging (Steps 26–28)](#phase-10-cli--packaging)
12. [Phase 11: Testing & Polish (Steps 29–31)](#phase-11-testing--polish)
13. [Roadmap Summary](#roadmap-summary)
14. [What You'll Know After Completing This](#what-youll-know-after)

---

## Before You Start

### What you need

| Item | Why | Check |
|------|-----|-------|
| Python 3.14+ installed | The project is Python 3.14+ | Run `python --version` |
| pip available | To install dependencies | Run `pip --version` |
| A code editor | VS Code, PyCharm, or any text editor | Open a `.py` file |
| Git installed | To track your work | Run `git --version` |
| Basic Python knowledge | Variables, functions, classes, imports | You can write `def foo(): return 1` |
| Terminal comfort | Running commands, navigating folders | You can `cd` and `ls` |

### How to use this guide

1. **Create a new folder** for your project: `mkdir ddosguard && cd ddosguard`
2. **Read each step** before writing any code
3. **Write the code** described in the step
4. **Run the verification** to confirm it works
5. **Commit your work** with git after each phase (optional but recommended)
6. **Move to the next step**

### Time estimate

For a complete beginner: **40–60 hours** total (about 1–2 weeks of part-time work).
For someone with Python experience: **15–25 hours**.

---

## Phase 1: Foundations

### Step 1: Set Up the Project Structure

**Task**: Create the folder structure and configuration files for a Python package.

Create these folders and files:

```
ddosguard/
├── __init__.py          # Empty for now
├── pyproject.toml       # Project metadata
└── requirements.txt     # Dependencies (empty for now)
```

**`pyproject.toml`**:
```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ddosguard"
version = "0.1.0"
description = "DDoS detection, mitigation and monitoring toolkit"
requires-python = ">=3.14"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

**`requirements.txt`** (empty for now — we'll fill it as we go):
```
# Add dependencies here as we install them
```

**What you'll learn**:
- How Python packages are structured (folders + `__init__.py`)
- What `pyproject.toml` is and why modern Python uses it instead of `setup.py`
- The difference between `dependencies` (runtime) and dev dependencies (testing)

**Why it matters**: Every Python project needs this structure to be installable, testable, and shareable. Getting it right now saves headaches later.

**Verify**:
```bash
python -c "import ddosguard; print(ddosguard.__file__)"
```
Expected: prints the path to your `ddosguard/__init__.py`.

**Estimated time**: 15 minutes

---

### Step 2: Install Dependencies

**Task**: Install the libraries this project needs.

```bash
pip install scapy>=2.5.0 fastapi>=0.110.0 "uvicorn[standard]>=0.30.0" pyyaml>=6.0.2 pytest>=8.0.0
```

Then update `requirements.txt`:
```
scapy>=2.5.0
fastapi>=0.110.0
uvicorn[standard]>=0.30.0
pyyaml>=6.0.2
pytest>=8.0.0
```

**What you'll learn**:
- What each library does:
  - **scapy**: packet manipulation — creating and parsing network packets
  - **fastapi**: building web APIs quickly
  - **uvicorn**: running FastAPI servers (the ASGI server)
  - **pyyaml**: reading/writing YAML configuration files
  - **pytest**: writing and running unit tests
- How `pip install` works
- Why we pin minimum versions (`>=2.5.0`) but not exact versions

**Why it matters**: You need these tools to build the rest of the project. Understanding what each one does will help you choose the right tool for each job.

**Verify**:
```bash
python -c "import scapy; import fastapi; import yaml; import pytest; print('All imports OK')"
```

**Estimated time**: 10 minutes (plus download time)

---

### Step 3: Version Control Setup

**Task**: Initialize git and make your first commit.

```bash
git init
git config user.name "Your Name"
git config user.email "you@example.com"
```

Create a `.gitignore`:
```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
*.egg

# Virtual environments
venv/
ENV/
.venv/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Data (may contain sensitive info)
data/

# Environments
.env
.env.local

# Test artifacts
.pytest_cache/
.coverage
htmlcov/

# Logs
*.log
logs/
```

Make your first commit:
```bash
git add -A
git commit -m "Initial project structure"
```

**What you'll learn**:
- What git is and why we use it (track changes, revert mistakes, collaborate)
- What a `.gitignore` does (keeps junk out of your repo)
- The basic git workflow: `add` → `commit`

**Why it matters**: You'll make mistakes. Git lets you undo them. It also lets you share your project with others (like uploading to GitHub).

**Verify**:
```bash
git log --oneline
```
Expected: shows your first commit.

**Estimated time**: 10 minutes

---

## Phase 2: Data Models & Traffic

### Step 4: Define Core Data Classes

**Task**: Create `ddosguard/core.py` with the fundamental data structures everything else will use.

Create `ddosguard/core.py`:

```python
"""
Data model shared across the toolkit.

Everything that flows through the pipeline is expressed as plain dataclasses so
it can be unit-tested without touching the network or spawning threads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Dict, List, Optional


class Protocol(IntEnum):
    """IP protocol numbers."""
    OTHER = 0
    TCP = 6
    UDP = 17
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPv6 = 41

    @staticmethod
    def from_int(code: int) -> "Protocol":
        try:
            return Protocol(code)
        except ValueError:
            return Protocol.OTHER


class Severity(IntEnum):
    """Alert severity levels, lowest to highest."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @staticmethod
    def from_str(name: str) -> "Severity":
        return Severity[name.upper()]


# Ordered from most to least severe — used for sorting alerts
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class PacketRecord:
    """A single network packet as seen by the monitor."""
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: Protocol = Protocol.OTHER
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ""          # TCP flags like "S" (SYN), "R" (RST), "SA" (SYN-ACK)
    payload_bytes: int = 0

    @property
    def is_tcp(self) -> bool:
        return self.protocol == Protocol.TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == Protocol.UDP

    @property
    def is_syn(self) -> bool:
        return "S" in self.flags

    @property
    def is_rst(self) -> bool:
        return "R" in self.flags


@dataclass
class TrafficWindow:
    """Aggregated statistics for one fixed-length time window."""
    start: datetime
    end: datetime
    packet_count: int = 0
    byte_count: int = 0
    protocol_counts: Dict[Protocol, int] = field(default_factory=dict)
    syn_count: int = 0
    rst_count: int = 0
    src_ports: Dict[int, int] = field(default_factory=dict)
    dst_ports: Dict[int, int] = field(default_factory=dict)

    def add(self, pkt: PacketRecord) -> None:
        """Add one packet to this window's counters."""
        self.packet_count += 1
        self.byte_count += pkt.length
        self.protocol_counts[pkt.protocol] = self.protocol_counts.get(pkt.protocol, 0) + 1
        if pkt.is_syn:
            self.syn_count += 1
        if pkt.is_rst:
            self.rst_count += 1
        self.src_ports[pkt.src_port] = self.src_ports.get(pkt.src_port, 0) + 1
        self.dst_ports[pkt.dst_port] = self.dst_ports.get(pkt.dst_port, 0) + 1

    @property
    def _seconds(self) -> float:
        return max(0.001, (self.end.timestamp() - self.start.timestamp()))

    def finalize(self) -> "TrafficStats":
        """Convert this window into final statistics."""
        return TrafficStats(
            window=self,
            per_proto={k.value: v for k, v in self.protocol_counts.items()},
            syn_ratio=(self.syn_count / self.packet_count) if self.packet_count else 0.0,
            byte_rate=(self.byte_count / self._seconds) if self._seconds else 0.0,
        )


@dataclass
class TrafficStats:
    """Finalized statistics for one window — the unit detection reasons over."""
    window: TrafficWindow
    per_proto: Dict[int, int] = field(default_factory=dict)
    syn_ratio: float = 0.0
    byte_rate: float = 0.0

    @property
    def packet_rate(self) -> float:
        return self.window.packet_count / self.window._seconds


@dataclass
class BaselineStats:
    """Statistical summary for one metric bucket (e.g. hour 14 on weekdays)."""
    mean: float = 0.0
    stdev: float = 0.0
    count: int = 0
    p5: float = 0.0
    p25: float = 0.0
    p75: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    samples: List[float] = field(default_factory=list)

    def add(self, value: float) -> None:
        self.samples.append(value)
        if len(self.samples) > 1000:
            self.samples.pop(0)
        self._recompute()

    def _recompute(self) -> None:
        if not self.samples:
            self.mean = self.stdev = self.p5 = self.p25 = self.p75 = self.p95 = self.p99 = 0.0
            self.count = 0
            return
        n = len(self.samples)
        self.mean = sum(self.samples) / n
        if n > 1:
            variance = sum((v - self.mean) ** 2 for v in self.samples) / (n - 1)
            self.stdev = variance ** 0.5
        else:
            self.stdev = 0.0
        self.p5 = self._percentile(5)
        self.p25 = self._percentile(25)
        self.p75 = self._percentile(75)
        self.p95 = self._percentile(95)
        self.p99 = self._percentile(99)
        self.count = n

    def _percentile(self, p: float) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        k = (p / 100.0) * (len(s) - 1)
        f = int(k)
        c = min(f + 1, len(s) - 1)
        return s[f] + (s[c] - s[f]) * (k - f)


@dataclass
class SignalResult:
    """One anomaly indicator from a detection signal."""
    name: str
    score: float = 0.0        # 0..1
    detail: Dict[str, object] = field(default_factory=dict)
    affected: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "detail": self.detail,
            "affected": self.affected,
        }


@dataclass
class CompositeScore:
    """Combined result of all detection signals."""
    signal_names: List[str] = field(default_factory=list)
    signal_scores: Dict[str, float] = field(default_factory=dict)
    total: float = 0.0        # 0..1
    severity: Severity = Severity.INFO
    classification: str = "unknown"
    window: Optional[TrafficStats] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "signal_names": self.signal_names,
            "signal_scores": {k: round(v, 4) for k, v in self.signal_scores.items()},
            "total": round(self.total, 4),
            "severity": self.severity.name,
            "classification": self.classification,
        }


@dataclass
class Alert:
    """A single notification payload delivered to administrators."""
    alert_id: str
    severity: Severity
    title: str
    summary: str
    attack_indicators: Dict[str, object] = field(default_factory=dict)
    affected_services: List[str] = field(default_factory=list)
    current_mitigation: Dict[str, object] = field(default_factory=dict)
    attack_sources: List[Dict[str, object]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    window: Optional[TrafficStats] = None
    occurred_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.name,
            "title": self.title,
            "summary": self.summary,
            "attack_indicators": self.attack_indicators,
            "affected_services": self.affected_services,
            "current_mitigation": self.current_mitigation,
            "attack_sources": self.attack_sources,
            "recommendations": self.recommendations,
            "window": self.window.to_dict() if self.window else None,
            "occurred_at": self.occurred_at.isoformat(),
        }


@dataclass
class WhitelistedIp:
    """An IP address excluded from mitigation."""
    ip: str
    reason: str = ""
    added_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, object]:
        return {"ip": self.ip, "reason": self.reason, "added_at": self.added_at.isoformat()}


@dataclass
class MitigationAction:
    """One firewall/mitigation rule planned or applied."""
    id: str
    rule_type: str             # "rate_limit" | "block" | "redirect"
    target: str               # IP or port
    action: str               # "allow" | "deny"
    reason: str = ""
    severity: Severity = Severity.LOW
    applied_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "rule_type": self.rule_type,
            "target": self.target,
            "action": self.action,
            "reason": self.reason,
            "severity": self.severity.name,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
        }
```

**What you'll learn**:
- **Dataclasses** (`@dataclass`): Python's way of creating classes that mostly hold data. They auto-generate `__init__`, `__repr__`, and comparison methods.
- **Enums** (`IntEnum`): named constant values that are also integers. `Protocol.TCP` is `6`, `Severity.CRITICAL` is `5`.
- **Properties** (`@property`): methods that look like attributes. `pkt.is_tcp` reads like data but computes on access.
- **Type hints** (`-> bool`, `: str`, `Dict[str, object]`): Python's way of documenting what types functions accept and return. Helps you catch bugs before running code.
- **Default factories** (`field(default_factory=dict)`): how to give a dataclass field a mutable default (like an empty dict) without the classic Python mutable-default trap.
- **The `Optional` type**: a value that can be something or `None`.

**Why it matters**: These are the building blocks of the entire project. Every other module imports from `core.py`. Understanding these structures means you understand what data flows through the system.

**Verify**:
```bash
python -c "
from ddosguard.core import PacketRecord, Protocol, Severity, TrafficWindow, TrafficStats
from datetime import datetime

pkt = PacketRecord(ts=datetime.now(), src_ip='10.0.0.1', dst_ip='10.0.0.2',
                   protocol=Protocol.TCP, src_port=12345, dst_port=80,
                   length=100, flags='S')
print(f'Packet: {pkt.src_ip} -> {pkt.dst_ip} proto={pkt.protocol.name} flags={pkt.flags}')
print(f'Is SYN: {pkt.is_syn}, Is TCP: {pkt.is_tcp}')

win = TrafficWindow(start=datetime.now(), end=datetime.now())
win.add(pkt)
stats = win.finalize()
print(f'Packet rate: {stats.packet_rate:.1f} pps')
print(f'SYN ratio: {stats.syn_ratio:.2f}')
"
```

Expected: prints packet info, `Is SYN: True`, packet rate ~number of packets per second.

**Estimated time**: 30 minutes

---

### Step 5: Understand Network Packets

**Task**: Learn what a network packet is and how Scapy represents one.

Write a small exploration script `explore_packets.py`:

```python
"""Explore how Scapy represents network packets."""
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, RandIP, RandShort, sr1, conf
import json

# Suppress Scapy's verbose output
conf.verb = 0

def describe_packet(pkt):
    """Print human-readable info about a packet."""
    if IP not in pkt:
        print("  Not an IP packet")
        return
    ip = pkt[IP]
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, f"proto-{ip.proto}")
    print(f"  IP: {ip.src} -> {ip.dst}  proto={proto_name}  len={ip.len}")

    if TCP in pkt:
        tcp = pkt[TCP]
        flags_str = ""
        if tcp.flags.S: flags_str += "S"
        if tcp.flags.A: flags_str += "A"
        if tcp.flags.F: flags_str += "F"
        if tcp.flags.R: flags_str += "R"
        if tcp.flags.P: flags_str += "P"
        if tcp.flags.U: flags_str += "U"
        print(f"    TCP: sport={tcp.sport} dport={tcp.dport} flags='{flags_str}' seq={tcp.seq}")
    elif UDP in pkt:
        udp = pkt[UDP]
        print(f"    UDP: sport={udp.sport} dport={udp.dport} len={udp.len}")
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        print(f"    ICMP: type={icmp.type} code={icmp.code}")

    if Raw in pkt:
        raw = pkt[Raw]
        data_preview = raw.load[:50] if len(raw.load) > 50 else raw.load
        print(f"    Payload: {data_preview!r}")

print("=== Creating packets with Scapy ===\n")

# A normal HTTP request (TCP SYN to port 80)
print("1. Normal TCP SYN to web server:")
syn_pkt = Ether() / IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S")
describe_packet(syn_pkt)

# A UDP packet (DNS query style)
print("\n2. UDP packet (like DNS):")
udp_pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=54321, dport=53) / Raw(load=b"DNS query data")
describe_packet(udp_pkt)

# A SYN flood sample (many SYN packets without completing the handshake)
print("\n3. SYN flood packet (malicious):")
syn_flood_pkt = Ether() / IP(src=RandIP(), dst="93.184.216.34") / TCP(sport=RandShort(), dport=80, flags="S")
describe_packet(syn_flood_pkt)

print("\n=== Protocol numbers ===")
for name, num in [("ICMP", 1), ("TCP", 6), ("UDP", 17)]:
    print(f"  {name}: {num}")

print("\n=== TCP Flags ===")
print("  S = SYN (start connection)")
print("  A = ACK (acknowledge)")
print("  F = FIN (finish connection)")
print("  R = RST (reset connection)")
print("  P = PSH (push data)")
print("  U = URG (urgent)")
print("\n  Common combinations:")
print("    SA = SYN-ACK (server responding to SYN)")
print("    S = SYN (client starting connection)")
print("    R = RST (reset — often used in attacks)")
print("    PA = PSH-ACK (normal data transfer)")

print("\n=== What is a DDoS attack? ===")
print("""
A Distributed Denial of Service (DDoS) attack tries to overwhelm a target
with more traffic than it can handle. Common types:

1. VOLUMETRIC ATTACK — flood the target with huge amounts of data
   - UDP floods: send random UDP packets to random ports
   - The goal: saturate the network bandwidth

2. PROTOCOL ATTACK — exploit how network protocols work
   - SYN flood: send many SYN packets but never complete the handshake
   - The server allocates resources for each half-open connection
   - Eventually the server runs out of resources

3. APPLICATION LAYER ATTACK — target specific services
   - HTTP flood: send many HTTP requests to a specific URL
   - Slowloris: open many connections and keep them open slowly
   - The goal: exhaust the application's resources (CPU, memory, threads)
""")

print("\n=== Running a live packet capture (will fail without Npcap on Windows) ===")
try:
    # This will fail on Windows without Npcap installed
    pkt_count = 0
    def packet_handler(pkt):
        global pkt_count
        if IP in pkt:
            pkt_count += 1
            if pkt_count <= 3:
                describe_packet(pkt)
    print("  Sniffing for 2 seconds... (this may fail without Npcap)")
    sniff(timeout=2, prn=packet_handler)
    print(f"  Captured {pkt_count} IP packets")
except Exception as e:
    print(f"  Expected failure: {e}")
    print("  (Install Npcap/WinPcap for live capture on Windows)")
```

Run it:
```bash
python explore_packets.py
```

**What you'll learn**:
- What IP packets look like: source/destination IP, protocol number, payload
- TCP flags and what they mean (SYN, ACK, RST, etc.)
- The three main DDoS attack types: volumetric (UDP flood), protocol (SYN flood), application layer
- How Scapy creates and inspects packets
- Why live capture needs Npcap on Windows

**Why it matters**: You can't detect attacks if you don't understand what normal and malicious traffic look like. This knowledge is the foundation of the detection signals you'll write later.

**Verify**: The script runs and prints packet descriptions, protocol numbers, flag meanings, and the DDoS explanation. The live capture part may fail (expected on Windows without Npcap).

**Estimated time**: 20 minutes

---

### Step 6: Create a Synthetic Packet Generator

**Task**: Build `ddosguard/capture/base.py` — a class that generates fake network packets for testing and demos, plus an abstract base class for all packet sources.

```python
"""
Pluggable packet sources: synthetic generator, pcap replay, and live capture.

The synthetic generator produces fake traffic shaped like real networks:
- Normal diurnal patterns (more traffic during the day, less at night)
- Three attack families: volumetric UDP flood, SYN flood, application-layer flood
"""
from __future__ import annotations

import random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Iterator, Optional

from ddosguard.core import PacketRecord, Protocol


class PacketSource(ABC):
    """Abstract base class for all packet sources."""

    @abstractmethod
    def iter_packets(self, window_seconds: float, delay: float = 0.0) -> Iterator[PacketRecord]:
        """Yield PacketRecord objects indefinitely (or until the source is exhausted)."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this source."""
        ...


# ---------------------------------------------------------------------------
# Synthetic generator — fake traffic for demos and tests
# ---------------------------------------------------------------------------

class SyntheticGenerator(PacketSource):
    """
    Generates synthetic packet streams resembling real network traffic.

    Normal mode:
      - Diurnal pattern: higher packet rates during "day" hours, lower at "night"
      - Mixed protocols: ~70% TCP, ~25% UDP, ~5% ICMP
      - Legitimate-looking traffic to common ports (80, 443, 22, 53, etc.)

    Attack mode:
      - Generates one of three attack families for a configurable duration
      - volumetric: high-rate UDP packets to random ports (bandwidth saturation)
      - syn_flood: high-rate TCP SYN packets to a single target (resource exhaustion)
      - application: high-rate TCP packets to a single service port (app-layer exhaustion)
    """

    def __init__(
        self,
        mode: str = "normal",          # "normal" or "attack"
        attack_family: str = "volumetric",
        attack_start: Optional[datetime] = None,
        attack_duration: float = 30.0,
        attack_mult: float = 20.0,     # how much louder the attack is vs normal
        base_rate: float = 50.0,       # packets per second during normal traffic
        src_ip_base: str = "192.168.1",
        dst_ip: str = "10.0.0.1",
    ):
        self.mode = mode
        self.attack_family = attack_family
        self.attack_start = attack_start or datetime.now()
        self.attack_end = self.attack_start + timedelta(seconds=attack_duration)
        self.attack_mult = attack_mult
        self.base_rate = base_rate
        self.src_ip_base = src_ip_base
        self.dst_ip = dst_ip
        self._counter = 0
        self._last_ts = datetime.now()

    @property
    def name(self) -> str:
        return f"synthetic-{self.mode}"

    def iter_packets(self, window_seconds: float, delay: float = 0.0) -> Iterator[PacketRecord]:
        """Generate packets for one window worth of time."""
        now = datetime.now()

        if self.mode == "attack" and self.attack_start <= now < self.attack_end:
            # We're in the attack window — generate attack traffic
            yield from self._generate_attack_packets(window_seconds, now)
        else:
            # Normal traffic
            yield from self._generate_normal_packets(window_seconds, now)

    def _generate_normal_packets(self, window_seconds: float, now: datetime) -> Iterator[PacketRecord]:
        """Generate normal-looking traffic for one window."""
        # Diurnal rate adjustment: more traffic during "day" (8am-8pm), less at night
        hour = now.hour + now.minute / 60.0
        if 8 <= hour < 20:
            rate_multiplier = 1.5   # busier during the day
        elif 6 <= hour < 8 or 20 <= hour < 22:
            rate_multiplier = 1.0   # moderate
        else:
            rate_multiplier = 0.4   # quiet at night

        target_rate = self.base_rate * rate_multiplier
        packet_count = int(target_rate * window_seconds)

        common_ports = [80, 443, 22, 53, 8080, 8443, 3306, 5432, 6379, 25]
        protocols = [Protocol.TCP] * 70 + [Protocol.UDP] * 25 + [Protocol.ICMP] * 5

        for i in range(packet_count):
            ts = now - timedelta(seconds=random.uniform(0, window_seconds))
            src_ip = f"{self.src_ip_base}.{random.randint(1, 254)}"
            dst_port = random.choice(common_ports)
            protocol = random.choice(protocols)

            if protocol == Protocol.TCP:
                flags = random.choices(["S", "SA", "PA", "A", "F", "R"], weights=[30, 25, 25, 10, 5, 5])[0]
            elif protocol == Protocol.UDP:
                flags = ""
            else:
                flags = ""

            yield PacketRecord(
                ts=ts,
                src_ip=src_ip,
                dst_ip=self.dst_ip,
                protocol=protocol,
                src_port=random.randint(1024, 65535),
                dst_port=dst_port,
                length=random.randint(40, 1500),
                flags=flags,
            )

    def _generate_attack_packets(self, window_seconds: float, now: datetime) -> Iterator[PacketRecord]:
        """Generate attack traffic for one window."""
        # Attack rate is much higher than normal
        target_rate = self.base_rate * self.attack_mult
        packet_count = int(target_rate * window_seconds)

        if self.attack_family == "volumetric":
            yield from self._volumetric_attack(packet_count, now)
        elif self.attack_family == "syn_flood":
            yield from self._syn_flood_attack(packet_count, now)
        elif self.attack_family == "application":
            yield from self._application_attack(packet_count, now)
        else:
            yield from self._volumetric_attack(packet_count, now)

    def _volumetric_attack(self, count: int, now: datetime) -> Iterator[PacketRecord]:
        """Volumetric UDP flood — saturate bandwidth with large UDP packets."""
        for i in range(count):
            ts = now - timedelta(seconds=random.uniform(0, 1.0))
            yield PacketRecord(
                ts=ts,
                src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                dst_ip=self.dst_ip,
                protocol=Protocol.UDP,
                src_port=random.randint(1024, 65535),
                dst_port=random.randint(1, 65535),   # random destination ports
                length=random.randint(512, 1500),     # large packets
                flags="",
            )

    def _syn_flood_attack(self, count: int, now: datetime) -> Iterator[PacketRecord]:
        """SYN flood — many half-open TCP connections."""
        for i in range(count):
            ts = now - timedelta(seconds=random.uniform(0, 1.0))
            yield PacketRecord(
                ts=ts,
                src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                dst_ip=self.dst_ip,
                protocol=Protocol.TCP,
                src_port=random.randint(1024, 65535),
                dst_port=80,                           # target the web server
                length=64,
                flags="S",                             # SYN only — never completes handshake
            )

    def _application_attack(self, count: int, now: datetime) -> Iterator[PacketRecord]:
        """Application-layer flood — target a specific service."""
        for i in range(count):
            ts = now - timedelta(seconds=random.uniform(0, 1.0))
            yield PacketRecord(
                ts=ts,
                src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                dst_ip=self.dst_ip,
                protocol=Protocol.TCP,
                src_port=random.randint(1024, 65535),
                dst_port=8080,                         # target a specific service
                length=random.randint(200, 500),
                flags="PA",                            # PSH-ACK — sending data
            )
```

Add a quick export at the bottom of the file to make `SyntheticGenerator` easily importable:
```python
__all__ = ["PacketSource", "SyntheticGenerator"]
```

**What you'll learn**:
- **ABCs (Abstract Base Classes)**: how to define an interface that multiple implementations must follow. `PacketSource` says "any packet source must have `iter_packets()` and `name`". This lets you swap sources without changing the rest of the code.
- **Generators** (`yield`): functions that produce values one at a time instead of building a huge list in memory. This is how you stream packets efficiently.
- **Diurnal patterns**: real networks have busy hours and quiet hours. Modeling this makes your baseline more realistic.
- **Attack families**: the three classic DDoS types and how they differ in packet characteristics:
  - Volumetric: many large UDP packets to random ports
  - SYN flood: many TCP SYN packets (half-open connections)
  - Application: many TCP packets with data to a specific service port

**Why it matters**: You need packets to test your detection system. Real pcap files are hard to get and share. A synthetic generator gives you unlimited, reproducible test traffic that you fully control.

**Verify**:
```bash
python -c "
from ddosguard.capture.base import SyntheticGenerator
from datetime import datetime, timedelta

gen = SyntheticGenerator(mode='normal', base_rate=100)
packets = list(gen.iter_packets(1.0))
print(f'Generated {len(packets)} normal packets in 1 second')
print(f'Sample: {packets[0].src_ip} -> {packets[0].dst_ip} proto={packets[0].protocol.name}')

# Attack mode
attack_gen = SyntheticGenerator(
    mode='attack',
    attack_family='syn_flood',
    attack_start=datetime.now(),
    attack_duration=10,
    attack_mult=50,
)
attack_packets = list(attack_gen.iter_packets(1.0))
syn_count = sum(1 for p in attack_packets if p.is_syn)
print(f'Generated {len(attack_packets)} attack packets, {syn_count} are SYN')
"
```

Expected: normal mode generates ~100 packets/sec with mixed protocols. Attack mode generates many SYN packets.

**Estimated time**: 30 minutes

---

## Phase 3: Windowing & Metrics

### Step 7: Build the Window Aggregator

**Task**: Create `ddosguard/metrics/window.py` — the class that collects packets into fixed-length windows and produces statistics.

A **time window** is a fixed-duration slice of time (e.g., 10 seconds). The aggregator accumulates packets into the current window, then when the window is "full", it emits a `TrafficStats` snapshot and resets for the next window.

```python
"""
Windowed traffic aggregation: collect packets into fixed-duration windows
and produce TrafficStats snapshots for the detection pipeline.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from ddosguard.core import PacketRecord, Protocol, TrafficStats, TrafficWindow


class WindowAggregator:
    """
    Collects packets into a fixed-duration window and finalizes them into
    TrafficStats when the window is complete.

    Usage:
        agg = WindowAggregator(window_seconds=10)
        for pkt in source.iter_packets(10):
            agg.add(pkt)
            if agg.is_window_complete(pkt.ts):
                stats = agg.finalize()
                # ... do something with stats ...
                agg.reset()
    """

    def __init__(self, window_seconds: float = 10.0):
        self.window_seconds = window_seconds
        self._window: Optional[TrafficWindow] = None
        self._first_ts: Optional[datetime] = None

    @property
    def start(self) -> datetime:
        """Start time of the current window."""
        if self._first_ts:
            return self._first_ts
        if self._window:
            return self._window.start
        return datetime.now()

    def add(self, pkt: PacketRecord) -> None:
        """Add a packet to the current window."""
        if self._window is None:
            self._window = TrafficWindow(start=pkt.ts, end=pkt.ts)
            self._first_ts = pkt.ts
        self._window.add(pkt)
        self._window.end = pkt.ts

    def is_window_complete(self, pkt_ts: datetime) -> bool:
        """Check if the current window has exceeded its duration."""
        if self._window is None or self._first_ts is None:
            return False
        elapsed = (pkt_ts - self._first_ts).total_seconds()
        return elapsed >= self.window_seconds

    def finalize(self) -> TrafficStats:
        """Finalize the current window into TrafficStats."""
        if self._window is None:
            raise RuntimeError("No window to finalize — call add() first")
        stats = self._window.finalize()
        self._window = None
        self._first_ts = None
        return stats

    def reset(self) -> None:
        """Reset the aggregator for a new window."""
        self._window = None
        self._first_ts = None
```

**What you'll learn**:
- **Time windows**: the fundamental idea behind streaming metrics. You don't analyze individual packets; you analyze aggregates over time slices.
- **The finalize pattern**: accumulate data, then produce a snapshot. This separates data collection from analysis, making both easier to test.
- **State management**: the aggregator holds state (`_window`, `_first_ts`) that evolves as packets arrive. Resetting clears that state for the next window.

**Why it matters**: The window aggregator is the bridge between raw packets and the statistics that detection signals reason over. Without it, you'd be trying to detect attacks from single packets — impossible for volumetric attacks that need volume over time.

**Verify**:
```bash
python -c "
from ddosguard.metrics.window import WindowAggregator
from ddosguard.capture.base import SyntheticGenerator
from datetime import datetime, timedelta

gen = SyntheticGenerator(mode='normal', base_rate=200)
agg = WindowAggregator(window_seconds=1.0)

packets = list(gen.iter_packets(2.0))
for pkt in packets:
    agg.add(pkt)
    if agg.is_window_complete(pkt.ts):
        stats = agg.finalize()
        print(f'Window: {stats.packet_rate:.1f} pps, {stats.byte_rate:.0f} B/s, syn_ratio={stats.syn_ratio:.2f}')
        agg.reset()
"
```

Expected: prints window stats with packet rate matching the generator's base rate.

**Estimated time**: 20 minutes

---

### Step 8: Add Rolling Window Support

**Task**: Extend `ddosguard/metrics/window.py` with a `RollingAggregator` — a variant that keeps a ring buffer of recent windows for trend analysis.

A **rolling window** maintains the last N windows and can compute statistics over them (e.g., "average packet rate over the last 5 windows"). This is useful for detecting trends — is traffic gradually increasing? Is this a sustained attack or a brief spike?

```python
from collections import deque


class RollingAggregator:
    """
    Maintains a rolling window of recent traffic statistics.

    Keeps the last N window snapshots in a ring buffer and can compute
    sliding-window statistics (mean, max, trend) over them.

    Useful for:
      - Detecting gradual increases (trend analysis)
      - Smoothing out brief spikes
      - Comparing current window to recent history
    """

    def __init__(self, window_seconds: float = 10.0, num_windows: int = 5):
        self.window_seconds = window_seconds
        self.num_windows = num_windows
        self._buffer: deque[TrafficStats] = deque(maxlen=num_windows)
        self._current: Optional[WindowAggregator] = WindowAggregator(window_seconds)
        self._first_ts: Optional[datetime] = None

    def add(self, pkt: PacketRecord) -> None:
        """Add a packet to the current window."""
        if self._current is None:
            self._current = WindowAggregator(self.window_seconds)
        self._current.add(pkt)
        if self._first_ts is None:
            self._first_ts = pkt.ts

    def _maybe_commit(self, pkt_ts: datetime) -> bool:
        """Commit the current window if it's complete. Returns True if committed."""
        if self._current is None or self._first_ts is None:
            return False
        if (pkt_ts - self._first_ts).total_seconds() >= self.window_seconds:
            stats = self._current.finalize()
            self._buffer.append(stats)
            self._current = WindowAggregator(self.window_seconds)
            self._first_ts = pkt_ts
            return True
        return False

    def add_and_commit(self, pkt: PacketRecord) -> Optional[TrafficStats]:
        """Add a packet and commit the window if complete. Returns stats if committed."""
        self.add(pkt)
        return self._maybe_commit(pkt.ts)

    @property
    def current_window(self) -> Optional[TrafficStats]:
        """The most recent committed window, or None."""
        return self._buffer[-1] if self._buffer else None

    @property
    def windows(self) -> List[TrafficStats]:
        """All committed windows, most recent last."""
        return list(self._buffer)

    def mean_packet_rate(self) -> float:
        """Mean packet rate over all committed windows."""
        if not self._buffer:
            return 0.0
        return sum(w.packet_rate for w in self._buffer) / len(self._buffer)

    def max_packet_rate(self) -> float:
        """Maximum packet rate over all committed windows."""
        if not self._buffer:
            return 0.0
        return max(w.packet_rate for w in self._buffer)

    def trend(self) -> float:
        """
        Trend indicator: positive = increasing, negative = decreasing.
        Computed as the slope between the first and last window's packet rate.
        Returns 0 if fewer than 2 windows.
        """
        if len(self._buffer) < 2:
            return 0.0
        windows = list(self._buffer)
        first_rate = windows[0].packet_rate
        last_rate = windows[-1].packet_rate
        return last_rate - first_rate
```

Update the `__all__` at the end of the file:
```python
__all__ = ["WindowAggregator", "RollingAggregator"]
```

**What you'll learn**:
- **Ring buffers** (`collections.deque(maxlen=N)`): a data structure that automatically discards old items when full. Perfect for "keep the last N things" scenarios.
- **Trend analysis**: comparing recent values to detect direction (increasing/decreasing). This is a simple form of anomaly detection — a sudden jump in the trend can indicate an attack starting.
- **Sliding windows vs fixed windows**: fixed windows give you discrete snapshots; rolling windows give you a continuous view of recent history.

**Why it matters**: Real attacks don't always start as a sudden spike. Sometimes traffic gradually increases as an attacker ramps up. Rolling windows help you catch both patterns.

**Verify**:
```bash
python -c "
from ddosguard.metrics.window import RollingAggregator
from ddosguard.capture.base import SyntheticGenerator
from datetime import datetime, timedelta

gen = SyntheticGenerator(mode='normal', base_rate=100)
roll = RollingAggregator(window_seconds=1.0, num_windows=5)

# Feed 7 windows of packets
for i in range(7):
    packets = list(gen.iter_packets(1.0))
    for pkt in packets:
        result = roll.add_and_commit(pkt)
    if result:
        print(f'Window {i+1}: {result.packet_rate:.1f} pps')

print(f'\\nMean rate: {roll.mean_packet_rate():.1f} pps')
print(f'Max rate: {roll.max_packet_rate():.1f} pps')
print(f'Trend: {roll.trend():.1f} (positive = increasing)')
"
```

Expected: prints 5+ windows of stats, mean/max rates, and a trend value.

**Estimated time**: 20 minutes

---

### Step 9: Write Tests for Windowing

**Task**: Create `tests/test_metrics.py` with unit tests for the window aggregator.

```python
"""Tests for window aggregation — no network, no permissions required."""
import pytest
from datetime import datetime, timedelta
from ddosguard.metrics.window import WindowAggregator, RollingAggregator
from ddosguard.core import PacketRecord, Protocol


def make_pkt(ts: datetime, protocol: Protocol = Protocol.TCP, flags: str = "",
             length: int = 100, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2",
             src_port: int = 12345, dst_port: int = 80) -> PacketRecord:
    """Helper to create a PacketRecord with sensible defaults."""
    return PacketRecord(
        ts=ts, src_ip=src_ip, dst_ip=dst_ip,
        protocol=protocol, src_port=src_port, dst_port=dst_port,
        length=length, flags=flags,
    )


class TestWindowAggregator:
    """Tests for the fixed-window aggregator."""

    def test_add_packet_increments_count(self):
        agg = WindowAggregator(window_seconds=10.0)
        ts = datetime.now()
        pkt = make_pkt(ts)
        agg.add(pkt)
        assert agg._window is not None
        assert agg._window.packet_count == 1
        assert agg._window.byte_count == 100

    def test_multiple_packets_accumulated(self):
        agg = WindowAggregator(window_seconds=10.0)
        base = datetime.now()
        for i in range(5):
            pkt = make_pkt(base + timedelta(seconds=i), length=100 + i * 10)
            agg.add(pkt)
        assert agg._window.packet_count == 5
        assert agg._window.byte_count == 500 + 10 * (0 + 1 + 2 + 3 + 4)  # 500 + 100 = 600

    def test_finalize_produces_stats(self):
        agg = WindowAggregator(window_seconds=10.0)
        ts = datetime.now()
        for i in range(10):
            pkt = make_pkt(ts + timedelta(seconds=i), protocol=Protocol.TCP if i % 2 == 0 else Protocol.UDP)
            agg.add(pkt)
        stats = agg.finalize()
        assert stats.packet_rate > 0
        assert stats.window.packet_count == 10

    def test_syn_count_tracked(self):
        agg = WindowAggregator(window_seconds=10.0)
        ts = datetime.now()
        agg.add(make_pkt(ts, flags="S"))   # SYN
        agg.add(make_pkt(ts + timedelta(seconds=1), flags="PA"))  # not SYN
        agg.add(make_pkt(ts + timedelta(seconds=2), flags="S"))   # SYN
        stats = agg.finalize()
        assert stats.window.syn_count == 2

    def test_reset_clears_state(self):
        agg = WindowAggregator(window_seconds=10.0)
        agg.add(make_pkt(datetime.now()))
        agg.reset()
        assert agg._window is None
        assert agg._first_ts is None

    def test_window_duration_respected(self):
        agg = WindowAggregator(window_seconds=5.0)
        base = datetime.now()
        # Add packets spanning 6 seconds — should trigger completion at 5 seconds
        for i in range(6):
            pkt = make_pkt(base + timedelta(seconds=i))
            agg.add(pkt)
            if agg.is_window_complete(pkt.ts):
                stats = agg.finalize()
                assert stats.window.packet_count >= 1
                agg.reset()
                break


class TestRollingAggregator:
    """Tests for the rolling-window aggregator."""

    def test_commits_windows(self):
        roll = RollingAggregator(window_seconds=1.0, num_windows=3)
        base = datetime.now()
        committed = 0
        for i in range(5):
            pkt = make_pkt(base + timedelta(seconds=i + 0.5))
            result = roll.add_and_commit(pkt)
            if result is not None:
                committed += 1
        assert committed >= 1  # at least one window should have committed

    def test_mean_packet_rate(self):
        roll = RollingAggregator(window_seconds=1.0, num_windows=3)
        base = datetime.now()
        # Feed exactly 3 windows of 10 packets each
        for window_idx in range(3):
            for i in range(10):
                pkt = make_pkt(base + timedelta(seconds=window_idx + i * 0.1))
                result = roll.add_and_commit(pkt)
        mean = roll.mean_packet_rate()
        assert mean > 0

    def test_trend_increase(self):
        roll = RollingAggregator(window_seconds=1.0, num_windows=3)
        base = datetime.now()
        # Window 1: 10 packets, Window 2: 20 packets, Window 3: 30 packets
        rates = [10, 20, 30]
        for window_idx, rate in enumerate(rates):
            for i in range(rate):
                pkt = make_pkt(base + timedelta(seconds=window_idx + i * 0.1))
                roll.add_and_commit(pkt)
        trend = roll.trend()
        assert trend > 0  # increasing

    def test_trend_decrease(self):
        roll = RollingAggregator(window_seconds=1.0, num_windows=3)
        base = datetime.now()
        rates = [30, 20, 10]
        for window_idx, rate in enumerate(rates):
            for i in range(rate):
                pkt = make_pkt(base + timedelta(seconds=window_idx + i * 0.1))
                roll.add_and_commit(pkt)
        trend = roll.trend()
        assert trend < 0  # decreasing

    def test_empty_buffer_returns_zero(self):
        roll = RollingAggregator(window_seconds=1.0, num_windows=3)
        assert roll.mean_packet_rate() == 0.0
        assert roll.max_packet_rate() == 0.0
        assert roll.trend() == 0.0
```

Run the tests:
```bash
python -m pytest tests/test_metrics.py -v
```

**What you'll learn**:
- **Unit test structure** with pytest: `test_` prefix, `assert` statements, test classes for grouping
- **Test fixtures/helpers**: the `make_pkt()` helper reduces repetition
- **Testing edge cases**: empty buffer, reset behavior, window boundary conditions
- **What "no network, no permissions" means**: these tests use synthetic data and pure computation — they never touch the network or require special OS permissions

**Why it matters**: Automated tests give you confidence that your code works and stays working as you change it. They also serve as documentation — reading the tests tells you what the code is supposed to do.

**Verify**: All tests pass:
```
python -m pytest tests/test_metrics.py -v
```
Expected: 10 tests, all passing (✓).

**Estimated time**: 30 minutes

---

## Phase 4: Baseline System

### Step 10: Understand Baselines and Diurnal Patterns

**Task**: Learn the concept of a traffic baseline and why time-of-day matters.

Read this explanation (no code yet):

```
WHAT IS A BASELINE?
===================

A baseline is a statistical model of "normal" traffic. It answers the question:
"What traffic rate should I expect at this time of day, on this day of the week?"

Why time-of-day matters:
- A web server gets more traffic at 2pm than at 2am
- A corporate network is busy during business hours, quiet at night
- If you compare 2am traffic to the 2pm baseline, you'll get false alarms

DIURNAL BUCKETS
================
A diurnal bucket is a statistical summary for a specific time slot:
- "weekday-14" = weekdays at 14:00 (2pm)
- "weekend-3" = weekends at 03:00 (3am)
- "weekday-8" = weekdays at 08:00 (8am, start of business)

Each bucket stores:
- mean: average packet rate (or byte rate, or whatever metric)
- stdev: how much variation is normal
- percentiles: p5, p25, p75, p95, p99 — useful for setting thresholds

STATISTICAL THRESHOLDS
=======================
A common approach: flag traffic as anomalous if it exceeds:
  mean + 2 * stdev   (about 95th percentile for normal distribution)
  mean + 3 * stdev   (about 99th percentile)

This adapts to each time bucket independently, so 2am traffic is compared
to the 2am baseline, not the 2pm baseline.

RESERVOIR SAMPLING
==================
To keep memory bounded, we keep a "reservoir" of recent observations.
When the reservoir is full, old values are evicted (FIFO — first in, first out).
Statistics are recomputed from whatever is in the reservoir.

This gives us a baseline that adapts to changing traffic patterns over time,
without storing every historical observation forever.
```

**What you'll learn**:
- The statistical foundation of anomaly detection: comparing observations to a model of normal
- Why context matters (time of day, day of week)
- The concept of standard deviations as a threshold mechanism
- Reservoir sampling as a memory-bounded way to maintain running statistics

**Why it matters**: The baseline is the "normal" reference that all detection signals compare against. A good baseline = fewer false alarms. A bad baseline = either missed attacks or constant false positives.

**Verify**: No code to run — this is a conceptual step. You should be able to explain:
1. What a diurnal bucket is and why we need them
2. How mean + 2*stdev works as a threshold
3. Why we use reservoir sampling

**Estimated time**: 10 minutes

---

### Step 11: Implement the Baseline Store

**Task**: Create `ddosguard/baseline/store.py` — the class that maintains diurnal baseline buckets, observes traffic, and persists to disk.

```python
"""
Statistical baseline models keyed by diurnal buckets.

Buckets:
  - "weekday-HH" for Monday-Friday, hour HH (0-23)
  - "weekend-HH" for Saturday-Sunday, hour HH (0-23)

Each bucket holds a BaselineStats (mean, stdev, percentiles) computed from
a reservoir of observed values.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, Optional

from ddosguard.core import BaselineStats, TrafficStats
from ddosguard.config import Config


class BaselineStore:
    """
    Maintains statistical baselines for traffic metrics, keyed by diurnal buckets.

    Usage:
        store = BaselineStore(config)
        store.observe(stats, timestamp)   # record an observation
        expected = store.expected("packet_rate", timestamp)  # get expected value
        store.save()                       # persist to disk
        store.load()                       # load from disk
    """

    def __init__(self, config: Config, data_dir: str = "data"):
        self.config = config
        self.data_dir = data_dir
        self.buckets: Dict[str, BaselineStats] = {}
        self._ready = False

    def set_ready(self, ready: bool) -> None:
        """Mark the baseline as trained and ready for detection."""
        self._ready = ready

    @property
    def is_ready(self) -> bool:
        """Whether the baseline has been trained."""
        return self._ready

    def _bucket_key(self, ts: datetime) -> str:
        """Get the diurnal bucket key for a timestamp."""
        weekday = ts.weekday()  # 0=Monday, 6=Sunday
        hour = ts.hour
        if weekday < 5:  # Monday-Friday
            return f"weekday-{hour}"
        else:  # Saturday-Sunday
            return f"weekend-{hour}"

    def observe(self, stats: TrafficStats, ts: datetime) -> None:
        """
        Observe one window of traffic and update the appropriate bucket.

        Records multiple metrics per window:
          - packet_rate
          - byte_rate
          - syn_ratio
        """
        # Always observe — even during warmup, so the baseline can start forming
        for metric_name, value in [
            ("packet_rate", stats.packet_rate),
            ("byte_rate", stats.byte_rate),
            ("syn_ratio", stats.syn_ratio),
        ]:
            key = self._bucket_key(ts)
            metric_key = f"{key}:{metric_name}"
            if metric_key not in self.buckets:
                self.buckets[metric_key] = BaselineStats()
            self.buckets[metric_key].add(value)

    def expected(self, metric: str, ts: datetime) -> float:
        """
        Get the expected (mean) value for a metric at a given time.

        Returns 0 if no baseline data exists for this bucket.
        """
        key = self._bucket_key(ts)
        metric_key = f"{key}:{metric}"
        if metric_key in self.buckets:
            return self.buckets[metric_key].mean
        return 0.0

    def expected_with_stdev(self, metric: str, ts: datetime) -> tuple[float, float]:
        """
        Get the expected mean and standard deviation for a metric.

        Returns (0.0, 0.0) if no baseline data exists.
        """
        key = self._bucket_key(ts)
        metric_key = f"{key}:{metric}"
        if metric_key in self.buckets:
            model = self.buckets[metric_key]
            return model.mean, model.stdev
        return 0.0, 0.0

    def all(self) -> Dict[str, BaselineStats]:
        """Return all buckets."""
        return dict(self.buckets)

    def save(self) -> None:
        """Persist the baseline to disk as JSON."""
        os.makedirs(self.data_dir, exist_ok=True)
        path = os.path.join(self.data_dir, "baseline.json")
        data = {}
        for key, stats in self.buckets.items():
            data[key] = {
                "mean": stats.mean,
                "stdev": stats.stdev,
                "count": stats.count,
                "p5": stats.p5,
                "p25": stats.p25,
                "p75": stats.p75,
                "p95": stats.p95,
                "p99": stats.p99,
                "samples": stats.samples,
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self) -> None:
        """Load the baseline from disk."""
        path = os.path.join(self.data_dir, "baseline.json")
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, values in data.items():
            stats = BaselineStats(
                mean=values.get("mean", 0.0),
                stdev=values.get("stdev", 0.0),
                count=values.get("count", 0),
                p5=values.get("p5", 0.0),
                p25=values.get("p25", 0.0),
                p75=values.get("p75", 0.0),
                p95=values.get("p95", 0.0),
                p99=values.get("p99", 0.0),
                samples=values.get("samples", []),
            )
            self.buckets[key] = stats
```

Add exports:
```python
__all__ = ["BaselineStore", "BaselineStats"]
```

**What you'll learn**:
- **Persistence** (save/load): how to save data to disk and reload it later. JSON is a simple, human-readable format.
- **Diurnal bucketing in code**: the `_bucket_key()` method translates a timestamp into a bucket name. This is the core of the time-of-day model.
- **Multi-metric baselines**: we track packet_rate, byte_rate, and syn_ratio separately, each with its own bucket. Different metrics have different normal ranges.
- **Graceful fallbacks**: `expected()` returns 0 if no data exists, rather than crashing. This is important during the early training period.

**Why it matters**: The baseline store is what makes detection adaptive. Without it, you'd need fixed thresholds that don't account for time-of-day patterns. With it, the system learns what's normal for each hour of each type of day.

**Verify**:
```bash
python -c "
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import TrafficStats, TrafficWindow
from datetime import datetime, timedelta

config = Config.load('config.yaml') if __import__('os').path.exists('config.yaml') else Config.load(None)
store = BaselineStore(config, data_dir='data')
store.set_ready(True)

# Simulate observing 10 windows of normal traffic
base = datetime.now()
for i in range(10):
    ts = base + timedelta(seconds=i * 10)
    # Create fake stats
    window = TrafficWindow(start=ts - timedelta(seconds=10), end=ts)
    for j in range(50):  # 50 packets per window
        window.add(type('P', (), {'ts': ts, 'length': 100, 'protocol': 6,
                                    'is_syn': False, 'is_rst': False,
                                    'src_port': 12345, 'dst_port': 80,
                                    'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2'})())
    stats = window.finalize()
    store.observe(stats, ts)

print(f'Buckets created: {len(store.all())}')
print(f'Expected packet_rate at now: {store.expected(\"packet_rate\", datetime.now()):.2f}')
print(f'Baseline saved to data/baseline.json')

# Reload and verify
store2 = BaselineStore(config, data_dir='data')
store2.load()
print(f'Loaded buckets: {len(store2.all())}')
print(f'Expected after reload: {store2.expected(\"packet_rate\", datetime.now()):.2f}')
"
```

Expected: creates buckets, saves to JSON, reloads, and shows matching expected values.

**Estimated time**: 30 minutes

---

### Step 12: Write Baseline Tests

**Task**: Create `tests/test_baseline.py` with tests for the baseline store.

```python
"""Tests for the baseline store — no network, no permissions required."""
import json
import os
import pytest
import tempfile
from datetime import datetime, timedelta
from ddosguard.baseline.store import BaselineStore
from ddosguard.core import BaselineStats, TrafficStats, TrafficWindow, Protocol
from ddosguard.config import Config


def make_stats(packet_rate: float, byte_rate: float, syn_ratio: float = 0.0) -> TrafficStats:
    """Create fake TrafficStats with specified rates."""
    now = datetime.now()
    window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    window.packet_count = int(packet_rate * 10)
    window.byte_count = int(byte_rate * 10)
    return TrafficStats(
        window=window,
        per_proto={6: int(packet_rate * 10 * 0.7), 17: int(packet_rate * 10 * 0.3)},
        syn_ratio=syn_ratio,
        byte_rate=byte_rate,
    )


class TestBaselineStore:
    """Tests for diurnal bucketing and persistence."""

    def test_bucket_key_weekday(self):
        store = BaselineStore(Config.load(None))
        ts = datetime(2026, 11, 2, 14, 30)  # Monday, 2:30pm
        assert store._bucket_key(ts) == "weekday-14"

    def test_bucket_key_weekend(self):
        store = BaselineStore(Config.load(None))
        ts = datetime(2026, 11, 7, 3, 0)  # Saturday, 3:00am
        assert store._bucket_key(ts) == "weekend-3"

    def test_observe_creates_buckets(self):
        store = BaselineStore(Config.load(None))
        ts = datetime.now()
        stats = make_stats(packet_rate=100.0, byte_rate=50000.0, syn_ratio=0.1)
        store.observe(stats, ts)
        assert len(store.all()) >= 3  # packet_rate, byte_rate, syn_ratio

    def test_expected_returns_mean(self):
        store = BaselineStore(Config.load(None))
        ts = datetime.now()
        stats = make_stats(packet_rate=100.0, byte_rate=50000.0)
        store.observe(stats, ts)
        expected = store.expected("packet_rate", ts)
        assert expected == pytest.approx(100.0, abs=1.0)

    def test_expected_returns_zero_when_empty(self):
        store = BaselineStore(Config.load(None))
        expected = store.expected("packet_rate", datetime.now())
        assert expected == 0.0

    def test_persistence_save_and_load(self):
        store = BaselineStore(Config.load(None), data_dir=tempfile.mkdtemp())
        ts = datetime.now()
        store.observe(make_stats(packet_rate=200.0, byte_rate=80000.0), ts)
        store.save()

        # Load into a new store
        store2 = BaselineStore(Config.load(None), data_dir=store.data_dir)
        store2.load()
        expected = store2.expected("packet_rate", ts)
        assert expected == pytest.approx(200.0, abs=1.0)

    def test_save_creates_file(self):
        store = BaselineStore(Config.load(None), data_dir=tempfile.mkdtemp())
        store.observe(make_stats(packet_rate=100.0, byte_rate=50000.0), datetime.now())
        store.save()
        path = os.path.join(store.data_dir, "baseline.json")
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data) >= 1

    def test_multiple_observations_update_stats(self):
        store = BaselineStore(Config.load(None))
        ts = datetime.now()
        for rate in [100, 110, 120, 90, 105]:
            store.observe(make_stats(packet_rate=float(rate), byte_rate=float(rate * 500)), ts)
        model = store.buckets.get(f"weekday-{ts.hour}:packet_rate")
        assert model is not None
        assert model.count == 5
        assert model.mean == pytest.approx(105.0, abs=1.0)

    def test_set_ready(self):
        store = BaselineStore(Config.load(None))
        assert not store.is_ready
        store.set_ready(True)
        assert store.is_ready

    def test_observed_values_in_reservoir(self):
        store = BaselineStore(Config.load(None))
        ts = datetime.now()
        for i in range(10):
            store.observe(make_stats(packet_rate=float(i * 10), byte_rate=float(i * 5000)), ts)
        model = store.buckets.get(f"weekday-{ts.hour}:packet_rate")
        assert model is not None
        assert len(model.samples) == 10
        assert model.p95 > model.p5  # percentiles should be ordered
```

Run:
```bash
python -m pytest tests/test_baseline.py -v
```

**What you'll learn**:
- **Temporary directories** (`tempfile.mkdtemp()`) for tests that need disk persistence without polluting the real filesystem
- **Approximate assertions** (`pytest.approx`) for comparing floating-point numbers
- **Test data setup**: creating fake `TrafficStats` with controlled values to test specific scenarios
- **Percentile ordering**: verifying that p95 > p5 is a basic sanity check on the statistics

**Why it matters**: Tests ensure the baseline store correctly buckets by time, persists data, and computes statistics. Without tests, you might silently get wrong baselines, leading to false alarms or missed attacks.

**Verify**: All tests pass.

**Estimated time**: 20 minutes

---

## Phase 5: Anomaly Detection

### Step 13: Understand Detection Signals

**Task**: Learn the signal-based detection approach.

```
DETECTION SIGNALS
==================
A "signal" is a function that looks at traffic statistics and returns a score
between 0 and 1 indicating how anomalous the traffic looks.

Five signals in this project:

1. VOLUME SIGNAL
   - What it detects: traffic volume significantly above baseline
   - How: compare packet_rate and byte_rate to the baseline mean + 2*stdev
   - Score: how many standard deviations above the mean
   - Why: volumetric attacks (UDP floods) cause huge traffic spikes

2. PROTOCOL SIGNAL
   - What it detects: unusual protocol distribution
   - How: compare the proportion of each protocol to the baseline
   - Score: deviation from normal protocol mix
   - Why: some attacks use unusual protocols or extreme protocol ratios

3. SOURCE SIGNAL
   - What it detects: many unique source IPs (distributed attack)
   - How: count unique source IPs, compare to baseline
   - Score: how concentrated or dispersed the sources are
   - Why: DDoS attacks come from many sources (botnets), not one

4. PORT SIGNAL
   - What it detects: traffic concentrated on unusual ports
   - How: look at destination port distribution
   - Score: how focused the port targeting is
   - Why: application-layer attacks target specific service ports

5. SYN SIGNAL
   - What it detects: high ratio of SYN packets (SYN flood)
   - How: compare SYN ratio to baseline
   - Score: how extreme the SYN ratio is
   - Why: SYN floods send many SYN packets without completing handshakes

COMPOSITE SCORING
==================
Each signal returns a 0..1 score. The composite scorer:
1. Takes all signal scores
2. Applies weights (configurable)
3. Applies confirmation damping (repeated high scores are damped to avoid oscillation)
4. Computes a weighted total
5. Maps the total to a severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)
6. Classifies the attack type (none/volumetric/protocol/application/mixed)
```

**What you'll learn**:
- The signal-based detection paradigm: multiple weak indicators → one strong conclusion
- Why we use multiple signals instead of one (robustness, different attack types)
- What "confirmation damping" means and why it's needed (prevents flipping between alarm and normal)
- How severity bands work (mapping a continuous score to discrete levels)

**Why it matters**: Real attacks manifest differently. A SYN flood looks different from a UDP flood, which looks different from an HTTP flood. Multiple signals let you detect all of them with one system.

**Verify**: Conceptual step. You should be able to explain each of the 5 signals and what attack type it catches.

**Estimated time**: 10 minutes

---

### Step 14: Implement Detection Signals

**Task**: Create `ddosguard/detect/signals.py` with the 5 detection signals.

```python
"""
Detection signals: individual anomaly indicators that feed the composite scorer.

Each signal takes TrafficStats + BaselineStore and returns a SignalResult with
a score from 0 (normal) to 1 (highly anomalous).
"""
from __future__ import annotations

from typing import Dict, List

from ddosguard.core import (
    BaselineStats,
    CompositeScore,
    PacketRecord,
    Severity,
    SignalResult,
    TrafficStats,
)
from ddosguard.baseline.store import BaselineStore


def _severity_from_score(total: float) -> Severity:
    """Map a composite score to a severity level."""
    if total >= 0.85:
        return Severity.CRITICAL
    elif total >= 0.70:
        return Severity.HIGH
    elif total >= 0.50:
        return Severity.MEDIUM
    elif total >= 0.30:
        return Severity.LOW
    return Severity.INFO


def volume_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    """
    Detect volumetric attacks: traffic significantly above baseline.

    Compares packet_rate and byte_rate to the diurnal baseline. Returns a high
    score when traffic exceeds mean + 2*stdev.
    """
    mean_pr, stdev_pr = baseline.expected_with_stdev("packet_rate", stats.window.start)
    mean_br, stdev_br = baseline.expected_with_stdev("byte_rate", stats.window.start)

    score = 0.0
    detail: Dict[str, float] = {}

    if stdev_pr > 0:
        # How many standard deviations above the mean?
        z_pr = max(0, stats.packet_rate - mean_pr) / stdev_pr
        detail["packet_rate_z"] = round(z_pr, 2)
        # Score scales from 0 to 1 as z goes from 0 to 5+
        score = min(1.0, z_pr / 5.0)

    if stdev_br > 0:
        z_br = max(0, stats.byte_rate - mean_br) / stdev_br
        detail["byte_rate_z"] = round(z_br, 2)
        score = max(score, min(1.0, z_br / 5.0))

    detail["baseline_mean_packet_rate"] = round(mean_pr, 2)
    detail["baseline_mean_byte_rate"] = round(mean_br, 2)
    detail["current_packet_rate"] = round(stats.packet_rate, 2)
    detail["current_byte_rate"] = round(stats.byte_rate, 2)

    return SignalResult(
        name="volume",
        score=score,
        detail=detail,
        affected=[f"packet_rate={stats.packet_rate:.1f} pps" if score > 0.3 else ""],
    )


def protocol_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    """
    Detect unusual protocol distributions.

    Compares the current protocol mix to the baseline. A sudden shift toward
    one protocol (e.g., mostly UDP during normal TCP-heavy traffic) is scored.
    """
    score = 0.0
    detail: Dict[str, float] = {}

    if stats.per_proto:
        total_packets = sum(stats.per_proto.values())
        if total_packets == 0:
            return SignalResult(name="protocol", score=0.0, detail={})

        # Current protocol proportions
        current_props: Dict[int, float] = {}
        for proto, count in stats.per_proto.items():
            current_props[proto] = count / total_packets

        # Compare to baseline if available
        # Since we don't have per-protocol baseline buckets in this simplified version,
        # we check for extreme protocol skew as a heuristic
        max_prop = max(current_props.values()) if current_props else 0
        detail["max_protocol_proportion"] = round(max_prop, 3)

        # If one protocol dominates (>80%), that's unusual in mixed traffic
        if max_prop > 0.80:
            score = min(1.0, (max_prop - 0.80) / 0.20)

        detail["protocol_distribution"] = {
            k: round(v, 3) for k, v in current_props.items()
        }

    return SignalResult(
        name="protocol",
        score=score,
        detail=detail,
    )


def source_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    """
    Detect distributed attacks: many unique source IPs.

    A sudden increase in unique sources suggests a botnet-based DDoS.
    """
    score = 0.0
    detail: Dict[str, object] = {}

    # We use the top_sources from the TrafficWindow
    top_srcs = stats.window.top_srcs if hasattr(stats.window, 'top_srcs') else []
    unique_sources = len(top_srcs) if top_srcs else 0
    detail["unique_sources"] = unique_sources

    # Check for many unique sources with concentrated traffic
    # This is a simplified heuristic: if top source has < 50% of traffic
    # and there are many sources, it's distributed
    if unique_sources > 10:
        # Many sources is suspicious in a short window
        score = min(1.0, (unique_sources - 10) / 90.0)  # saturates at 100 sources

    detail["source_count"] = unique_sources
    return SignalResult(
        name="source",
        score=score,
        detail=detail,
        affected=[f"{unique_sources} unique sources" if score > 0.3 else ""],
    )


def port_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    """
    Detect port-targeted attacks: traffic concentrated on specific ports.

    Application-layer DDoS often targets a single service port. A high
    concentration on one port is scored.
    """
    score = 0.0
    detail: Dict[str, object] = {}

    dst_ports = stats.window.dst_ports if hasattr(stats.window, 'dst_ports') else {}
    if dst_ports:
        total = sum(dst_ports.values())
        if total > 0:
            max_port_count = max(dst_ports.values())
            max_port_prop = max_port_count / total
            max_port = max(dst_ports, key=dst_ports.get)

            detail["max_port"] = max_port
            detail["max_port_proportion"] = round(max_port_prop, 3)
            detail["total_ports_hit"] = len(dst_ports)

            # If traffic is heavily concentrated on one port (>70%), score it
            if max_port_prop > 0.70:
                score = min(1.0, (max_port_prop - 0.70) / 0.30)

    return SignalResult(
        name="port",
        score=score,
        detail=detail,
        affected=[f"port {detail.get('max_port', '?')} targeted" if score > 0.3 else ""],
    )


def syn_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    """
    Detect SYN floods: high ratio of SYN packets.

    A SYN flood sends many TCP SYN packets without completing the handshake.
    Normal traffic has a low SYN ratio; a SYN flood has a very high one.
    """
    score = 0.0
    detail: Dict[str, float] = {
        "syn_ratio": round(stats.syn_ratio, 3),
    }

    # Normal SYN ratio is typically < 0.3 (some SYN during normal connection setup)
    # A SYN flood can have ratio > 0.8
    if stats.syn_ratio > 0.3:
        score = min(1.0, (stats.syn_ratio - 0.3) / 0.6)  # saturates at ratio > 0.9

    detail["baseline_syn_ratio"] = 0.1  # approximate normal
    return SignalResult(
        name="syn",
        score=score,
        detail=detail,
        affected=[f"SYN ratio={stats.syn_ratio:.2f}" if score > 0.3 else ""],
    )


def run_all_signals(stats: TrafficStats, baseline: BaselineStore) -> List[SignalResult]:
    """Run all 5 detection signals and return their results."""
    return [
        volume_signal(stats, baseline),
        protocol_signal(stats, baseline),
        source_signal(stats, baseline),
        port_signal(stats, baseline),
        syn_signal(stats, baseline),
    ]
```

Add exports:
```python
__all__ = [
    "volume_signal", "protocol_signal", "source_signal", "port_signal", "syn_signal",
    "run_all_signals", "_severity_from_score",
]
```

**What you'll learn**:
- **Z-score**: a statistical measure of how far a value is from the mean, in units of standard deviation. `z = 3` means "3 standard deviations above normal" — very unusual.
- **Signal design**: each signal is a self-contained function that knows how to detect one specific anomaly pattern. This modularity makes it easy to add new signals later.
- **Heuristics vs statistical models**: some signals use statistical comparison (volume uses z-score), others use heuristics (protocol uses proportion thresholds). Both are valid; the best choice depends on the data.
- **Score calibration**: signals return 0..1, but the raw computation might give values outside that range. `min(1.0, ...)` and `max(0, ...)` clamp the scores.

**Why it matters**: These 5 signals are the "senses" of your detection system. Each one detects a different attack pattern. Together they give broad coverage.

**Verify**:
```bash
python -c "
from ddosguard.detect.signals import run_all_signals, volume_signal, syn_signal
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import TrafficStats, TrafficWindow, PacketRecord, Protocol
from datetime import datetime, timedelta

config = Config.load(None)
baseline = BaselineStore(config, data_dir='data')
baseline.set_ready(True)

# Create stats with very high packet rate (simulating volumetric attack)
now = datetime.now()
window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
for i in range(5000):  # 5000 packets in 10 seconds = 500 pps
    pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{i%254}', dst_ip='10.0.0.1',
                       protocol=Protocol.UDP, src_port=12345, dst_port=80,
                       length=512, flags='')
    window.add(pkt)
stats = window.finalize()

# Observe some normal baseline first
for i in range(10):
    baseline.observe(make_stats(50.0, 25000.0), now)

signals = run_all_signals(stats, baseline)
for s in signals:
    if s.score > 0.1:
        print(f'{s.name}: score={s.score:.3f} detail={s.detail}')
"

# Helper for the test above
def make_stats(pr, br):
    from ddosguard.core import TrafficStats
    now = datetime.now()
    w = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    w.packet_count = int(pr * 10)
    w.byte_count = int(br * 10)
    return TrafficStats(window=w, per_proto={6: int(pr*10*0.7), 17: int(pr*10*0.3)}, syn_ratio=0.1, byte_rate=br)
"

```

Expected: volume signal shows high score for the 500 pps traffic compared to 50 pps baseline.

**Estimated time**: 30 minutes

---

### Step 15: Implement the Composite Scorer

**Task**: Create `ddosguard/detect/scorer.py` — the class that combines signals into one score, applies damping, and classifies the attack.

```python
"""
Composite scoring: combine multiple detection signals into one anomaly score.

Handles:
  - Weighted combination of signals
  - Confirmation damping (prevents oscillation)
  - Severity classification
  - Attack type classification (volumetric, protocol, application, mixed)
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ddosguard.core import (
    CompositeScore,
    SignalResult,
    Severity,
    TrafficStats,
)
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.signals import run_all_signals, _severity_from_score


class CompositeScorer:
    """
    Runs all detection signals and produces a composite anomaly score.

    Configurable weights per signal, confirmation damping to prevent
    oscillation between alarm and normal states, and classification
    of the attack type.
    """

    def __init__(self, config=None):
        # Default weights — can be overridden by config
        self.weights = {
            "volume": 0.30,
            "protocol": 0.20,
            "source": 0.20,
            "port": 0.15,
            "syn": 0.15,
        }
        self.confirmation_damping = 0.8
        self._previous_score: Optional[float] = None
        if config:
            self._load_weights_from_config(config)

    def _load_weights_from_config(self, config) -> None:
        """Load signal weights from config if available."""
        try:
            detection = config.detection
            if "weights" in detection and isinstance(detection["weights"], dict):
                for name, weight in detection["weights"].items():
                    if name in self.weights:
                        self.weights[name] = float(weight)
            if "confirmation_damping" in detection:
                self.confirmation_damping = float(detection["confirmation_damping"])
        except (AttributeError, KeyError, TypeError):
            pass  # Use defaults if config is missing or malformed

    def score(self, stats: TrafficStats, baseline: BaselineStore) -> CompositeScore:
        """
        Run all signals and produce a composite score.

        Steps:
        1. Run all 5 detection signals
        2. Weight and combine them
        3. Apply confirmation damping
        4. Classify severity and attack type
        """
        signals = run_all_signals(stats, baseline)

        # Build weighted score
        total = 0.0
        signal_scores: Dict[str, float] = {}
        signal_names: List[str] = []

        for sig in signals:
            weight = self.weights.get(sig.name, 0.0)
            weighted = sig.score * weight
            total += weighted
            signal_scores[sig.name] = sig.score
            signal_names.append(sig.name)

        # Apply confirmation damping
        total = self._apply_damping(total)

        # Classify
        severity = _severity_from_score(total)
        classification = self._classify(signals, total)

        return CompositeScore(
            signal_names=signal_names,
            signal_scores=signal_scores,
            total=total,
            severity=severity,
            classification=classification,
            window=stats,
        )

    def _apply_damping(self, new_score: float) -> float:
        """
        Apply confirmation damping to prevent oscillation.

        If the new score jumps up suddenly, damp it toward the previous score.
        If it's consistently high, let it rise. This prevents false alarms from
        brief spikes.
        """
        if self._previous_score is None:
            self._previous_score = new_score
            return new_score

        # Damp rapid increases more than gradual ones
        if new_score > self._previous_score:
            # New score is higher — damp the increase
            damped = self._previous_score + (new_score - self._previous_score) * self.confirmation_damping
        else:
            # New score is lower — let it drop faster (attack is ending)
            damped = self._previous_score + (new_score - self._previous_score) * (2 - self.confirmation_damping)

        self._previous_score = damped
        return max(0.0, min(1.0, damped))

    def _classify(self, signals: List[SignalResult], total: float) -> str:
        """Classify the attack type based on which signals fired."""
        if total < 0.30:
            return "none"

        fired = {s.name for s in signals if s.score > 0.3}

        if "volume" in fired and "syn" in fired:
            return "mixed"
        elif "volume" in fired and "protocol" in fired:
            return "mixed"
        elif "volume" in fired:
            # Check if it's SYN-heavy or UDP-heavy
            if signals[4].score > 0.5:  # syn signal (index 4)
                return "protocol"
            return "volumetric"
        elif "syn" in fired:
            return "protocol"
        elif "port" in fired or "protocol" in fired:
            return "application"
        elif "source" in fired:
            return "volumetric"  # distributed source = volumetric attack

        return "unknown"
```

Add exports:
```python
__all__ = ["CompositeScorer"]
```

**What you'll learn**:
- **Weighted sums**: combining multiple indicators where some matter more than others. Volume gets 30% weight, SYN gets 15%, etc.
- **Confirmation damping**: a simple but effective technique to prevent false alarms. Instead of reacting to every spike, the score moves gradually. Think of it like a "momentum" term.
- **Attack classification**: mapping signal combinations to attack types. Volume + SYN = mixed, volume alone = volumetric, SYN alone = protocol, port targeting = application.
- **Config-driven parameters**: weights and damping come from the config file, so you can tune the system without changing code.

**Why it matters**: Individual signals can be noisy. The composite scorer turns 5 noisy signals into one reliable score. The damping prevents the system from flapping between "attack!" and "all clear" on borderline traffic.

**Verify**:
```bash
python -c "
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import TrafficStats, TrafficWindow, PacketRecord, Protocol
from datetime import datetime, timedelta

config = Config.load(None)
baseline = BaselineStore(config, data_dir='data')
baseline.set_ready(True)
scorer = CompositeScorer(config)

# Train baseline with normal traffic
now = datetime.now()
for i in range(20):
    window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    for j in range(50):
        pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{j%254}', dst_ip='10.0.0.1',
                           protocol=Protocol.TCP, src_port=12345, dst_port=80,
                           length=100, flags='PA')
        window.add(pkt)
    baseline.observe(window.finalize(), now)

# Score normal traffic
normal_window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
for j in range(50):
    pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{j%254}', dst_ip='10.0.0.1',
                       protocol=Protocol.TCP, src_port=12345, dst_port=80,
                       length=100, flags='PA')
    normal_window.add(pkt)
normal_stats = normal_window.finalize()
normal_score = scorer.score(normal_stats, baseline)
print(f'Normal traffic: score={normal_score.total:.3f}, severity={normal_score.severity.name}, class={normal_score.classification}')

# Score attack traffic (SYN flood: 2000 SYN packets)
attack_window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
for j in range(2000):
    pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{j%254}', dst_ip='10.0.0.1',
                       protocol=Protocol.TCP, src_port=12345, dst_port=80,
                       length=64, flags='S')  # SYN only
    attack_window.add(pkt)
attack_stats = attack_window.finalize()
attack_score = scorer.score(attack_stats, baseline)
print(f'Attack traffic: score={attack_score.total:.3f}, severity={attack_score.severity.name}, class={attack_score.classification}')
print(f'Signals: {attack_score.signal_scores}')
"

```

Expected: normal traffic scores low (< 0.3), attack traffic scores higher (> 0.5), with SYN signal firing.

**Estimated time**: 25 minutes

---

## Phase 6: Rate Limiting & Mitigation

### Step 16: Understand Token Buckets

**Task**: Learn the token bucket rate limiting algorithm.

```
TOKEN BUCKET ALGORITHM
=======================
A token bucket is a simple rate-limiting algorithm:

- A "bucket" holds tokens (representing permission to send data)
- Tokens are added to the bucket at a fixed rate (e.g., 100 tokens/second)
- Each request consumes tokens (e.g., 1 token per packet)
- If the bucket is empty, the request is denied

Key parameters:
  rate:  how many tokens are added per second (sustained rate)
  burst: how many tokens the bucket can hold (maximum burst size)

Behavior:
  - With burst=0: the bucket starts empty. The first request is denied until
    enough time has passed for tokens to accumulate. This is "strict" rate limiting.
  - With burst>0: the bucket starts with burst tokens. The first burst_rate
    requests are allowed immediately, then the rate limits kick in.

Refill calculation (analytical, not tick-based):
  tokens = min(bucket_capacity, tokens + elapsed_time * rate)

This is accurate regardless of how often you check — no drift from timer gaps.

WHY TOKEN BUCKETS FOR DDoS?
============================
- They're simple and efficient
- They allow controlled bursts (real networks have bursts)
- They can be applied per-source IP (each attacker gets their own bucket)
- They degrade gracefully (legitimate traffic gets through at the sustained rate)
```

**What you'll learn**:
- The token bucket algorithm and its parameters
- The difference between sustained rate and burst capacity
- Analytical refill vs tick-based refill
- Why per-source buckets are effective for DDoS (each attacker is limited independently)

**Why it matters**: Rate limiting is the primary mitigation for volumetric attacks. Token buckets are the industry-standard approach — they're used in everything from API rate limiters to network QoS.

**Verify**: Conceptual step.

**Estimated time**: 10 minutes

---

### Step 17: Implement Token Bucket & Rate Limiter

**Task**: Create `ddosguard/mitigate/ratelimit.py` with `TokenBucket` and `RateLimiter`.

```python
"""
Token bucket rate limiting.

TokenBucket: a single bucket that refills at a fixed rate.
RateLimiter: manages per-key buckets with whitelist support.
"""
from __future__ import annotations

from typing import Dict, Optional
from datetime import datetime


class TokenBucket:
    """
    A token bucket for rate limiting.

    Tokens are added at `rate` per second, up to a maximum of `burst` tokens.
    Each call to consume() uses `tokens` tokens (default 1).

    Usage:
        bucket = TokenBucket(rate=100, burst=200)
        if bucket.consume(1):
            # Allowed — process the packet
            pass
        else:
            # Denied — rate limited
            pass
    """

    def __init__(self, rate: float = 100.0, burst: float = 200.0):
        """
        Args:
            rate: Tokens added per second (sustained rate).
            burst: Maximum bucket capacity. If 0, bucket starts empty.
        """
        self.rate = rate
        self.burst = burst
        self._tokens = burst if burst > 0 else 0.0  # burst=0 means start empty (strict)
        self._last_refill = datetime.now()
        self._refill()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill."""
        now = datetime.now()
        elapsed = (now - self._last_refill).total_seconds()
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_refill = now

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume `tokens` from the bucket.

        Returns True if allowed, False if rate limited.
        """
        if tokens <= 0:
            return True
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def available_tokens(self) -> float:
        """Current number of tokens available (after refill)."""
        self._refill()
        return self._tokens

    def stats(self) -> Dict[str, float]:
        """Return current bucket statistics."""
        self._refill()
        return {
            "tokens": self._tokens,
            "rate": self.rate,
            "burst": self.burst,
            "utilization": self._tokens / self.burst if self.burst > 0 else 0.0,
        }


class RateLimiter:
    """
    Manages per-key token buckets with whitelist support.

    Each unique key (e.g., source IP) gets its own token bucket, allowing
    per-source rate limiting. Whitelisted keys bypass rate limiting entirely.

    Usage:
        limiter = RateLimiter(default_rate=100, default_burst=200)
        limiter.add_whitelist("192.168.1.1")
        if limiter.admit(key="10.0.0.1", tokens=1):
            # Allowed
            pass
    """

    def __init__(self, default_rate: float = 100.0, default_burst: float = 200.0):
        self.default_rate = default_rate
        self.default_burst = default_burst
        self._buckets: Dict[str, TokenBucket] = {}
        self._whitelist: set[str] = set()
        self._total_admitted = 0
        self._total_denied = 0

    def add_whitelist(self, key: str) -> None:
        """Add a key to the whitelist (bypasses rate limiting)."""
        self._whitelist.add(key)

    def remove_whitelist(self, key: str) -> bool:
        """Remove a key from the whitelist. Returns True if it was whitelisted."""
        if key in self._whitelist:
            self._whitelist.remove(key)
            return True
        return False

    def is_whitelisted(self, key: str) -> bool:
        """Check if a key is whitelisted."""
        return key in self._whitelist

    def admit(self, key: str, tokens: float = 1.0) -> bool:
        """
        Check if a request from `key` is allowed.

        Whitelisted keys are always admitted. Non-whitelisted keys go through
        the token bucket.
        """
        if key in self._whitelist:
            self._total_admitted += 1
            return True

        if key not in self._buckets:
            self._buckets[key] = TokenBucket(self.default_rate, self.default_burst)

        allowed = self._buckets[key].consume(tokens)
        if allowed:
            self._total_admitted += 1
        else:
            self._total_denied += 1
        return allowed

    def stats(self, key: Optional[str] = None) -> Dict[str, object]:
        """
        Get statistics for a specific key, or overall stats if key is None.
        """
        if key is not None:
            if key in self._whitelist:
                return {"key": key, "whitelisted": True, "admitted": "unlimited"}
            if key in self._buckets:
                bucket_stats = self._buckets[key].stats()
                bucket_stats["key"] = key
                bucket_stats["whitelisted"] = False
                return bucket_stats
            return {"key": key, "whitelisted": False, "buckets": "not yet seen"}

        return {
            "total_admitted": self._total_admitted,
            "total_denied": self._total_denied,
            "active_buckets": len(self._buckets),
            "whitelisted_keys": len(self._whitelist),
        }

    def clear(self) -> None:
        """Clear all buckets and whitelist."""
        self._buckets.clear()
        self._whitelist.clear()
        self._total_admitted = 0
        self._total_denied = 0
```

Add exports:
```python
__all__ = ["TokenBucket", "RateLimiter"]
```

**What you'll learn**:
- **Analytical refill**: computing token accumulation from elapsed time, not from a timer tick. This is accurate even if `consume()` is called at irregular intervals.
- **Per-key isolation**: each source IP gets its own bucket. An attacker can't consume the tokens allocated to legitimate users.
- **Whitelist**: a simple way to exempt trusted sources. Critical for not blocking your own admin traffic during an attack.
- **Admission statistics**: tracking admitted/denied counts per key and overall. Useful for dashboards and alerting.

**Why it matters**: Rate limiting is your primary defense against volumetric attacks. Without it, the only options are dropping all traffic (which blocks legitimate users too) or letting the attack through (which overwhelms the server).

**Verify**:
```bash
python -c "
from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter

# Test TokenBucket
print('=== TokenBucket Tests ===')
bucket = TokenBucket(rate=10, burst=5)  # 10 tokens/sec, max 5
print(f'Initial tokens: {bucket.available_tokens:.1f}')
assert bucket.consume(1)
assert bucket.consume(1)
assert bucket.consume(1)
assert bucket.consume(1)
assert bucket.consume(1)
print(f'After 5 consumes: {bucket.available_tokens:.1f} (should be ~0)')
assert not bucket.consume(1)  # Should be denied — bucket empty
print('6th consume denied (correct)')

# Test RateLimiter
print('\\n=== RateLimiter Tests ===')
limiter = RateLimiter(default_rate=100, default_burst=200)
limiter.add_whitelist('192.168.1.1')

# Whitelisted IP always admitted
assert limiter.admit('192.168.1.1', 1)
print('Whitelisted IP admitted (correct)')

# Non-whitelisted IP goes through bucket
admitted = sum(limiter.admit('10.0.0.1', 1) for _ in range(250))
print(f'250 requests from 10.0.0.1: {admitted} admitted (should be ~200 with burst)')
print(f'Stats: {limiter.stats(\"10.0.0.1\")}')
print(f'Overall: {limiter.stats()}')
"

```

Expected: TokenBucket allows 5 consumes (burst), then denies. RateLimiter whitelists one IP, limits another to ~200 requests.

**Estimated time**: 30 minutes

---

### Step 18: Write Rate Limiter Tests

**Task**: Create `tests/test_ratelimit.py` with tests for the token bucket and rate limiter.

```python
"""Tests for rate limiting — no network, no permissions required."""
import pytest
import time
from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter


class TestTokenBucket:
    """Tests for the token bucket algorithm."""

    def test_initial_burst_available(self):
        """With burst > 0, initial tokens should be available."""
        bucket = TokenBucket(rate=10, burst=5)
        assert bucket.available_tokens == pytest.approx(5.0, abs=0.01)

    def test_burst_zero_starts_empty(self):
        """With burst=0, the bucket should start empty (strict mode)."""
        bucket = TokenBucket(rate=10, burst=0)
        assert bucket.available_tokens == pytest.approx(0.0, abs=0.01)
        assert not bucket.consume(1)  # Denied — no tokens

    def test_consume_allowed_when_tokens_available(self):
        bucket = TokenBucket(rate=100, burst=50)
        assert bucket.consume(1)
        assert bucket.consume(10)
        assert bucket.consume(30)
        assert bucket.available_tokens == pytest.approx(10.0, abs=0.01)

    def test_consume_denied_when_empty(self):
        bucket = TokenBucket(rate=100, burst=5)
        for _ in range(5):
            assert bucket.consume(1)
        assert not bucket.consume(1)  # Empty — denied

    def test_refill_over_time(self):
        bucket = TokenBucket(rate=100, burst=50)
        # Exhaust the bucket
        for _ in range(50):
            bucket.consume(1)
        assert bucket.available_tokens == pytest.approx(0.0, abs=0.01)

        # Wait for refill (at least 0.5 seconds for 50 tokens at 100/sec)
        time.sleep(0.5)
        assert bucket.available_tokens >= 40  # Should have refilled ~50 tokens

    def test_consume_multiple_tokens(self):
        bucket = TokenBucket(rate=100, burst=50)
        assert bucket.consume(5)   # Consume 5 at once
        assert bucket.available_tokens == pytest.approx(45.0, abs=0.01)

    def test_negative_consume_allowed(self):
        """Negative token consumption should always be allowed (no-op)."""
        bucket = TokenBucket(rate=10, burst=5)
        assert bucket.consume(0)
        assert bucket.consume(-1)

    def test_stats(self):
        bucket = TokenBucket(rate=100, burst=50)
        stats = bucket.stats()
        assert stats["rate"] == 100
        assert stats["burst"] == 50
        assert "tokens" in stats
        assert "utilization" in stats


class TestRateLimiter:
    """Tests for the per-key rate limiter."""

    def test_whitelist_bypasseslimiting(self):
        limiter = RateLimiter(default_rate=1, default_burst=1)
        limiter.add_whitelist("10.0.0.1")
        # Whitelisted IP should always be admitted even with tiny bucket
        for _ in range(100):
            assert limiter.admit("10.0.0.1", 1)

    def test_non_whitelisted_is_limited(self):
        limiter = RateLimiter(default_rate=10, default_burst=5)
        admitted = sum(limiter.admit("10.0.0.2", 1) for _ in range(20))
        assert admitted <= 20
        assert admitted >= 5  # At least burst should go through

    def test_multiple_keys_independent_buckets(self):
        limiter = RateLimiter(default_rate=10, default_burst=5)
        # Fill up bucket for IP1
        for _ in range(5):
            limiter.admit("10.0.0.1", 1)
        # IP2 should still have full bucket
        assert limiter.admit("10.0.0.2", 1)

    def test_whitelist_remove(self):
        limiter = RateLimiter(default_rate=100, default_burst=200)
        limiter.add_whitelist("10.0.0.1")
        assert limiter.is_whitelisted("10.0.0.1")
        assert limiter.remove_whitelist("10.0.0.1")
        assert not limiter.is_whitelisted("10.0.0.1")
        assert not limiter.remove_whitelist("10.0.0.1")  # Already removed

    def test_stats_per_key(self):
        limiter = RateLimiter(default_rate=10, default_burst=5)
        for _ in range(3):
            limiter.admit("10.0.0.1", 1)
        stats = limiter.stats("10.0.0.1")
        assert stats["key"] == "10.0.0.1"
        assert stats["whitelisted"] is False

    def test_stats_overall(self):
        limiter = RateLimiter(default_rate=10, default_burst=5)
        limiter.add_whitelist("10.0.0.1")
        for _ in range(10):
            limiter.admit("10.0.0.2", 1)
        stats = limiter.stats()
        assert stats["total_admitted"] == 10
        assert stats["whitelisted_keys"] == 1
        assert stats["active_buckets"] == 1

    def test_clear_resets(self):
        limiter = RateLimiter(default_rate=10, default_burst=5)
        limiter.add_whitelist("10.0.0.1")
        limiter.admit("10.0.0.2", 1)
        limiter.clear()
        assert len(limiter._buckets) == 0
        assert len(limiter._whitelist) == 0
        assert limiter._total_admitted == 0
        assert limiter._total_denied == 0
```

Run:
```bash
python -m pytest tests/test_ratelimit.py -v
```

**What you'll learn**:
- Testing time-dependent code: the `time.sleep(0.5)` test waits for real refill. This is acceptable in unit tests when the time scale is small.
- Testing strict vs permissive modes: `burst=0` vs `burst>0` gives different behavior, both of which should be tested.
- Testing per-key isolation: ensuring one key's bucket doesn't affect another's.

**Why it matters**: Rate limiting is security-critical code. Bugs here could either let attacks through (too permissive) or block legitimate users (too strict). Tests give confidence.

**Verify**: All tests pass. The time-based test may take ~0.5 seconds to run.

**Estimated time**: 20 minutes

---

## Phase 7: Firewall Rules

### Step 19: Implement Firewall Rule Generation

**Task**: Create `ddosguard/mitigate/firewall.py` — generates iptables-style rules for each mitigation stage.

```python
"""
Firewall rule generation for DDoS mitigation.

Generates iptables-style rule sets for each mitigation stage (0-4).
Rules are iptables commands with comment metadata for tracking.

IMPORTANT: By default, rules are generated in dry-run mode (not executed).
Setting dry_run=False will execute the iptables commands, which requires
root/admin privileges and can block real traffic. Use with caution.
"""
from __future__ import annotations

import subprocess
from typing import Dict, List, Optional


class FirewallManager:
    """
    Generates and manages iptables firewall rules for DDoS mitigation.

    Stages:
      0: No mitigation (monitor only)
      1: Lenient per-IP rate limit (100 packets/sec per IP)
      2: Strict per-IP limit + recent module tracking (50 pps + block repeat offenders)
      3: Service-port rate limits (limit traffic to specific ports)
      4: Full DROP + scrubbing hint (aggressive mitigation)

    Whitelisted IPs always get permit rules before any DROP rules.
    """

    def __init__(self, dry_run: bool = True, chain: str = "INPUT"):
        self.dry_run = dry_run
        self.chain = chain
        self._active_rules: List[str] = []

    def generate_rules(self, stage: int, severity: str = "",
                       config: Optional[Dict] = None,
                       whitelist: Optional[List[str]] = None) -> List[str]:
        """
        Generate iptables rules for a given mitigation stage.

        Args:
            stage: Mitigation stage (0-4).
            severity: Severity label for comment metadata.
            config: Optional config dict with rate limits.
            whitelist: Optional list of IP addresses to whitelist.

        Returns:
            List of iptables command strings (NOT executed unless dry_run=False).
        """
        whitelist = whitelist or []
        rules: List[str] = []

        # Stage 0: no mitigation
        if stage == 0:
            return rules

        # Comment header for this rule set
        rules.append(f"# ddosguard: stage={stage} severity={severity} generated={__import__('datetime').datetime.now().isoformat()}")

        # Whitelist permit rules (always first — they bypass drops)
        for ip in whitelist:
            rules.append(f"-A {self.chain} -s {ip} -j ACCEPT  # ddosguard: whitelist {ip}")

        # Stage 1: lenient per-IP rate limit
        if stage >= 1:
            rate = self._get_rate(config, stage, "rate", 100)
            burst = self._get_rate(config, stage, "burst", 200)
            rules.append(f"-A {self.chain} -p tcp -m limit --limit {rate}/second --limit-burst {burst} -j ACCEPT  # ddosguard: stage={stage} lenient")
            rules.append(f"-A {self.chain} -p udp -m limit --limit {rate}/second --limit-burst {burst} -j ACCEPT  # ddosguard: stage={stage} lenient")

        # Stage 2: strict per-IP + recent module
        if stage >= 2:
            strict_rate = self._get_rate(config, stage, "rate", 50)
            strict_burst = self._get_rate(config, stage, "burst", 100)
            rules.append(f"-A {self.chain} -p tcp -m recent --set --name DDOSGUARD --rsource  # ddosguard: stage={stage} recent set")
            rules.append(f"-A {self.chain} -p tcp -m recent --update --seconds 10 --hitcount {strict_rate} --name DDOSGUARD --rsource -j DROP  # ddosguard: stage={stage} recent drop")
            rules.append(f"-A {self.chain} -p udp -m recent --set --name DDOSGUARD_UDP --rsource  # ddosguard: stage={stage} recent set udp")
            rules.append(f"-A {self.chain} -p udp -m recent --update --seconds 10 --hitcount {strict_rate} --name DDOSGUARD_UDP --rsource -j DROP  # ddosguard: stage={stage} recent drop udp")

        # Stage 3: service-port rate limits
        if stage >= 3:
            port_rate = self._get_rate(config, stage, "rate", 20)
            rules.append(f"-A {self.chain} -p tcp --dport 80 -m limit --limit {port_rate}/second -j ACCEPT  # ddosguard: stage={stage} port 80")
            rules.append(f"-A {self.chain} -p tcp --dport 443 -m limit --limit {port_rate}/second -j ACCEPT  # ddosguard: stage={stage} port 443")
            rules.append(f"-A {self.chain} -p tcp --dport 8080 -m limit --limit {port_rate}/second -j ACCEPT  # ddosguard: stage={stage} port 8080")

        # Stage 4: full DROP (aggressive)
        if stage >= 4:
            rules.append(f"-A {self.chain} -p udp -j DROP  # ddosguard: stage={stage} full drop udp")
            rules.append(f"-A {self.chain} -p tcp --syn -j DROP  # ddosguard: stage={stage} full drop syn")
            rules.append(f"# ddosguard: consider enabling scrubbing center for stage 4  # ddosguard: stage={stage}")

        return rules

    def _get_rate(self, config: Optional[Dict], stage: int, key: str, default: float) -> float:
        """Get a rate parameter from config or return default."""
        if config and "rate_limits" in config:
            for rl in config["rate_limits"]:
                if rl.get("stage") == stage:
                    return float(rl.get(key, default))
        return float(default)

    def apply(self, rules: List[str]) -> bool:
        """
        Execute iptables commands to apply the given rules.

        WARNING: This modifies the system firewall. Requires root/admin privileges.
        Only call this if dry_run=False and you understand the consequences.

        Returns True if all commands succeeded, False otherwise.
        """
        if self.dry_run:
            print(f"[DRY RUN] Would apply {len(rules)} rules:")
            for rule in rules:
                print(f"  {rule}")
            self._active_rules = rules
            return True

        # Actually execute iptables commands
        success = True
        for rule in rules:
            if rule.startswith("#"):
                continue  # Skip comments
            cmd = f"iptables {rule}"
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                self._active_rules.append(rule)
            except subprocess.CalledProcessError as e:
                print(f"Failed to apply rule: {rule}")
                print(f"Error: {e.stderr}")
                success = False
        return success

    def clear(self) -> bool:
        """
        Remove all ddosguard rules from iptables.

        Returns True if successful, False otherwise.
        """
        if self.dry_run:
            print(f"[DRY RUN] Would clear {len(self._active_rules)} ddosguard rules")
            self._active_rules.clear()
            return True

        success = True
        for rule in self._active_rules:
            # Remove by comment match — this is a simplified approach
            cmd = f"iptables -D {self.chain} -m comment --comment 'ddosguard' -j DROP 2>/dev/null || true"
            try:
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            except Exception:
                pass
        self._active_rules.clear()
        return success

    @property
    def active_rules(self) -> List[str]:
        """Currently active rules (in dry_run mode, the last generated set)."""
        return list(self._active_rules)
```

Add exports:
```python
__all__ = ["FirewallManager"]
```

**What you'll learn**:
- **iptables basics**: the Linux firewall utility. Rules are specified as `-A CHAIN conditions -j ACTION`. You're learning the concepts even if on Windows (where iptables doesn't exist natively).
- **Rule ordering matters**: whitelist ACCEPT rules must come BEFORE DROP rules, otherwise the DROP catches whitelisted traffic first.
- **Dry-run pattern**: generate rules but don't execute them until you're sure. This is critical for safety — a bad rule can lock you out of your own server.
- **Comment metadata**: embedding `# ddosguard:` comments in rules makes them trackable and removable later.
- **Stage-based escalation**: different levels of mitigation for different severity levels. You don't DROP everything for a minor spike.

**Why it matters**: Firewall rules are the actual mitigation action. Rate limiting tells you who to block; firewall rules actually block them. Without firewall integration, rate limiting is just analysis.

**Verify**:
```bash
python -c "
from ddosguard.mitigate.firewall import FirewallManager

fw = FirewallManager(dry_run=True)

print('=== Stage 0 (no mitigation) ===')
rules = fw.generate_rules(stage=0, severity='INFO')
print(f'Rules: {len(rules)}')
for r in rules: print(f'  {r}')

print('\\n=== Stage 1 (lenient rate limit) ===')
rules = fw.generate_rules(stage=1, severity='LOW', whitelist=['192.168.1.1'])
for r in rules: print(f'  {r}')

print('\\n=== Stage 4 (full DROP) ===')
rules = fw.generate_rules(stage=4, severity='CRITICAL', whitelist=['192.168.1.1'])
for r in rules: print(f'  {r}')

print('\\n=== Apply (dry run) ===')
fw.apply(rules)
"

```

Expected: prints rule sets for each stage, showing comment headers, whitelist rules, and stage-specific mitigation rules.

**Estimated time**: 25 minutes

---

## Phase 8: Alerting & Escalation

### Step 20: Understand Alerting

**Task**: Learn how alerting and escalation work.

```
ALERTING SYSTEM
================
When the detection system identifies an anomaly, it generates an Alert.
The AlertManager handles:

1. SIGNATURE DEDUPLICATION
   - Each alert has a "signature" based on its characteristics
   - If the same signature was seen recently (within cooldown), suppress it
   - Prevents alert storms: one attack = one alert, not one per packet

2. COOLDOWN
   - Configurable time between repeated alerts for the same signature
   - Default: 60 seconds
   - During cooldown, the alert is logged but not delivered

3. RATE LIMITING (max_per_minute)
   - Maximum number of alerts delivered per minute
   - Prevents overwhelming administrators during large attacks
   - Default: 10 alerts/minute

4. MULTI-CHANNEL NOTIFIERS
   - Console: print alerts to stdout (always enabled by default)
   - File: append alerts to a JSONL file for later analysis
   - Desktop: send native desktop notifications (if supported)
   - Slack: send to a Slack webhook
   - Email: send via SMTP

ESCALATION LADDER
==================
Severity-based escalation:
  - INFO/LOW: log only, no action
  - MEDIUM: notify administrators, begin light mitigation
  - HIGH: actively mitigate, notify urgently
  - CRITICAL: maximum mitigation, all channels notified, urgent escalation

The MitigationPolicy maps severity to mitigation stages (0-4), creating
a complete escalation pipeline from detection to action.
```

**What you'll learn**:
- **Alert deduplication**: why you don't want one email per packet during an attack
- **Cooldown**: a simple but effective way to prevent notification spam
- **Multi-channel delivery**: different ways to reach administrators (console for dev, email/Slack for production, desktop for interactive use)
- **Escalation**: mapping severity to action. Higher severity = stronger mitigation + more urgent notification.

**Why it matters**: Detection without alerting is useless — nobody knows there's a problem. Alerting without deduplication is harmful — you get alert fatigue and ignore real attacks.

**Verify**: Conceptual step.

**Estimated time**: 10 minutes

---

### Step 21: Implement Alert Manager

**Task**: Create `ddosguard/alert/manager.py` with the `AlertManager` class.

```python
"""
Alert management: generation, deduplication, cooldown, and delivery.

Handles signature-based deduplication to prevent alert storms, cooldown periods
between repeated alerts, rate limiting on alerts per minute, and delivery to
multiple channels (console, file, desktop, Slack, email).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional

from ddosguard.core import Alert, CompositeScore, Severity, TrafficStats
from ddosguard.config import Config


class AlertManager:
    """
    Manages alert generation, deduplication, cooldown, and delivery.

    Features:
      - Signature-based deduplication (same attack = same signature)
      - Configurable cooldown between repeated alerts
      - Max alerts per minute to prevent notification floods
      - Multi-channel delivery: console, file, desktop, Slack, email
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.load(None)
        self._last_alert_time: Dict[str, datetime] = {}  # signature -> last sent time
        self._cooldown_seconds = self._get_config("alerting.cooldown", 60)
        self._max_per_minute = self._get_config("alerting.max_per_minute", 10)
        self._minute_count = 0
        self._minute_start = datetime.now()
        self._notifiers: Dict[str, bool] = {
            "console": self._get_config("alerting.notifiers.console", True),
            "file": self._get_config("alerting.notifiers.file", False),
            "desktop": self._get_config("alerting.notifiers.desktop", False),
            "slack": self._get_config("alerting.notifiers.slack", False),
            "email": self._get_config("alerting.notifiers.email", False),
        }
        self._file_path = self._get_config("alerting.notifiers.file_path", "data/alerts.jsonl")
        self._slack_webhook = self._get_config("alerting.notifiers.slack_webhook", "")
        self._email_config = {
            "smtp_host": self._get_config("alerting.notifiers.smtp_host", ""),
            "smtp_port": self._get_config("alerting.notifiers.smtp_port", 587),
            "email_from": self._get_config("alerting.notifiers.email_from", ""),
            "email_to": self._get_config("alerting.notifiers.email_to", ""),
        }

    def _get_config(self, path: str, default) -> any:
        """Get a nested config value by dot path, or return default."""
        if self.config is None:
            return default
        try:
            parts = path.split(".")
            value = self.config
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                elif hasattr(value, part):
                    value = getattr(value, part)
                else:
                    return default
            return value if value is not None else default
        except (AttributeError, KeyError, TypeError):
            return default

    def _signature(self, alert: Alert) -> str:
        """
        Generate a unique signature for an alert based on its key characteristics.

        Alerts with the same signature are considered duplicates.
        """
        data = f"{alert.severity.name}:{alert.title}:{alert.summary}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _check_cooldown(self, signature: str) -> bool:
        """Check if the alert is within cooldown. Returns True if allowed."""
        now = datetime.now()
        if signature in self._last_alert_time:
            elapsed = (now - self._last_alert_time[signature]).total_seconds()
            if elapsed < self._cooldown_seconds:
                return False  # Still in cooldown
        return True

    def _check_rate_limit(self) -> bool:
        """Check if we're within the per-minute rate limit. Returns True if allowed."""
        now = datetime.now()
        if (now - self._minute_start).total_seconds() >= 60:
            self._minute_count = 0
            self._minute_start = now
        if self._minute_count >= self._max_per_minute:
            return False  # Rate limited
        self._minute_count += 1
        return True

    def generate(self, score: CompositeScore, stats: TrafficStats,
                 mitigation: Optional[Dict] = None) -> Optional[Alert]:
        """
        Generate an alert from a composite score.

        Returns the Alert if it should be delivered, None if suppressed
        by deduplication or rate limiting.
        """
        if score.total < 0.30:
            return None  # Below alert threshold

        alert = Alert(
            alert_id=f"alert-{int(time.time())}-{hashlib.md5(str(score.total).encode()).hexdigest()[:8]}",
            severity=score.severity,
            title=self._title_for(score),
            summary=self._summary_for(score, stats),
            attack_indicators=score.signal_scores,
            affected_services=[f"port-{stats.window.dst_ports.get(k, k)}" for k in list(stats.window.dst_ports.keys())[:3]] if hasattr(stats.window, 'dst_ports') else [],
            current_mitigation=mitigation or {},
            attack_sources=[{"ip": stats.window.top_srcs[i][0], "packets": stats.window.top_srcs[i][1]}
                           for i in range(min(3, len(stats.window.top_srcs)))] if hasattr(stats.window, 'top_srcs') else [],
            recommendations=self._recommendations_for(score),
            window=stats,
        )

        signature = self._signature(alert)
        if not self._check_cooldown(signature):
            return None  # Duplicate — suppressed
        if not self._check_rate_limit():
            return None  # Rate limited

        alert.occurred_at = datetime.now()
        self._last_alert_time[signature] = alert.occurred_at
        return alert

    def _title_for(self, score: CompositeScore) -> str:
        """Generate an alert title based on classification and severity."""
        classification = score.classification
        severity = score.severity.name
        if classification == "none":
            return "Normal traffic"
        elif classification == "volumetric":
            return f"Volumetric DDoS detected ({severity})"
        elif classification == "protocol":
            return f"Protocol attack detected ({severity})"
        elif classification == "application":
            return f"Application-layer attack detected ({severity})"
        elif classification == "mixed":
            return f"Mixed DDoS attack detected ({severity})"
        return f"Anomaly detected ({severity})"

    def _summary_for(self, score: CompositeScore, stats: TrafficStats) -> str:
        """Generate a human-readable summary."""
        parts = []
        parts.append(f"Score: {score.total:.3f} ({score.severity.name} severity)")
        parts.append(f"Classification: {score.classification}")
        parts.append(f"Packet rate: {stats.packet_rate:.1f} pps")
        parts.append(f"Byte rate: {stats.byte_rate:.0f} B/s")
        if score.signal_scores:
            fired = [f"{name}={score:.2f}" for name, score in score.signal_scores.items() if score > 0.3]
            if fired:
                parts.append(f"Signals: {', '.join(fired)}")
        return ". ".join(parts)

    def _recommendations_for(self, score: CompositeScore) -> List[str]:
        """Generate recommended actions based on classification."""
        recommendations = []
        classification = score.classification
        if classification == "volumetric":
            recommendations.append("Enable upstream rate limiting")
            recommendations.append("Consider blocking top source IPs")
            recommendations.append("Contact ISP for traffic scrubbing")
        elif classification == "protocol":
            recommendations.append("Enable SYN cookies")
            recommendations.append("Increase backlog queue")
            recommendations.append("Block repeat offenders via recent module")
        elif classification == "application":
            recommendations.append("Rate limit the targeted service port")
            recommendations.append("Deploy a web application firewall")
            recommendations.append("Consider CAPTCHA for suspicious requests")
        elif classification == "mixed":
            recommendations.append("Apply all applicable mitigations")
            recommendations.append("Escalate to incident response team")
        return recommendations

    def deliver(self, alert: Alert) -> None:
        """
        Deliver an alert to all enabled notifiers.
        """
        alert_dict = alert.to_dict()
        alert_json = json.dumps(alert_dict, indent=2, default=str)

        # Console (always enabled)
        if self._notifiers.get("console", True):
            print(f"\n{'='*60}")
            print(f"ALERT: [{alert.severity.name}] {alert.title}")
            print(f"{'='*60}")
            print(f"{alert.summary}")
            print(f"{'='*60}\n")

        # File (JSONL)
        if self._notifiers.get("file"):
            os.makedirs(os.path.dirname(self._file_path) or ".", exist_ok=True)
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(alert_json + "\n")

        # Desktop notification
        if self._notifiers.get("desktop"):
            self._notify_desktop(alert)

        # Slack
        if self._notifiers.get("slack") and self._slack_webhook:
            self._notify_slack(alert)

        # Email
        if self._notifiers.get("email") and self._email_config.get("smtp_host"):
            self._notify_email(alert)

    def _notify_desktop(self, alert: Alert) -> None:
        """Send a desktop notification (simplified cross-platform approach)."""
        try:
            # Try notify-send (Linux)
            subprocess.run([
                "notify-send",
                f"DDoS Alert: {alert.severity.name}",
                f"{alert.title}: {alert.summary[:100]}",
            ], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Desktop notification not available

    def _notify_slack(self, alert: Alert) -> None:
        """Send alert to Slack webhook."""
        try:
            import urllib.request
            import urllib.error
            payload = json.dumps({
                "text": f"*{alert.severity.name}* DDoS Alert: {alert.title}\n{alert.summary}",
                "username": "ddosguard",
                "icon_emoji": ":rotating_light:",
            }).encode("utf-8")
            req = urllib.request.Request(
                self._slack_webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass  # Slack notification failed silently

    def _notify_email(self, alert: Alert) -> None:
        """Send alert via email (simplified)."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(f"Severity: {alert.severity.name}\n\n{alert.title}\n\n{alert.summary}")
            msg["Subject"] = f"DDoS Alert: {alert.severity.name} - {alert.title}"
            msg["From"] = self._email_config["email_from"]
            msg["To"] = self._email_config["email_to"]
            server = smtplib.SMTP(self._email_config["smtp_host"], self._email_config["smtp_port"])
            server.starttls()
            server.send_message(msg)
            server.quit()
        except Exception:
            pass  # Email notification failed silently

    def get_timeline(self, limit: int = 100) -> List[Dict]:
        """
        Get the alert timeline from the file store.

        Returns the most recent alerts from the JSONL file.
        """
        if not os.path.exists(self._file_path):
            return []
        alerts = []
        with open(self._file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return alerts[-limit:]
```

Add exports:
```python
__all__ = ["AlertManager"]
```

**What you'll learn**:
- **Hash-based signatures**: using a hash of alert characteristics to detect duplicates. Same attack → same hash → suppressed.
- **Cooldown tracking**: storing the last alert time per signature in a dict.
- **Rate limiting alerts**: a separate counter for alerts per minute, distinct from the packet rate limiter.
- **Multi-channel delivery**: each notifier is independent; if one fails (e.g., no Slack webhook configured), the others still work.
- **JSONL format**: one JSON object per line — easy to append to and easy to read back line by line. Common format for log/alert storage.

**Why it matters**: Alerting bridges the gap between detection and human response. Without good alerting, attacks go unnoticed. With bad alerting (no dedup, no rate limit), administrators get overwhelmed and start ignoring alerts.

**Verify**:
```bash
python -c "
from ddosguard.alert.manager import AlertManager
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import TrafficStats, TrafficWindow, PacketRecord, Protocol, Severity
from datetime import datetime, timedelta
import os, json

# Setup
config = Config.load(None)
baseline = BaselineStore(config, data_dir='data')
baseline.set_ready(True)
scorer = CompositeScorer(config)
manager = AlertManager(config)

# Make config file-based alerting enabled
os.makedirs('data', exist_ok=True)

# Train baseline with normal traffic
now = datetime.now()
for i in range(20):
    window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    for j in range(50):
        pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{j%254}', dst_ip='10.0.0.1',
                           protocol=Protocol.TCP, src_port=12345, dst_port=80,
                           length=100, flags='PA')
        window.add(pkt)
    baseline.observe(window.finalize(), now)

# Score attack traffic
attack_window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
for j in range(2000):
    pkt = PacketRecord(ts=now, src_ip=f'10.0.0.{j%254}', dst_ip='10.0.0.1',
                       protocol=Protocol.TCP, src_port=12345, dst_port=80,
                       length=64, flags='S')
    attack_window.add(pkt)
attack_stats = attack_window.finalize()
score = scorer.score(attack_stats, baseline)

print(f'Score: {score.total:.3f}, Classification: {score.classification}')

# Generate alert
alert = manager.generate(score, attack_stats)
if alert:
    print(f'Alert generated: [{alert.severity.name}] {alert.title}')
    print(f'Summary: {alert.summary[:100]}...')
    print(f'Recommendations: {alert.recommendations}')
    manager.deliver(alert)
    print('Alert delivered (console)')
else:
    print('No alert generated (score too low or suppressed)')

# Test dedup: generate same alert again immediately
alert2 = manager.generate(score, attack_stats)
print(f'\\nSecond alert (dedup test): {\"suppressed\" if alert2 is None else \"generated\"}')

# Check file output
if os.path.exists('data/alerts.jsonl'):
    with open('data/alerts.jsonl') as f:
        lines = f.readlines()
    print(f'\\nAlerts in file: {len(lines)}')
    if lines:
        alert_data = json.loads(lines[-1])
        print(f'Last alert in file: {alert_data[\"severity\"]} - {alert_data[\"title\"]}')
"

```

Expected: alert generated for the attack traffic, delivered to console, written to JSONL file, second attempt suppressed by dedup.

**Estimated time**: 35 minutes

---

### Step 22: Implement Alert Director

**Task**: Create `ddosguard/alert/director.py` with the `AlertDirector` class for ranking and prioritization.

```python
"""
Alert director: ranking, prioritization, and urgent alert extraction.

Provides a higher-level interface over AlertManager for:
  - Ranking alerts by severity
  - Extracting urgent (CRITICAL) alerts
  - Managing the alert queue
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ddosguard.alert.manager import AlertManager
from ddosguard.core import Alert, Severity, SEVERITY_ORDER


class AlertDirector:
    """
    Manages and ranks alerts for administrator consumption.

    Wraps AlertManager and provides:
      - A ranked alert queue (most severe first)
      - Urgent alert extraction (CRITICAL only)
      - Timeline access
    """

    def __init__(self, config=None):
        self._manager = AlertManager(config)
        self._seen: Dict[str, Alert] = {}  # signature -> Alert

    @property
    def manager(self) -> AlertManager:
        """Access to the underlying AlertManager."""
        return self._manager

    def add_alert(self, alert: Alert) -> None:
        """Add an alert to the director's seen set."""
        sig = self._signature(alert)
        self._seen[sig] = alert

    def get_urgent(self) -> List[Alert]:
        """
        Get all CRITICAL severity alerts, ranked by severity order.

        Returns alerts sorted with CRITICAL first.
        """
        urgent = [a for a in self._seen.values() if a.severity == Severity.CRITICAL]
        return sorted(urgent, key=lambda a: SEVERITY_ORDER.index(a.severity))

    def get_timeline(self, limit: int = 50) -> List[Alert]:
        """
        Get all seen alerts, ranked by severity (most severe first).

        Returns a list of Alert objects sorted by severity.
        """
        alerts = list(self._seen.values())
        return sorted(alerts, key=lambda a: SEVERITY_ORDER.index(a.severity))[-limit:]

    def get_by_severity(self, severity: Severity) -> List[Alert]:
        """Get all alerts of a specific severity."""
        return [a for a in self._seen.values() if a.severity == severity]

    def get_summary(self) -> Dict[str, int]:
        """Get a summary of alerts by severity."""
        summary = {s.name: 0 for s in SEVERITY_ORDER}
        for alert in self._seen.values():
            summary[alert.severity.name] = summary.get(alert.severity.name, 0) + 1
        return summary

    def clear(self) -> None:
        """Clear all seen alerts."""
        self._seen.clear()

    def _signature(self, alert: Alert) -> str:
        """Generate a signature for an alert."""
        import hashlib
        data = f"{alert.severity.name}:{alert.title}:{alert.summary}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
```

Add exports:
```python
__all__ = ["AlertDirector"]
```

**What you'll learn**:
- **Separation of concerns**: `AlertManager` handles delivery mechanics (dedup, cooldown, channels). `AlertDirector` handles the administrator-facing view (ranking, urgent alerts, summaries). This separation makes each class easier to test and use.
- **Severity ordering**: using `SEVERITY_ORDER` to sort alerts so the most critical ones surface first.
- **Aggregation**: `get_summary()` gives a quick overview (how many of each severity) without reading every alert.

**Why it matters**: During an attack, administrators don't have time to read every alert. They need the most critical ones surfaced first. The director provides that prioritization.

**Verify**:
```bash
python -c "
from ddosguard.alert.director import AlertDirector
from ddosguard.core import Alert, Severity, CompositeScore, TrafficStats, TrafficWindow
from datetime import datetime, timedelta
import time

director = AlertDirector()

# Create fake alerts at different severities
now = datetime.now()
for sev, title in [
    (Severity.INFO, 'Normal traffic'),
    (Severity.LOW, 'Minor anomaly'),
    (Severity.MEDIUM, 'Moderate spike'),
    (Severity.HIGH, 'High volume attack'),
    (Severity.CRITICAL, 'CRITICAL DDoS in progress'),
]:
    alert = Alert(
        alert_id=f'test-{sev.name}',
        severity=sev,
        title=title,
        summary=f'Test alert at {sev.name} level',
        occurred_at=now,
    )
    director.add_alert(alert)

print('=== Summary ===')
print(director.get_summary())

print('\\n=== Urgent (CRITICAL only) ===')
for a in director.get_urgent():
    print(f'  [{a.severity.name}] {a.title}')

print('\\n=== Full timeline (most severe first) ===')
for a in director.get_timeline(10):
    print(f'  [{a.severity.name}] {a.title}')
"

```

Expected: summary shows counts per severity, urgent shows only CRITICAL, timeline shows all sorted by severity.

**Estimated time**: 20 minutes

---

## Phase 9: Dashboard & Controls

### Step 23: Set Up the FastAPI Dashboard

**Task**: Create `ddosguard/dashboard/app.py` — the FastAPI web application for the live dashboard.

```python
"""
Live dashboard for ddosguard — FastAPI web application.

Provides real-time read endpoints for:
  - Pipeline status
  - Traffic statistics
  - Baseline models
  - Alerts timeline
  - Mitigation actions
  - Whitelist management
  - Control endpoints (pause/resume)

Serves a static HTML dashboard with live JS polling.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ddosguard.core import (
    Alert,
    MitigationAction,
    Severity,
    SEVERITY_ORDER,
    TrafficStats,
    WhitelistedIp,
)
from ddosguard.monitor import MonitorState


app = FastAPI(title="ddosguard Dashboard", description="Live DDoS monitoring dashboard")

# Shared state (populated by MonitorRunner at runtime)
state = MonitorState()


# ---------------------------------------------------------------------------
# Pydantic models for request/response validation
# ---------------------------------------------------------------------------

class WhitelistAddRequest(BaseModel):
    ip: str
    reason: str = ""


class WhitelistRemoveRequest(BaseModel):
    ip: str


class MitigationRequest(BaseModel):
    stage: int = 1
    reason: str = ""


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Serve the dashboard HTML."""
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return {"error": "Dashboard HTML not found"}


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def get_status():
    """Get current pipeline status."""
    return {
        "running": state.running,
        "paused": state.paused,
        "current_severity": state.current_severity.name if state.current_severity else "INFO",
        "mitigation_stage": state.mitigation_stage,
        "packet_rate": state.current_stats.packet_rate if state.current_stats else 0.0,
        "byte_rate": state.current_stats.byte_rate if state.current_stats else 0.0,
        "alert_count": len(state.alerts),
        "active_mitigations": len(state.mitigations),
        "baseline_ready": state.baseline and state.baseline.is_ready,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/stats")
async def get_stats():
    """Get latest traffic statistics."""
    if state.current_stats:
        s = state.current_stats
        return {
            "packet_rate": s.packet_rate,
            "byte_rate": s.byte_rate,
            "syn_ratio": s.syn_ratio,
            "per_proto": s.per_proto,
            "unique_sources": s.window.top_talkers.src_unique if hasattr(s.window, 'top_talkers') else 0,
            "top_sources": getattr(s.window, 'top_srcs', [])[:10],
            "top_ports": getattr(s.window, 'top_talkers', {}).dst_ports[:10] if hasattr(s.window, 'top_talkers') else [],
            "window_start": s.window.start.isoformat(),
            "window_end": s.window.end.isoformat(),
        }
    return {"packet_rate": 0, "byte_rate": 0}


@app.get("/api/baseline")
async def get_baseline():
    """Get current baseline models."""
    if state.baseline:
        buckets = {}
        for key, stats in state.baseline.all().items():
            buckets[key] = {
                "mean": stats.mean,
                "stdev": stats.stdev,
                "count": stats.count,
                "p5": stats.p5,
                "p25": stats.p25,
                "p75": stats.p75,
                "p95": stats.p95,
                "p99": stats.p99,
            }
        return {
            "buckets": buckets,
            "ready": state.baseline.is_ready,
            "bucket_count": len(buckets),
        }
    return {"buckets": {}, "ready": False, "bucket_count": 0}


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts."""
    alerts = state.alerts[-limit:] if state.alerts else []
    return {
        "alerts": [a.to_dict() for a in alerts],
        "count": len(alerts),
    }


@app.get("/api/mitigations")
async def get_mitigations():
    """Get active mitigation actions."""
    return {
        "mitigations": [m.to_dict() for m in state.mitigations],
        "count": len(state.mitigations),
        "current_stage": state.mitigation_stage,
    }


@app.get("/api/whitelist")
async def get_whitelist():
    """Get current whitelist."""
    return {
        "whitelist": [w.to_dict() for w in state.whitelist],
        "count": len(state.whitelist),
    }


@app.post("/api/whitelist")
async def add_whitelist(request: WhitelistAddRequest):
    """Add an IP to the whitelist."""
    from ddosguard.monitor import WhitelistStore
    ws = WhitelistStore("data/whitelist.json")
    ws.add(request.ip, request.reason)
    state.whitelist = ws.all()
    return {"status": "added", "ip": request.ip}


@app.post("/api/whitelist/remove")
async def remove_whitelist(request: WhitelistRemoveRequest):
    """Remove an IP from the whitelist."""
    from ddosguard.monitor import WhitelistStore
    ws = WhitelistStore("data/whitelist.json")
    ws.remove(request.ip)
    state.whitelist = ws.all()
    return {"status": "removed", "ip": request.ip}


@app.get("/api/rate-limit")
async def get_rate_limit():
    """Get current rate limit configuration."""
    return {
        "default_rate": state.rate_limit_config.get("default_rate", 100),
        "default_burst": state.rate_limit_config.get("default_burst", 200),
        "whitelist_count": len(state.whitelist),
    }


@app.post("/api/mitigate")
async def trigger_mitigation(request: MitigationRequest):
    """Trigger a mitigation action (for manual control from dashboard)."""
    action = MitigationAction(
        id=f"manual-{int(time.time())}",
        rule_type="rate_limit",
        target="all",
        action="deny",
        reason=request.reason or f"Manual stage {request.stage} mitigation",
        severity=Severity.MEDIUM,
        applied_at=datetime.now(),
    )
    state.mitigations.append(action)
    state.mitigation_stage = request.stage
    return {"status": "applied", "action": action.to_dict()}


@app.post("/api/mitigations/clear")
async def clear_mitigations():
    """Clear all active mitigations."""
    state.mitigations.clear()
    state.mitigation_stage = 0
    return {"status": "cleared"}


@app.post("/api/control/pause")
async def pause_monitor():
    """Pause the monitoring pipeline."""
    state.paused = True
    return {"status": "paused"}


@app.post("/api/control/resume")
async def resume_monitor():
    """Resume the monitoring pipeline."""
    state.paused = False
    return {"status": "resumed"}


# ---------------------------------------------------------------------------
# Mount static files (CSS, JS, etc.)
# ---------------------------------------------------------------------------

static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
```

Create `ddosguard/dashboard/__init__.py`:
```python
"""Dashboard module — FastAPI web application for live monitoring."""
```

**What you'll learn**:
- **FastAPI basics**: creating an app, defining routes with decorators, returning dictionaries (automatically serialized to JSON)
- **Pydantic models**: using `BaseModel` for request validation. The `WhitelistAddRequest` ensures the POST body has an `ip` field.
- **Statelessness**: each endpoint is a function that reads from shared state. There's no database — everything is in memory. This is fine for a demo/dashboard but wouldn't scale to multiple servers.
- **Static file serving**: `StaticFiles` mounts a directory for CSS/JS/images. Used here for the dashboard HTML and any assets.
- **API design**: the `/api/` endpoints are the data layer; the HTML page is the UI layer. This separation is common in modern web apps.

**Why it matters**: The dashboard is how humans interact with the system. Without it, you'd be reading console output or parsing JSONL files. A live web dashboard makes the system accessible and understandable.

**Verify**:
```bash
python -c "
from ddosguard.dashboard.app import app
import json

# Test that the app can be imported and has routes
routes = [r.path for r in app.routes if hasattr(r, 'path')]
print(f'Routes: {len(routes)}')
for r in sorted(routes):
    print(f'  {r}')

# Test the status endpoint by simulating a request
from fastapi.testclient import TestClient
client = TestClient(app)
response = client.get('/api/status')
print(f'\\nStatus endpoint: {response.status_code}')
data = response.json()
print(f'packet_rate: {data[\"packet_rate\"]}')
print(f'baseline_ready: {data[\"baseline_ready\"]}')
"
```

Expected: lists all API routes, status endpoint returns JSON with zero values (no traffic yet).

**Estimated time**: 30 minutes

---

### Step 24: Create the Dashboard HTML

**Task**: Create `ddosguard/dashboard/static/index.html` — the live web dashboard UI.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ddosguard — Live Dashboard</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
            --info: #3b82f6;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }

        h1 { font-size: 1.5rem; margin-bottom: 16px; color: var(--accent); }
        h2 { font-size: 1rem; margin-bottom: 8px; color: var(--muted); font-weight: 500; }

        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }

        .card h2 { margin-bottom: 12px; }

        .metric {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            padding: 8px 0;
            border-bottom: 1px solid var(--border);
        }
        .metric:last-child { border-bottom: none; }
        .metric-label { color: var(--muted); font-size: 0.875rem; }
        .metric-value { font-weight: 600; font-size: 1.125rem; font-variant-numeric: tabular-nums; }

        .severity-dot {
            display: inline-block;
            width: 12px; height: 12px;
            border-radius: 50%;
            margin-right: 6px;
            vertical-align: middle;
        }
        .severity-critical { background: var(--danger); }
        .severity-high { background: var(--warning); }
        .severity-medium { background: var(--accent); }
        .severity-low { background: var(--info); }
        .severity-info { background: var(--muted); }

        .alert-item {
            padding: 10px;
            margin-bottom: 8px;
            background: var(--bg);
            border-left: 3px solid var(--border);
            border-radius: 4px;
            font-size: 0.875rem;
        }
        .alert-item.critical { border-left-color: var(--danger); }
        .alert-item.high { border-left-color: var(--warning); }
        .alert-item.medium { border-left-color: var(--accent); }

        .btn {
            padding: 8px 16px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--surface);
            color: var(--text);
            cursor: pointer;
            font-size: 0.875rem;
            margin-right: 8px;
            margin-bottom: 8px;
        }
        .btn:hover { background: var(--border); }
        .btn.danger { border-color: var(--danger); color: var(--danger); }
        .btn.danger:hover { background: var(--danger); color: white; }
        .btn.success { border-color: var(--success); color: var(--success); }

        .section {
            margin-bottom: 24px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: var(--muted); font-weight: 500; }

        .spark {
            height: 60px;
            margin-top: 8px;
        }

        .status-bar {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }

        .status-pill {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        .pill-running { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .pill-paused { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .pill-ready { background: rgba(56, 189, 248, 0.2); color: var(--accent); }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 0.8rem;
            text-align: center;
        }

        #update-time {
            color: var(--muted);
            font-size: 0.75rem;
            text-align: right;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>ddosguard — Live Dashboard</h1>

        <div class="status-bar">
            <span class="status-pill pill-running" id="status-running">● Running</span>
            <span class="status-pill pill-ready" id="status-baseline">● Baseline: Training</span>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Current Traffic</h2>
                <div class="metric">
                    <span class="metric-label">Packet Rate</span>
                    <span class="metric-value" id="metric-pps">0 pps</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Byte Rate</span>
                    <span class="metric-value" id="metric-bps">0 B/s</span>
                </div>
                <div class="metric">
                    <span class="metric-label">SYN Ratio</span>
                    <span class="metric-value" id="metric-syn">0%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Mitigation Stage</span>
                    <span class="metric-value" id="metric-stage">0 (none)</span>
                </div>
                <canvas class="spark" id="spark-pps"></canvas>
            </div>

            <div class="card">
                <h2>Alert Summary</h2>
                <div class="metric">
                    <span class="metric-label">Total Alerts</span>
                    <span class="metric-value" id="metric-alert-count">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Current Severity</span>
                    <span class="metric-value" id="metric-severity">
                        <span class="severity-dot severity-info"></span>INFO
                    </span>
                </div>
                <div class="metric">
                    <span class="metric-label">Active Mitigations</span>
                    <span class="metric-value" id="metric-mitigations">0</span>
                </div>
            </div>

            <div class="card">
                <h2>Controls</h2>
                <button class="btn" onclick="fetchEndpoint('/api/control/pause')">Pause</button>
                <button class="btn" onclick="fetchEndpoint('/api/control/resume')">Resume</button>
                <button class="btn danger" onclick="fetchEndpoint('/api/mitigations/clear')">Clear Mitigations</button>
                <hr style="border-color: var(--border); margin: 12px 0;">
                <h2>Add to Whitelist</h2>
                <input type="text" id="whitelist-ip" placeholder="IP address" style="width:100%; padding:6px; margin-bottom:6px; background:var(--bg); border:1px solid var(--border); color:var(--text); border-radius:4px;">
                <button class="btn success" onclick="addWhitelist()">Add Whitelist Entry</button>
                <div id="whitelist-status" style="margin-top:8px; font-size:0.8rem; color:var(--muted);"></div>
            </div>
        </div>

        <div class="section">
            <div class="card">
                <h2>Recent Alerts</h2>
                <div id="alerts-container">
                    <p style="color:var(--muted); font-size:0.875rem;">No alerts yet.</p>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="card">
                <h2>Baseline Buckets</h2>
                <div style="overflow-x:auto;">
                    <table>
                        <thead>
                            <tr><th>Bucket</th><th>Mean</th><th>Stdev</th><th>Count</th><th>P95</th></tr>
                        </thead>
                        <tbody id="baseline-table">
                            <tr><td colspan="5" style="color:var(--muted);">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="footer">
            ddosguard — DDoS Detection & Mitigation Toolkit<br>
            <span id="update-time">Not connected</span>
        </div>
    </div>

    <script>
        // Poll interval in milliseconds
        const POLL_MS = 2000;
        let ppsHistory = [];

        async function fetchEndpoint(path) {
            try {
                const resp = await fetch(path, { method: 'POST' });
                const data = await resp.json();
                console.log('Endpoint response:', path, data);
                updateStatus();
            } catch (e) {
                console.error('Endpoint error:', e);
            }
        }

        async function addWhitelist() {
            const ip = document.getElementById('whitelist-ip').value.trim();
            if (!ip) return;
            try {
                const resp = await fetch('/api/whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip, reason: 'Added from dashboard' })
                });
                const data = await resp.json();
                document.getElementById('whitelist-status').textContent = data.status + ': ' + data.ip;
                updateStatus();
            } catch (e) {
                console.error('Whitelist error:', e);
            }
        }

        function drawSpark() {
            const canvas = document.getElementById('spark-pps');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const w = canvas.width = canvas.clientWidth;
            const h = canvas.height = canvas.clientHeight;
            ctx.clearRect(0, 0, w, h);

            if (ppsHistory.length < 2) return;

            const maxVal = Math.max(...ppsHistory, 1);
            const step = w / (ppsHistory.length - 1);

            // Draw line
            ctx.beginPath();
            ctx.strokeStyle = '#38bdf8';
            ctx.lineWidth = 2;
            ppsHistory.forEach((val, i) => {
                const x = i * step;
                const y = h - (val / maxVal) * (h - 4) - 2;
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();

            // Fill area under line
            ctx.lineTo(w, h);
            ctx.lineTo(0, h);
            ctx.closePath();
            ctx.fillStyle = 'rgba(56, 189, 248, 0.1)';
            ctx.fill();
        }

        function updateStatus() {
            Promise.all([
                fetch('/api/status').then(r => r.json()),
                fetch('/api/stats').then(r => r.json()),
                fetch('/api/alerts').then(r => r.json()),
                fetch('/api/baseline').then(r => r.json()),
            ]).then(([status, stats, alerts, baseline]) => {
                // Status
                document.getElementById('status-running').textContent =
                    status.running ? '● Running' : '○ Stopped';
                document.getElementById('status-running').className =
                    'status-pill ' + (status.running ? 'pill-running' : 'pill-paused');
                document.getElementById('status-baseline').textContent =
                    '● Baseline: ' + (status.baseline_ready ? 'Ready' : 'Training');
                document.getElementById('metric-stage').textContent =
                    status.mitigation_stage + ' (' +
                    (status.mitigation_stage === 0 ? 'none' :
                     status.mitigation_stage === 1 ? 'lenient' :
                     status.mitigation_stage === 2 ? 'strict' :
                     status.mitigation_stage === 3 ? 'port limits' : 'full DROP') + ')';

                // Metrics
                document.getElementById('metric-pps').textContent =
                    stats.packet_rate.toFixed(1) + ' pps';
                document.getElementById('metric-bps').textContent =
                    stats.byte_rate.toFixed(0) + ' B/s';
                document.getElementById('metric-syn').textContent =
                    (stats.syn_ratio * 100).toFixed(1) + '%';

                // Severity
                const sevEl = document.getElementById('metric-severity');
                const sevMap = {
                    'CRITICAL': 'severity-critical',
                    'HIGH': 'severity-high',
                    'MEDIUM': 'severity-medium',
                    'LOW': 'severity-low',
                    'INFO': 'severity-info',
                };
                const cls = sevMap[status.current_severity] || 'severity-info';
                sevEl.innerHTML = `<span class="severity-dot ${cls}"></span>${status.current_severity}`;

                // Counts
                document.getElementById('metric-alert-count').textContent = alerts.count;
                document.getElementById('metric-mitigations').textContent = status.active_mitigations;

                // Alerts
                const container = document.getElementById('alerts-container');
                if (alerts.alerts.length === 0) {
                    container.innerHTML = '<p style="color:var(--muted); font-size:0.875rem;">No alerts yet.</p>';
                } else {
                    container.innerHTML = alerts.alerts.map(a => `
                        <div class="alert-item ${a.severity.toLowerCase()}">
                            <strong>[${a.severity}]</strong> ${a.title}
                            <div style="color:var(--muted); margin-top:4px;">${a.summary.substring(0, 120)}...</div>
                            <div style="color:var(--muted); font-size:0.75rem; margin-top:4px;">${a.occurred_at}</div>
                        </div>
                    `).join('');
                }

                // Baseline
                const tbody = document.getElementById('baseline-table');
                const entries = Object.entries(baseline.buckets).slice(0, 20);
                if (entries.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);">No baseline data yet.</td></tr>';
                } else {
                    tbody.innerHTML = entries.map(([key, vals]) => `
                        <tr>
                            <td>${key}</td>
                            <td>${vals.mean.toFixed(1)}</td>
                            <td>${vals.stdev.toFixed(1)}</td>
                            <td>${vals.count}</td>
                            <td>${vals.p95.toFixed(1)}</td>
                        </tr>
                    `).join('');
                }

                // Sparkline
                ppsHistory.push(stats.packet_rate);
                if (ppsHistory.length > 50) ppsHistory.shift();
                drawSpark();

                // Update time
                document.getElementById('update-time').textContent =
                    'Last updated: ' + new Date().toLocaleTimeString();
            }).catch(e => {
                console.error('Status update error:', e);
            });
        }

        // Start polling
        updateStatus();
        setInterval(updateStatus, POLL_MS);
    </script>
</body>
</html>
```

**What you'll learn**:
- **HTML structure**: the semantic elements (`header`, `main`, `section`, `table`) and how they organize a page
- **CSS custom properties** (`:root { --bg: ... }`): variables that make theming consistent. Change `--bg` and the whole dark theme updates.
- **CSS Grid** (`grid-template-columns: repeat(auto-fit, minmax(280px, 1fr))`): a responsive layout that automatically adjusts columns based on screen width
- **Vanilla JavaScript fetch API**: making HTTP requests without libraries. `fetch('/api/status')` gets JSON, `.json()` parses it
- **Promise.all**: fetching multiple endpoints in parallel and waiting for all of them
- **Canvas API**: drawing a simple sparkline chart using `<canvas>` and 2D context
- **setInterval**: polling the API every 2 seconds for live updates
- **DOM manipulation**: `document.getElementById`, `.textContent`, `.innerHTML` to update the page

**Why it matters**: A dashboard makes the system usable. Without it, you'd need to parse JSON or watch console output. The HTML/JS dashboard is the "user interface" for your security tool.

**Verify**: Start the dashboard server and open it in a browser:
```bash
python -m ddosguard dashboard --port 8080
```
Then open `http://127.0.0.1:8080` in a browser. You should see the dashboard with "No alerts yet" and zero metrics. The page polls every 2 seconds.

**Estimated time**: 35 minutes

---

### Step 25: Wire the Dashboard to the Monitor

**Task**: Update `ddosguard/monitor.py` to connect the `MonitorRunner` to the dashboard state.

The `MonitorState` is the bridge between the running pipeline and the dashboard. It's a thread-safe snapshot that the dashboard reads.

```python
"""
Shared state and monitor runner for the DDoS detection pipeline.

MonitorState: thread-safe snapshot of the current pipeline state, used by
the dashboard to read live data.

MonitorRunner: the main loop that drives the pipeline:
  1. Capture packets from a source
  2. Aggregate into windows
  3. Update baseline (during training)
  4. Score traffic against baseline
  5. Decide on mitigation
  6. Generate and deliver alerts
  7. Update dashboard state
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from ddosguard.core import (
    Alert,
    CompositeScore,
    MitigationAction,
    PacketRecord,
    Severity,
    SignalResult,
    TrafficStats,
    WhitelistedIp,
)
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.capture.base import PacketSource
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.mitigate.firewall import FirewallManager
from ddosguard.mitigate.policy import MitigationPolicy
from ddosguard.mitigate.ratelimit import RateLimiter
from ddosguard.alert import AlertManager, AlertDirector


class MonitorState:
    """
    Thread-safe snapshot of the current pipeline state.

    The MonitorRunner updates this state on each loop iteration.
    The dashboard reads from it (no locking needed for reads of individual
    fields, but the snapshot pattern ensures consistency).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.running = False
        self.paused = False
        self.current_severity: Severity = Severity.INFO
        self.mitigation_stage: int = 0
        self.current_stats: Optional[TrafficStats] = None
        self.alerts: List[Alert] = []
        self.mitigations: List[MitigationAction] = []
        self.whitelist: List[WhitelistedIp] = []
        self.baseline: Optional[BaselineStore] = None
        self.rate_limit_config: Dict = {"default_rate": 100, "default_burst": 200}

    def snapshot(self) -> Dict:
        """Get a consistent snapshot of the current state."""
        with self._lock:
            return {
                "running": self.running,
                "paused": self.paused,
                "current_severity": self.current_severity.name,
                "mitigation_stage": self.mitigation_stage,
                "current_stats": self.current_stats.to_dict() if self.current_stats else None,
                "alerts": [a.to_dict() for a in self.alerts[-50:]],
                "mitigations": [m.to_dict() for m in self.mitigations],
                "whitelist": [w.to_dict() for w in self.whitelist],
                "baseline_ready": self.baseline.is_ready if self.baseline else False,
                "rate_limit_config": dict(self.rate_limit_config),
            }

    def update_stats(self, stats: TrafficStats) -> None:
        with self._lock:
            self.current_stats = stats

    def update_severity(self, severity: Severity) -> None:
        with self._lock:
            self.current_severity = severity

    def update_mitigation_stage(self, stage: int) -> None:
        with self._lock:
            self.mitigation_stage = stage

    def add_alert(self, alert: Alert) -> None:
        with self._lock:
            self.alerts.append(alert)

    def add_mitigation(self, action: MitigationAction) -> None:
        with self._lock:
            self.mitigations.append(action)

    def set_running(self, running: bool) -> None:
        with self._lock:
            self.running = running

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.paused = paused


class WhitelistStore:
    """Persists the whitelist to a JSON file."""

    def __init__(self, path: str = "data/whitelist.json"):
        self.path = path
        self._ips: Dict[str, str] = {}  # ip -> reason
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self._ips = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._ips = {}

    def add(self, ip: str, reason: str = "") -> None:
        self._ips[ip] = reason
        self._save()

    def remove(self, ip: str) -> bool:
        if ip in self._ips:
            del self._ips[ip]
            self._save()
            return True
        return False

    def all(self) -> List[WhitelistedIp]:
        return [WhitelistedIp(ip=ip, reason=reason) for ip, reason in self._ips.items()]

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self._ips, f, indent=2)


class MonitorRunner:
    """
    Main loop that drives the DDoS detection and mitigation pipeline.

    Pipeline per iteration:
      1. Capture packets from source
      2. Aggregate into time windows
      3. Update baseline (during training phase)
      4. Score against baseline
      5. Decide on mitigation
      6. Generate and deliver alerts
      7. Update dashboard state
    """

    def __init__(self, config: Config, source: PacketSource):
        self.config = config
        self.source = source
        self.state = MonitorState()
        self.baseline = BaselineStore(config, data_dir=config.baseline.get("data_dir", "data"))
        self.baseline.load()
        self.baseline.set_ready(True)
        self.scorer = CompositeScorer(config)
        self.limiter = RateLimiter(
            default_rate=config.mitigation.get("default_rate", 100),
            default_burst=config.mitigation.get("default_burst", 200),
        )
        self.firewall = FirewallManager(dry_run=config.mitigation.get("dry_run", True))
        self.alert_manager = AlertManager(config)
        self.alert_director = AlertDirector(config)
        self.mitigation_policy = MitigationPolicy(config)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._whitelist_store = WhitelistStore("data/whitelist.json")
        self.state.whitelist = self._whitelist_store.all()

        # Load whitelist into rate limiter
        for ip in self.state.whitelist:
            self.limiter.add_whitelist(ip.ip)

        # Load mitigation stage from config
        self.state.mitigation_stage = config.mitigation.get("stage", 0)

    def start(self) -> None:
        """Start the monitoring loop in a background thread."""
        self.state.set_running(True)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logging.info("MonitorRunner started")

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        self.state.set_running(False)
        logging.info("MonitorRunner stopped")

    def _run(self) -> None:
        """Main monitoring loop."""
        window_seconds = self.config.capture.get("window_seconds", 10.0)
        aggregator = __import__('ddosguard.metrics.window', fromlist=['WindowAggregator']).WindowAggregator(window_seconds)

        logging.info("Monitor loop started, window=%ss", window_seconds)

        while not self._stop_event.is_set():
            if self.state.paused:
                time.sleep(0.5)
                continue

            try:
                for pkt in self.source.iter_packets(window_seconds):
                    if self._stop_event.is_set():
                        break
                    if self.state.paused:
                        break

                    aggregator.add(pkt)

                    if aggregator.is_window_complete(pkt.ts):
                        stats = aggregator.finalize()
                        self._process_window(stats)
                        aggregator = __import__('ddosguard.metrics.window', fromlist=['WindowAggregator']).WindowAggregator(window_seconds)
                        break  # Process one window per outer loop iteration

                time.sleep(0.1)  # Brief sleep to avoid busy-waiting
            except Exception as e:
                logging.error("Error in monitor loop: %s", e, exc_info=True)
                time.sleep(1.0)

    def _process_window(self, stats: TrafficStats) -> None:
        """Process a single window of traffic."""
        # Update baseline (always observe, even during attack, so baseline can adapt)
        self.baseline.observe(stats, stats.window.start)

        # Score the traffic
        score = self.scorer.score(stats, self.baseline)

        # Update state
        self.state.update_stats(stats)
        self.state.update_severity(score.severity)
        self.state.update_mitigation_stage(score.severity.value)  # Map severity to stage

        # Mitigation decision
        action = self.mitigation_policy.decide(score, stats)
        if action:
            self.mitigation_policy.apply(action)
            self.state.add_mitigation(action)

            # Generate firewall rules for the current stage
            whitelist_ips = [w.ip for w in self.state.whitelist]
            rules = self.firewall.generate_rules(
                stage=score.severity.value,
                severity=score.severity.name,
                config={"rate_limits": self.config.mitigation.get("rate_limits", [])},
                whitelist=whitelist_ips,
            )
            if rules and not self.config.mitigation.get("dry_run", True):
                self.firewall.apply(rules)

        # Alert generation
        alert = self.alert_manager.generate(score, stats)
        if alert:
            self.alert_manager.deliver(alert)
            self.alert_director.add_alert(alert)
            self.state.add_alert(alert)

        logging.info(
            "Window: pps=%.1f sev=%s stage=%d alerts=%d",
            stats.packet_rate,
            score.severity.name,
            self.state.mitigation_stage,
            len(self.state.alerts),
        )
```

Add exports in `ddosguard/monitor.py`:
```python
__all__ = ["MonitorState", "WhitelistStore", "MonitorRunner"]
```

**What you'll learn**:
- **Threading**: the monitor runs in a background thread so the dashboard can serve HTTP in the foreground. `threading.Event` is the thread-safe way to signal "stop".
- **Thread safety**: `MonitorState` uses a `Lock` to protect writes. Reads of individual fields are safe without locking (Python's GIL helps), but the snapshot method acquires the lock for consistency.
- **The full pipeline loop**: this is where everything comes together — capture → window → baseline → score → mitigate → alert → update state. Reading this method is like reading the system's heartbeat.
- **Daemon threads**: `daemon=True` means the thread won't prevent the program from exiting. Important for clean shutdown.

**Why it matters**: This is the glue code that connects all the pieces. Understanding it means you understand how the entire system runs end-to-end.

**Verify**:
```bash
python -c "
from ddosguard.monitor import MonitorState, MonitorRunner
from ddosguard.config import Config
from ddosguard.capture.base import SyntheticGenerator

config = Config.load(None)
source = SyntheticGenerator(mode='normal', base_rate=50)
runner = MonitorRunner(config, source)

print(f'State initial: running={runner.state.running}')
print(f'Baseline ready: {runner.baseline.is_ready}')
print(f'Whitelist count: {len(runner.state.whitelist)}')

# Start and stop quickly (just to test lifecycle)
runner.start()
import time
time.sleep(1)
runner.stop()
print(f'After stop: running={runner.state.running}')
print('MonitorRunner lifecycle OK')
"
```

Expected: state initializes, baseline loads, whitelist loads, runner starts and stops cleanly.

**Estimated time**: 30 minutes

---

## Phase 10: CLI & Packaging

### Step 26: Build the CLI

**Task**: Create `ddosguard/cli.py` — the command-line interface with subcommands.

```python
"""
Command-line interface for ddosguard.

Subcommands:
  baseline    Train the baseline model
  monitor     Live monitor with dashboard
  replay      Offline pcap analysis
  simulate    Synthetic attack demo
  alert       View persisted alerts
  dashboard   Run dashboard only
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from ddosguard import __version__
from ddosguard.alert import AlertManager
from ddosguard.baseline import BaselineStore
from ddosguard.config import Config
from ddosguard.capture import pcap_source, scapy_source
from ddosguard.capture.base import SyntheticGenerator
from ddosguard.detect import CompositeScorer
from ddosguard.metrics.window import WindowAggregator
from ddosguard.mitigate.firewall import FirewallManager
from ddosguard.mitigate.policy import MitigationPolicy
from ddosguard.core import Severity, SEVERITY_ORDER

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("ddosguard")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ddosguard",
        description="DDoS detection and mitigation toolkit",
    )
    p.add_argument("--version", action="version", version=f"ddosguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # baseline
    baseline = sub.add_parser("baseline", help="train the baseline model")
    baseline.add_argument("--seconds", type=int, default=600, help="observation duration (seconds)")
    baseline.add_argument("--config", default="config.yaml")
    baseline.add_argument("--source", choices=["synthetic", "scapy", "pcap"], default="synthetic")
    baseline.add_argument("--pcap", default=None)
    baseline.add_argument("--interval", type=float, default=10.0)

    # monitor
    monitor = sub.add_parser("monitor", help="live monitor with dashboard")
    monitor.add_argument("--config", default="config.yaml")
    monitor.add_argument("--no-dashboard", action="store_true")
    monitor.add_argument("--host", default="127.0.0.1")
    monitor.add_argument("--port", type=int, default=8080)

    # replay
    replay = sub.add_parser("replay", help="analyze a pcap trace offline")
    replay.add_argument("pcap", help="pcap file to replay")
    replay.add_argument("--window", type=float, default=10.0)

    # simulate
    simulate = sub.add_parser("simulate", help="synthetic attack demo")
    simulate.add_argument("--family", choices=["volumetric", "syn_flood", "application"], default="volumetric")
    simulate.add_argument("--duration", type=float, default=45.0)
    simulate.add_argument("--packets", type=int, default=20000)

    # alert
    alert_cmd = sub.add_parser("alert", help="show/persist alerts")
    alert_cmd.add_argument("--file", default="data/alerts.jsonl")
    alert_cmd.add_argument("--limit", type=int, default=20)

    # dashboard
    dashboard = sub.add_parser("dashboard", help="run dashboard only")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8080)
    dashboard.add_argument("--config", default="config.yaml")

    return p


def _load_config(path: str | None) -> Config:
    cfg_path = path or "config.yaml"
    return Config.load(cfg_path)


def _make_source(config: Config, source: str, pcap_file: str | None = None):
    if source == "pcap":
        return pcap_source.PcapSource(pcap_file or config.capture.get("pcap_file", "data/live.pcap"))
    if source == "scapy":
        return scapy_source.ScapySource(config.capture.get("interface", "any"))
    return SyntheticGenerator(mode="normal")


def cmd_baseline(args) -> int:
    config = _load_config(args.config)
    source = _make_source(config, args.source, args.pcap)
    baseline = BaselineStore(config, data_dir=config.baseline.get("data_dir", "data"))
    baseline.load()
    baseline.set_ready(True)
    logger.info("baseline loaded: %d models", len(baseline.all()))

    win_sec = config.capture.get("window_seconds", 10)
    window = WindowAggregator(win_sec)
    end = time.monotonic() + args.seconds
    samples = 0
    while time.monotonic() < end:
        for pkt in source.iter_packets(win_sec):
            window.add(pkt)
            if (pkt.ts - window.start).total_seconds() >= win_sec:
                stats = window.finalize()
                baseline.observe(stats, pkt.ts)
                samples += 1
                if samples % 10 == 0:
                    logger.info("baseline: observed %d windows", samples)
                window = WindowAggregator(win_sec)
        time.sleep(0.05)
    baseline.save()
    logger.info("baseline saved (%d models)", len(baseline.all()))
    return 0


def cmd_monitor(args) -> int:
    config = _load_config(args.config)
    source = _make_source(config, config.capture.get("source", "synthetic"))

    from ddosguard.monitor import MonitorRunner

    monitor = MonitorRunner(config, source)
    monitor.state.baseline = monitor.baseline
    monitor.state.mitigations = MitigationPolicy(config)
    monitor.start()

    if not args.no_dashboard:
        import uvicorn
        from ddosguard.dashboard import app

        logger.info("dashboard: http://%s:%d", args.host, args.port)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")

    monitor.stop()
    return 0


def cmd_replay(args) -> int:
    config = _load_config(None)
    source = pcap_source.PcapSource(args.pcap, window_seconds=config.capture.get("window_seconds", 10))
    baseline = BaselineStore(config)
    scorer = CompositeScorer(config)
    win_sec = config.capture.get("window_seconds", 10)
    aggregator = WindowAggregator(win_sec)
    seq = list(source.iter_packets(win_sec, 0.0))
    for i in range(0, len(seq), 100):
        chunk = seq[i : i + 100]
        for pkt in chunk:
            aggregator.add(pkt)
        stats = aggregator.finalize()
        score = scorer.score(stats, baseline)
        logger.info(
            "[%04d] pps=%.1f bytes=%.0f proto=%s score=%.3f sev=%s",
            i // 100,
            stats.packet_rate,
            stats.byte_rate,
            {6: stats.per_proto.get(6, 0), 17: stats.per_proto.get(17, 0)},
            score.total,
            score.severity.name,
        )
    return 0


def cmd_simulate(args) -> int:
    generator = SyntheticGenerator(
        mode="attack",
        attack_family=args.family,
        attack_start=datetime.now(),
        attack_duration=args.duration,
        attack_mult=20,
    )
    logger.info("generating %s attack for %.1fs", args.family, args.duration)
    for pkt in generator.iter_packets(10.0, 0.0):
        print(f"{pkt.src_ip} {pkt.dst_ip} {pkt.protocol.name} {pkt.flags}", end=" ")
        if pkt.length % 100 == 0:
            print()
    return 0


def cmd_alert(args) -> int:
    if not os.path.exists(args.file):
        print(f"no alerts file at {args.file}")
        return 0
    with open(args.file, encoding="utf-8") as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    rows.sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]))
    for r in rows[-args.limit:]:
        print(f"{r['severity']:8s} {r['title']}")
        print(f"         {r['summary']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "baseline": cmd_baseline,
        "monitor": cmd_monitor,
        "replay": cmd_replay,
        "simulate": cmd_simulate,
        "alert": cmd_alert,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
```

**What you'll learn**:
- **argparse**: Python's built-in CLI framework. Subparsers let you have multiple commands (`baseline`, `monitor`, etc.) under one program.
- **Dispatch pattern**: a dictionary mapping command names to handler functions. Cleaner than a big if/elif chain.
- **Module entry points**: `if __name__ == "__main__"` lets you run the file directly (`python cli.py`) and also import it as a module.
- **Logging**: using Python's `logging` module instead of `print()` for operational messages. Gives you timestamps, levels, and easy configuration.

**Why it matters**: A CLI makes the tool usable from the command line — for scripts, automation, and interactive use. It's the primary interface for operators.

**Verify**:
```bash
python -m ddosguard --help
python -m ddosguard baseline --help
python -m ddosguard monitor --help
python -m ddosguard simulate --help
```

Expected: each shows its help text with available options.

**Estimated time**: 25 minutes

---

### Step 27: Create `__main__.py`

**Task**: Create `ddosguard/__main__.py` so you can run `python -m ddosguard` directly.

```python
"""Entry point for `python -m ddosguard`."""
from ddosguard.cli import main

main()
```

**What you'll learn**:
- **`__main__.py`**: the Python convention for making a package runnable with `python -m package`. Without it, `python -m ddosguard` fails.
- **Module vs package execution**: `python ddosguard/cli.py` runs the file directly. `python -m ddosguard` runs the package, which looks for `__main__.py`.

**Verify**:
```bash
python -m ddosguard --help
```
Expected: shows the main help with all subcommands.

**Estimated time**: 5 minutes

---

### Step 28: Create a Config File

**Task**: Create `config.yaml` with demonstration defaults.

```yaml
capture:
  source: synthetic          # synthetic | pcap | scapy
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
  dry_run: true              # set false to apply real iptables rules (requires root)
  stage: 0
  default_rate: 100
  default_burst: 200
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
  whitelist:
    - 192.168.1.1
    - 10.0.0.0/8

alerting:
  cooldown: 60
  max_per_minute: 10
  notifiers:
    console: true
    file: true
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

**What you'll learn**:
- **YAML**: a human-readable configuration format. Indentation matters (use spaces, not tabs). Lists use `-`, dicts use `key: value`.
- **Configuration-driven behavior**: the entire system is parameterized by this file. Change `dry_run: false` to enable real firewall rules. Change `weights` to tune detection sensitivity.
- **Sensible defaults**: the config includes safe defaults (dry_run=true, whitelist includes common private ranges).

**Why it matters**: Hard-coding values in source code makes the system rigid. A config file lets you tune the system for different environments without changing code.

**Estimated time**: 5 minutes

---

## Phase 11: Testing & Polish

### Step 29: Write Detection Tests

**Task**: Create `tests/test_detection.py` with tests for signals and the composite scorer.

```python
"""Tests for detection signals and composite scoring — no network required."""
import pytest
from datetime import datetime, timedelta
from ddosguard.detect.signals import (
    volume_signal, protocol_signal, source_signal, port_signal, syn_signal,
    run_all_signals,
)
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import (
    PacketRecord, Protocol, Severity, SignalResult, TrafficStats, TrafficWindow,
)


def make_stats(packet_rate: float, byte_rate: float,
               syn_ratio: float = 0.0, per_proto: dict = None,
               window_start: datetime = None) -> TrafficStats:
    """Create fake TrafficStats with controlled values."""
    now = window_start or datetime.now()
    window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    window.packet_count = int(packet_rate * 10)
    window.byte_count = int(byte_rate * 10)
    window.syn_count = int(syn_ratio * window.packet_count)
    window.protocol_counts = {Protocol.TCP: int(packet_rate * 10 * 0.7),
                               Protocol.UDP: int(packet_rate * 10 * 0.3)}
    return TrafficStats(
        window=window,
        per_proto=per_proto or {6: int(packet_rate * 10 * 0.7), 17: int(packet_rate * 10 * 0.3)},
        syn_ratio=syn_ratio,
        byte_rate=byte_rate,
    )


class TestVolumeSignal:
    """Tests for the volume/anomaly detection signal."""

    def test_normal_traffic_low_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        # Train baseline with similar traffic
        ts = datetime.now()
        for i in range(10):
            stats = make_stats(50.0, 25000.0, 0.1)
            baseline.observe(stats, ts)

        stats = make_stats(55.0, 27500.0, 0.1)
        result = volume_signal(stats, baseline)
        assert result.score < 0.5  # Normal variation should score low

    def test_high_traffic_high_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        ts = datetime.now()
        for i in range(10):
            baseline.observe(make_stats(50.0, 25000.0, 0.1), ts)

        stats = make_stats(500.0, 250000.0, 0.1)  # 10x normal
        result = volume_signal(stats, baseline)
        assert result.score > 0.5  # Should be flagged

    def test_detail_contains_baseline_values(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        ts = datetime.now()
        baseline.observe(make_stats(100.0, 50000.0, 0.1), ts)

        stats = make_stats(200.0, 100000.0, 0.1)
        result = volume_signal(stats, baseline)
        assert "baseline_mean_packet_rate" in result.detail
        assert "current_packet_rate" in result.detail


class TestSynSignal:
    """Tests for the SYN flood detection signal."""

    def test_low_syn_ratio_low_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        stats = make_stats(100.0, 50000.0, syn_ratio=0.1)
        result = syn_signal(stats, baseline)
        assert result.score < 0.3

    def test_high_syn_ratio_high_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        stats = make_stats(100.0, 50000.0, syn_ratio=0.9)
        result = syn_signal(stats, baseline)
        assert result.score > 0.5

    def test_syn_ratio_in_detail(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        stats = make_stats(100.0, 50000.0, syn_ratio=0.5)
        result = syn_signal(stats, baseline)
        assert "syn_ratio" in result.detail


class TestPortSignal:
    """Tests for the port-targeting signal."""

    def test_distributed_ports_low_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        window = TrafficWindow(start=datetime.now() - timedelta(seconds=10),
                               end=datetime.now())
        for port in [80, 443, 22, 53, 8080, 3306]:
            window.dst_ports[port] = 10
        stats = window.finalize()
        result = port_signal(stats, baseline)
        assert result.score < 0.3

    def test_concentrated_port_high_score(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        window = TrafficWindow(start=datetime.now() - timedelta(seconds=10),
                               end=datetime.now())
        window.dst_ports[80] = 100  # 100 packets to port 80
        window.dst_ports[443] = 5   # 5 packets to port 443
        stats = window.finalize()
        result = port_signal(stats, baseline)
        assert result.score > 0.3


class TestCompositeScorer:
    """Tests for the composite scorer."""

    def test_normal_traffic_low_total(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        scorer = CompositeScorer(config)

        # Train
        ts = datetime.now()
        for i in range(20):
            baseline.observe(make_stats(50.0, 25000.0, 0.1), ts)

        stats = make_stats(55.0, 27500.0, 0.1)
        score = scorer.score(stats, baseline)
        assert score.total < 0.30
        assert score.classification == "none"

    def test_attack_traffic_high_total(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        scorer = CompositeScorer(config)
        ts = datetime.now()
        for i in range(20):
            baseline.observe(make_stats(50.0, 25000.0, 0.1), ts)

        stats = make_stats(500.0, 250000.0, syn_ratio=0.8)
        score = scorer.score(stats, baseline)
        assert score.total > 0.50
        assert score.severity.value >= Severity.MEDIUM.value

    def test_severity_mapping(self):
        config = Config.load(None)
        scorer = CompositeScorer(config)
        # The _severity_from_score function maps scores to severity
        from ddosguard.detect.signals import _severity_from_score
        assert _severity_from_score(0.20) == Severity.INFO
        assert _severity_from_score(0.40) == Severity.LOW
        assert _severity_from_score(0.60) == Severity.MEDIUM
        assert _severity_from_score(0.80) == Severity.HIGH
        assert _severity_from_score(0.90) == Severity.CRITICAL

    def test_classification_volumetric(self):
        config = Config.load(None)
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        scorer = CompositeScorer(config)
        ts = datetime.now()
        for i in range(20):
            baseline.observe(make_stats(50.0, 25000.0, 0.1), ts)

        stats = make_stats(500.0, 250000.0, syn_ratio=0.1)
        score = scorer.score(stats, baseline)
        assert score.classification in ("volumetric", "mixed", "unknown")

    def test_weights_used(self):
        config = Config.load(None)
        scorer = CompositeScorer(config)
        assert "volume" in scorer.weights
        assert "syn" in scorer.weights
        assert sum(scorer.weights.values()) == pytest.approx(1.0)
```

Run:
```bash
python -m pytest tests/test_detection.py -v
```

**What you'll learn**:
- **Testing with controlled inputs**: creating fake `TrafficStats` with specific packet rates, byte rates, and SYN ratios to test signal responses
- **Training the baseline in tests**: observing normal traffic into the baseline before testing detection, so signals have a reference to compare against
- **Testing severity boundaries**: verifying that score thresholds map to the correct severity levels
- **Testing classification**: verifying that different attack patterns produce different classifications

**Why it matters**: Detection is the core of the system. Tests ensure signals respond correctly to different traffic patterns and that the scorer combines them properly.

**Verify**: All tests pass.

**Estimated time**: 25 minutes

---

### Step 30: Write Alert & Firewall Tests

**Task**: Create `tests/test_alert.py` and `tests/test_firewall.py`.

`tests/test_alert.py`:
```python
"""Tests for alerting — no network required."""
import json
import os
import pytest
import tempfile
from datetime import datetime
from ddosguard.alert.manager import AlertManager
from ddosguard.alert.director import AlertDirector
from ddosguard.core import Alert, CompositeScore, Severity, TrafficStats, TrafficWindow
from ddosguard.config import Config


def make_score(total: float, classification: str = "volumetric",
               severity: Severity = Severity.HIGH) -> CompositeScore:
    """Create a fake CompositeScore."""
    return CompositeScore(
        signal_names=["volume"],
        signal_scores={"volume": total},
        total=total,
        severity=severity,
        classification=classification,
    )


def make_stats(packet_rate: float = 100.0, byte_rate: float = 50000.0) -> TrafficStats:
    """Create fake TrafficStats."""
    now = datetime.now()
    window = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    window.packet_count = int(packet_rate * 10)
    window.byte_count = int(byte_rate * 10)
    return TrafficStats(window=window, per_proto={6: 70, 17: 30},
                        syn_ratio=0.1, byte_rate=byte_rate)


class TestAlertManager:
    """Tests for AlertManager generation and deduplication."""

    def test_alert_generated_above_threshold(self):
        config = Config.load(None)
        manager = AlertManager(config)
        score = make_score(0.60, "volumetric", Severity.HIGH)
        stats = make_stats(500.0, 250000.0)

        alert = manager.generate(score, stats)
        assert alert is not None
        assert alert.severity == Severity.HIGH
        assert "Volumetric" in alert.title

    def test_no_alert_below_threshold(self):
        config = Config.load(None)
        manager = AlertManager(config)
        score = make_score(0.20, "none", Severity.INFO)
        stats = make_stats(50.0, 25000.0)

        alert = manager.generate(score, stats)
        assert alert is None  # Below threshold

    def test_dedup_suppresses_duplicates(self):
        config = Config.load(None)
        manager = AlertManager(config)
        score = make_score(0.60, "volumetric", Severity.HIGH)
        stats = make_stats(500.0, 250000.0)

        alert1 = manager.generate(score, stats)
        assert alert1 is not None

        alert2 = manager.generate(score, stats)
        assert alert2 is None  # Duplicate — suppressed by cooldown

    def test_console_notification(self, capsys):
        config = Config.load(None)
        manager = AlertManager(config)
        score = make_score(0.60, "volumetric", Severity.HIGH)
        stats = make_stats(500.0, 250000.0)
        alert = manager.generate(score, stats)
        manager.deliver(alert)
        captured = capsys.readouterr()
        assert "ALERT" in captured.out
        assert "Volumetric" in captured.out

    def test_file_notification(self):
        config = Config.load(None)
        tmpdir = tempfile.mkdtemp()
        config_data = {
            "alerting": {
                "notifiers": {
                    "console": False,
                    "file": True,
                    "file_path": os.path.join(tmpdir, "alerts.jsonl"),
                }
            }
        }
        # Create a config-like object
        class FakeConfig:
            def __init__(self, data):
                self._data = data
            def __getattr__(self, name):
                return self._data.get(name, {})
            def get(self, key, default=None):
                parts = key.split(".")
                value = self._data
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return default
                return value if value is not None else default

        cfg = FakeConfig(config_data)
        manager = AlertManager(cfg)
        score = make_score(0.60, "volumetric", Severity.HIGH)
        stats = make_stats(500.0, 250000.0)
        alert = manager.generate(score, stats)
        manager.deliver(alert)

        path = config_data["alerting"]["notifiers"]["file_path"]
        assert os.path.exists(path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["severity"] == "HIGH"

    def test_rate_limiting(self):
        config_data = {
            "alerting": {
                "max_per_minute": 2,
                "cooldown": 1,
            }
        }
        class FakeConfig:
            def __init__(self, data):
                self._data = data
            def get(self, key, default=None):
                parts = key.split(".")
                value = self._data
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return default
                return value if value is not None else default

        cfg = FakeConfig(config_data)
        manager = AlertManager(cfg)
        score = make_score(0.60, "volumetric", Severity.HIGH)

        alerts = []
        for i in range(5):
            stats = make_stats(500.0 + i, 250000.0 + i * 1000)
            alert = manager.generate(score, stats)
            if alert:
                alerts.append(alert)

        assert len(alerts) <= 2  # Rate limited to max_per_minute


class TestAlertDirector:
    """Tests for AlertDirector ranking and prioritization."""

    def test_add_and_get_urgent(self):
        director = AlertDirector()
        alert = Alert(
            alert_id="test-1",
            severity=Severity.CRITICAL,
            title="Critical attack",
            summary="Test summary",
        )
        director.add_alert(alert)
        urgent = director.get_urgent()
        assert len(urgent) == 1
        assert urgent[0].severity == Severity.CRITICAL

    def test_get_timeline_sorted(self):
        director = AlertDirector()
        for sev in [Severity.INFO, Severity.CRITICAL, Severity.LOW, Severity.HIGH]:
            alert = Alert(
                alert_id=f"test-{sev.name}",
                severity=sev,
                title=f"{sev.name} alert",
                summary="Test",
            )
            director.add_alert(alert)
        timeline = director.get_timeline(10)
        assert len(timeline) == 4
        assert timeline[0].severity == Severity.CRITICAL
        assert timeline[-1].severity == Severity.INFO

    def test_get_summary(self):
        director = AlertDirector()
        director.add_alert(Alert(alert_id="1", severity=Severity.CRITICAL, title="X", summary="X"))
        director.add_alert(Alert(alert_id="2", severity=Severity.CRITICAL, title="Y", summary="Y"))
        director.add_alert(Alert(alert_id="3", severity=Severity.LOW, title="Z", summary="Z"))
        summary = director.get_summary()
        assert summary["CRITICAL"] == 2
        assert summary["LOW"] == 1
        assert summary["INFO"] == 0

    def test_clear(self):
        director = AlertDirector()
        director.add_alert(Alert(alert_id="1", severity=Severity.CRITICAL, title="X", summary="X"))
        director.clear()
        assert len(director.get_timeline(10)) == 0
```

`tests/test_firewall.py`:
```python
"""Tests for firewall rule generation — no network required."""
import pytest
from ddosguard.mitigate.firewall import FirewallManager


class TestFirewallManager:
    """Tests for firewall rule generation."""

    def test_stage_zero_no_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=0, severity="INFO")
        assert len(rules) == 0

    def test_stage_one_has_rate_limit_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=1, severity="LOW")
        assert len(rules) >= 1
        rule_text = "\n".join(rules)
        assert "limit" in rule_text.lower() or "ACCEPT" in rule_text

    def test_stage_four_has_drop_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=4, severity="CRITICAL")
        rule_text = "\n".join(rules)
        assert "DROP" in rule_text

    def test_whitelist_included(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=2, severity="HIGH", whitelist=["192.168.1.1"])
        rule_text = "\n".join(rules)
        assert "192.168.1.1" in rule_text
        # Whitelist rule should come before DROP rules
        whitelist_idx = rule_text.find("192.168.1.1")
        drop_idx = rule_text.find("DROP")
        assert whitelist_idx < drop_idx

    def test_comment_metadata_present(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=2, severity="HIGH")
        rule_text = "\n".join(rules)
        assert "ddosguard" in rule_text
        assert "stage=2" in rule_text

    def test_dry_run_does_not_execute(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=1, severity="LOW")
        result = fw.apply(rules)
        assert result is True
        # Should print DRY RUN message, not execute iptables

    def test_active_rules_tracked(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=1, severity="LOW")
        fw.apply(rules)
        assert len(fw.active_rules) == len(rules)

    def test_clear_in_dry_run(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=1, severity="LOW")
        fw.apply(rules)
        assert len(fw.active_rules) > 0
        fw.clear()
        assert len(fw.active_rules) == 0

    def test_multiple_stages_combined(self):
        fw = FirewallManager(dry_run=True)
        # Stage 3 should include stage 1 and 2 rules plus stage 3 rules
        rules = fw.generate_rules(stage=3, severity="HIGH")
        rule_text = "\n".join(rules)
        assert "limit" in rule_text.lower()
        assert "ddosguard" in rule_text
```

Run both:
```bash
python -m pytest tests/test_alert.py tests/test_firewall.py -v
```

**What you'll learn**:
- **Testing dedup**: generating the same alert twice and verifying the second is suppressed
- **Testing rate limiting**: generating many alerts quickly and verifying the per-minute cap is enforced
- **Testing with fake config objects**: when the real `Config` class doesn't expose the nested structure you need, create a fake that does
- **Testing rule content**: asserting that generated rules contain expected strings ("DROP", "limit", IP addresses, comments) without executing them
- **Testing execution safety**: verifying dry_run mode doesn't actually run iptables commands

**Why it matters**: Alerting and firewall code are security-sensitive. Tests verify that alerts are properly deduplicated (no storms), rate-limited (no floods), and that firewall rules are generated correctly before they're ever applied.

**Verify**: All tests pass.

**Estimated time**: 30 minutes

---

### Step 31: Run All Tests and Verify Everything

**Task**: Run the full test suite and verify the entire system works end-to-end.

```bash
# Run all tests
python -m pytest tests/ -v

# Verify CLI
python -m ddosguard --help

# Verify all modules import
python -c "
from ddosguard.core import *
from ddosguard.config import Config
from ddosguard.capture.base import SyntheticGenerator
from ddosguard.metrics.window import WindowAggregator, RollingAggregator
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.signals import run_all_signals
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter
from ddosguard.mitigate.firewall import FirewallManager
from ddosguard.mitigate.policy import MitigationPolicy
from ddosguard.alert.manager import AlertManager
from ddosguard.alert.director import AlertDirector
from ddosguard.monitor import MonitorState, MonitorRunner, WhitelistStore
from ddosguard.dashboard.app import app
print('All imports OK')
"
```

Expected:
- All 19 tests pass
- CLI help shows all 6 subcommands
- All imports resolve without errors

**What you'll learn**:
- **Integration verification**: running the full test suite confirms all pieces work together
- **Import hygiene**: verifying all public APIs are importable from the package level

**Why it matters**: This is the final check before considering the project complete. If anything fails here, you know exactly what to fix.

**Estimated time**: 10 minutes

---

## Roadmap Summary

| Phase | Steps | What You Build | Time |
|-------|-------|----------------|------|
| **Foundations** | 1–3 | Project structure, dependencies, git | 45 min |
| **Data Models & Traffic** | 4–6 | Core dataclasses, packet understanding, synthetic generator | 1 hr 20 min |
| **Windowing & Metrics** | 7–9 | Window aggregator, rolling window, metrics tests | 1 hr 10 min |
| **Baseline System** | 10–12 | Baseline concepts, baseline store, baseline tests | 1 hr 20 min |
| **Anomaly Detection** | 13–15 | Signal concepts, 5 signals, composite scorer | 1 hr 5 min |
| **Rate Limiting & Mitigation** | 16–18 | Token bucket concepts, TokenBucket + RateLimiter, rate limiter tests | 1 hr 20 min |
| **Firewall Rules** | 19 | FirewallManager with iptables-style rule generation | 25 min |
| **Alerting & Escalation** | 20–22 | Alert concepts, AlertManager, AlertDirector | 1 hr 5 min |
| **Dashboard & Controls** | 23–25 | FastAPI dashboard, HTML/JS UI, MonitorRunner wiring | 1 hr 35 min |
| **CLI & Packaging** | 26–28 | CLI with subcommands, `__main__.py`, config file | 35 min |
| **Testing & Polish** | 29–31 | Detection tests, alert/firewall tests, full suite run | 40 min |
| **TOTAL** | | | **~13 hours** |

---

## What You'll Know After Completing This

### Python skills
- Building a multi-module package with proper `__init__.py` exports
- Dataclasses, enums, properties, type hints, default factories
- ABCs (abstract base classes) for defining interfaces
- Generators (`yield`) for streaming data
- `collections.deque` for ring buffers
- `argparse` for CLI construction
- `threading` with `Event` and `Lock` for concurrent programming
- `logging` for operational messages
- JSON persistence (save/load) and JSONL for log storage
- Pydantic `BaseModel` for request validation in FastAPI

### Networking & security concepts
- IP packet structure (source/dest IP, protocol, ports, flags, payload)
- TCP flags (SYN, ACK, RST, FIN, PSH, URG) and the TCP handshake
- The three DDoS attack types: volumetric, protocol, application layer
- Diurnal traffic patterns and why time-of-day matters for baselines
- Statistical thresholds: mean, standard deviation, z-scores, percentiles
- Token bucket rate limiting algorithm (rate, burst, analytical refill)
- iptables rule structure (chains, conditions, actions, comments)
- Alert deduplication, cooldown, and rate limiting
- Multi-channel alerting (console, file, desktop, Slack, email)

### Software engineering practices
- Test-driven understanding: writing tests that define expected behavior
- Unit tests with no external dependencies (no network, no permissions)
- pytest: test discovery, assertions, fixtures, approximate comparisons
- Dry-run patterns for safety-critical code (firewall rules)
- Configuration-driven behavior (YAML config instead of hard-coded values)
- Version control workflow (git init, add, commit, push)
- Project structure conventions (where to put what)
- Separation of concerns (detection vs mitigation vs alerting vs dashboard)

### Tooling
- Scapy for packet creation and inspection
- FastAPI for building web APIs
- uvicorn for serving ASGI applications
- PyYAML for configuration files
- pytest for automated testing

---

*This guide is designed to be followed step by step. Each step builds on the previous ones. If you get stuck, focus on understanding the "What you'll learn" section — that's the knowledge that transfers to future projects. The code is secondary; the concepts are primary.*
