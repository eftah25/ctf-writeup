# Learning Path: Build DDoS Detection & Mitigation From Scratch

**A complete beginner-to-advanced guide that teaches you BY DOING.**

> This guide doesn't just tell you what to build. It teaches you the concepts **before** showing code, then makes you write code yourself, then makes you break it and fix it so you actually understand it.
>
> Each step has three parts:
> - **Learn** — the concept explained in plain language, with WORKED EXAMPLES that show the actual thinking (read this first)
> - **Build** — write the code yourself (don't copy-paste blindly)
> - **Practice** — break it, fix it, extend it (this is where learning happens)
>
> Follow steps in order. Do not skip. Each step builds on the previous.

---

## Table of Contents

1. [Before You Start — What You Need](#before-you-start)
2. [Phase 1: Foundations (Steps 1–3)](#phase-1-foundations) — Project setup, dependencies, git
3. [Phase 2: Data Models & Traffic (Steps 4–6)](#phase-2-data-models--traffic) — dataclasses, packets, synthetic generator
4. [Phase 3: Windowing & Metrics (Steps 7–9)](#phase-3-windowing--metrics) — time windows, aggregation, tests
5. [Phase 4: Baseline System (Steps 10–12)](#phase-4-baseline-system) — statistical baselines, diurnal patterns, persistence
6. [Phase 5: Anomaly Detection (Steps 13–15)](#phase-5-anomaly-detection) — signals, z-scores, composite scoring
7. [Phase 6: Rate Limiting & Mitigation (Steps 16–18)](#phase-6-rate-limiting--mitigation) — token buckets, per-key limiting, tests
8. [Phase 7: Firewall Rules (Step 19)](#phase-7-firewall-rules) — iptables-style rule generation
9. [Phase 8: Alerting & Escalation (Steps 20–22)](#phase-8-alerting--escalation) — dedup, cooldown, multi-channel
10. [Phase 9: Dashboard & Controls (Steps 23–25)](#phase-9-dashboard--controls) — FastAPI, HTML/JS, threading
11. [Phase 10: CLI & Packaging (Steps 26–28)](#phase-10-cli--packaging) — argparse, `__main__.py`, config
12. [Phase 11: Testing & Polish (Steps 29–31)](#phase-11-testing--polish) — detection tests, alert/firewall tests, full suite
13. [Roadmap Summary](#roadmap-summary)
14. [What You'll Know After Completing This](#what-youll-know-after)

---

## Before You Start

### What you need

| Item | Check |
|------|-------|
| Python 3.14+ installed | Run `python --version` |
| pip available | Run `pip --version` |
| A code editor | VS Code, PyCharm, or any text editor |
| Git installed | Run `git --version` |
| Basic Python: variables, functions, classes, imports | You can write `def foo(): return 1` and `class Foo: pass` |
| Terminal comfort | You can `cd`, `ls`, run commands |

### How to use this guide

1. **Read the "Learn" section first.** Don't skip to the code. The concepts are what you're here for.
2. **Write the code yourself.** Type it out. Don't copy-paste. The act of typing makes you notice details.
3. **Do the Practice exercises.** Breaking and fixing your own code is where real learning happens.
4. **Move to the next step only when the current one works.**

### Time estimate

- Complete beginner: **40–60 hours** (1–2 weeks part-time)
- Python experience: **15–25 hours**

---

## Phase 1: Foundations

### Step 1: Set Up the Project Structure

#### Learn

Every Python project needs a standard structure so tools can find it. Here's what you need:

```
ddosguard/
├── __init__.py       ← Makes this folder a Python "package"
├── pyproject.toml    ← Project metadata (name, version, dependencies)
└── requirements.txt  ← List of pip packages to install
```

- **`__init__.py`** can be empty. Its presence tells Python "this folder is a package — you can import from it."
- **`pyproject.toml`** replaces the old `setup.py`. It tells build tools how to install your package.
- **`requirements.txt`** lists the pip packages your project needs, one per line.

**Why this matters**: Without this structure, you can't `pip install` your project, other tools don't know what it is, and you can't share it.

#### Build

Create these files:

**`ddosguard/__init__.py`** — empty file (just create it)

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

**`requirements.txt`** — empty for now (we'll fill it in Step 2):
```
# Add dependencies here as we install them
```

#### Practice

1. Create the folder `ddosguard/` and the three files above
2. Open a terminal in the parent folder and run:
   ```bash
   python -c "import ddosguard; print(ddosguard.__file__)"
   ```
3. **Break it**: Delete `__init__.py` and run the same command. See the error. Put it back.

**Verify**: The import command prints a path ending in `ddosguard/__init__.py`.

**Time**: 15 minutes

---

### Step 2: Install Dependencies

#### Learn

Python has a giant ecosystem of libraries. You install them with `pip`. Here's what this project needs:

| Library | What it does |
|---------|-------------|
| **scapy** | Create and inspect network packets |
| **fastapi** | Build web APIs (the dashboard backend) |
| **uvicorn** | Run FastAPI servers (the ASGI server that actually listens on a port) |
| **pyyaml** | Read/write YAML files (our config format) |
| **pytest** | Run unit tests |

**Why these?** Each solves one specific problem. You could write everything from scratch, but that's not what professional software does — you use the right tool for each job.

**Version pinning**: `>=2.5.0` means "at least version 2.5.0, but any newer version works." We don't pin exact versions because that makes upgrades painful.

#### Build

Install everything:
```bash
pip install scapy>=2.5.0 fastapi>=0.110.0 "uvicorn[standard]>=0.30.0" pyyaml>=6.0.2 pytest>=8.0.0
```

Update `requirements.txt`:
```
scapy>=2.5.0
fastapi>=0.110.0
uvicorn[standard]>=0.30.0
pyyaml>=6.0.2
pytest>=8.0.0
```

#### Practice

1. Install the packages (above)
2. Verify each one imports:
   ```bash
   python -c "import scapy; print('scapy', scapy.__version__)"
   python -c "import fastapi; print('fastapi', fastapi.__version__)"
   python -c "import yaml; print('pyyaml OK')"
   python -c "import pytest; print('pytest', pytest.__version__)"
   ```
3. **Break it**: Uninstall one package (`pip uninstall scapy`) and try importing it. See the error. Reinstall it.

**Verify**: All four `import` commands succeed without errors.

**Time**: 10 minutes (+ download time)

---

### Step 3: Version Control with Git

#### Learn

**Git** tracks changes to your files. You've probably saved versions of a file as `file.py`, `file_v2.py`, `file_final.py`, `file_REAL_final.py`. Git replaces that mess with a proper history.

The basic workflow:
```
Working files  →  git add  →  Staging area  →  git commit  →  Permanent history
```

- `git add` says "I want to include these changes in the next save"
- `git commit` saves the staged changes with a message

**`.gitignore`** tells git what to ignore (cache files, virtual environments, secrets). Without it, your repo fills up with junk.

#### Build

```bash
git init
git config user.name "Your Name"
git config user.email "you@example.com"
```

Create `.gitignore`:
```
# Python
__pycache__/
*.py[cod]
*.egg-info/
.eggs/

# Virtual environments
venv/
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

#### Practice

1. Run the git setup above
2. Check your history: `git log --oneline`
3. **Break it**: Make a change to `pyproject.toml`, then run `git status`. See the uncommitted change. Commit it.
4. **Practice**: Create a junk file `junk.txt`, add it, commit it. Then `git rm junk.txt` and commit. Watch it disappear from history.

**Verify**: `git log --oneline` shows at least one commit.

**Time**: 10 minutes

---

## Phase 2: Data Models & Traffic

### Step 4: Learn About Data Classes

#### Learn

Python has **dataclasses** — a way to write classes that mostly hold data. Before dataclasses, you'd write:

```python
class Packet:
    def __init__(self, ts, src_ip, dst_ip, protocol):
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
```

With dataclasses:

```python
from dataclasses import dataclass

@dataclass
class Packet:
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: int
```

The `@dataclass` decorator auto-generates `__init__`, `__repr__`, and comparison methods. You write less code and get more behavior.

**Key concepts**:
- **Type hints** (`: str`, `: int`): tell readers (and tools) what type each field is
- **Default values**: `flags: str = ""` gives a field a default
- **`field(default_factory=dict)`**: for mutable defaults (you can't use `dict` directly as a default — Python would share one dict across all instances)
- **`@property`**: methods that look like attributes. `pkt.is_tcp` calls a method but reads like data.

**Enums** (`IntEnum`): named integer constants. `Protocol.TCP` is `6`. You can use it in comparisons and it prints nicely.

#### Build

Create `ddosguard/core.py`. This will be the data layer for the entire project.

First, write just the `PacketRecord` and `Protocol` — don't write everything at once:

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

class Protocol(IntEnum):
    OTHER = 0
    TCP = 6
    UDP = 17
    ICMP = 1

@dataclass
class PacketRecord:
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: Protocol = Protocol.OTHER
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ""

    @property
    def is_tcp(self) -> bool:
        return self.protocol == Protocol.TCP

    @property
    def is_syn(self) -> bool:
        return "S" in self.flags
```

#### Practice

1. Write the code above in `ddosguard/core.py`
2. Test it:
   ```bash
   python -c "
   from ddosguard.core import PacketRecord, Protocol
   from datetime import datetime
   pkt = PacketRecord(ts=datetime.now(), src_ip='10.0.0.1', dst_ip='10.0.0.2',
                      protocol=Protocol.TCP, flags='S')
   print(pkt)
   print('is_tcp:', pkt.is_tcp)
   print('is_syn:', pkt.is_syn)
   "
   ```
3. **Extend it**: Add `is_udp`, `is_rst` properties yourself (look at `is_tcp` and `is_syn` for the pattern)
4. **Break it**: Try `PacketRecord(ts="not a date", ...)` and see what happens. Then fix it by passing a real `datetime`.

**Verify**: The test prints the packet and shows `is_tcp: True`, `is_syn: True`.

**Time**: 30 minutes

---

### Step 5: Understand Network Packets

#### Learn

A **network packet** is a chunk of data sent over a network. It has:

```
[ Ethernet header ] [ IP header ] [ Protocol header ] [ Payload ]
```

- **IP header**: source IP, destination IP, protocol number (6=TCP, 17=UDP, 1=ICMP)
- **TCP header**: source port, destination port, flags (SYN, ACK, RST, etc.)
- **Payload**: the actual data being sent

**TCP flags** (the important ones for DDoS):
- **S (SYN)**: "I want to start a connection" — first step of TCP handshake
- **A (ACK)**: "I acknowledge your data"
- **R (RST)**: "Reset this connection NOW" — used in attacks to kill connections
- **FA (FIN+ACK)**: "I'm done, close the connection"

**Three DDoS attack types**:
1. **Volumetric** (UDP flood): send massive amounts of data to saturate bandwidth
2. **Protocol** (SYN flood): send many SYN packets but never complete the handshake → server wastes resources on half-open connections
3. **Application layer** (HTTP flood): send many requests to a specific service → exhausts the application

#### Build

Write an exploration script `explore_packets.py` that uses Scapy to create and inspect packets:

```python
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, RandIP, RandShort, sniff, conf

conf.verb = 0  # Disable Scapy's verbose output

def describe(pkt):
    if not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, str(ip.proto))
    print(f"  {ip.src} -> {ip.dst}  proto={proto}")

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = ""
        if tcp.flags.S: flags += "S"
        if tcp.flags.A: flags += "A"
        if tcp.flags.R: flags += "R"
        if tcp.flags.F: flags += "F"
        print(f"    TCP: sport={tcp.sport} dport={tcp.dport} flags='{flags}'")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        print(f"    UDP: sport={udp.sport} dport={udp.dport}")

# Create packets
print("1. Normal TCP SYN:")
pkt = Ether()/IP(src="192.168.1.1", dst="93.184.216.34")/TCP(sport=12345, dport=80, flags="S")
describe(pkt)

print("\n2. UDP packet:")
pkt = Ether()/IP(src="192.168.1.1", dst="8.8.8.8")/UDP(sport=54321, dport=53)/Raw(load=b"test")
describe(pkt)

print("\n3. SYN flood packet:")
pkt = Ether()/IP(src=RandIP(), dst="93.184.216.34")/TCP(sport=RandShort(), dport=80, flags="S")
describe(pkt)

print("\nProtocol numbers: ICMP=1, TCP=6, UDP=17")
print("\nTCP flags: S=SYN, A=ACK, R=RST, F=FIN, P=PSH")
```

#### Practice

1. Write the script and run it: `python explore_packets.py`
2. **Experiment**: Create a packet with flags="SA" (SYN-ACK). Describe it. What's the difference from "S"?
3. **Experiment**: Create a packet with flags="R" (RST). Describe it.
4. **Try live capture** (may fail without Npcap): `sniff(timeout=2, prn=describe)` — this captures real packets from your network for 2 seconds.

**Verify**: The script prints three packet descriptions with correct IPs, ports, and flags.

**Time**: 20 minutes

---

### Step 6: Build the Synthetic Packet Generator

#### Learn

You need packets to test your detection system. Real pcap files are hard to get. So you build a **synthetic generator** — a class that creates fake packets that look real enough.

Key concepts:
- **ABC (Abstract Base Class)**: An ABC defines an interface. `PacketSource` says "any packet source must have `iter_packets()` and `name`." This lets you swap sources without changing the code that uses them.
- **Generators (`yield`)**: Instead of returning a list of 10,000 packets (which uses memory), a generator yields one packet at a time. The caller processes each packet and moves on.
- **Diurnal patterns**: Real networks have busy hours and quiet hours. Your generator should reflect this — more packets during "day", fewer at "night".
- **Attack families**: Three types of attacks, three different packet patterns.

#### Build

Create `ddosguard/capture/base.py`:

```python
from __future__ import annotations
import random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Iterator, Optional
from ddosguard.core import PacketRecord, Protocol

class PacketSource(ABC):
    @abstractmethod
    def iter_packets(self, window_seconds: float, delay: float = 0.0) -> Iterator[PacketRecord]:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

class SyntheticGenerator(PacketSource):
    def __init__(self, mode="normal", attack_family="volumetric",
                 attack_start=None, attack_duration=30.0, attack_mult=20.0,
                 base_rate=50.0, src_ip_base="192.168.1", dst_ip="10.0.0.1"):
        self.mode = mode
        self.attack_family = attack_family
        self.attack_start = attack_start or datetime.now()
        self.attack_end = self.attack_start + timedelta(seconds=attack_duration)
        self.attack_mult = attack_mult
        self.base_rate = base_rate
        self.src_ip_base = src_ip_base
        self.dst_ip = dst_ip

    @property
    def name(self) -> str:
        return f"synthetic-{self.mode}"

    def iter_packets(self, window_seconds, delay=0.0):
        now = datetime.now()
        if self.mode == "attack" and self.attack_start <= now < self.attack_end:
            yield from self._attack(window_seconds, now)
        else:
            yield from self._normal(window_seconds, now)

    def _normal(self, window_seconds, now):
        hour = now.hour + now.minute / 60.0
        mult = 1.5 if 8 <= hour < 20 else (1.0 if 6 <= hour < 8 or 20 <= hour < 22 else 0.4)
        target = int(self.base_rate * mult * window_seconds)
        ports = [80, 443, 22, 53, 8080, 3306, 5432]
        protos = [Protocol.TCP]*70 + [Protocol.UDP]*25 + [Protocol.ICMP]*5
        for _ in range(target):
            ts = now - timedelta(seconds=random.uniform(0, window_seconds))
            yield PacketRecord(
                ts=ts,
                src_ip=f"{self.src_ip_base}.{random.randint(1,254)}",
                dst_ip=self.dst_ip,
                protocol=random.choice(protos),
                src_port=random.randint(1024, 65535),
                dst_port=random.choice(ports),
                length=random.randint(40, 1500),
                flags=random.choice(["S","SA","PA","A","F","R"]) if random.choice(protos)==Protocol.TCP else "",
            )

    def _attack(self, window_seconds, now):
        target = int(self.base_rate * self.attack_mult * window_seconds)
        if self.attack_family == "volumetric":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0,1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1,254)}",
                    dst_ip=self.dst_ip, protocol=Protocol.UDP,
                    src_port=random.randint(1024,65535),
                    dst_port=random.randint(1,65535),
                    length=random.randint(512,1500), flags="",
                )
        elif self.attack_family == "syn_flood":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0,1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1,254)}",
                    dst_ip=self.dst_ip, protocol=Protocol.TCP,
                    src_port=random.randint(1024,65535), dst_port=80,
                    length=64, flags="S",
                )
        elif self.attack_family == "application":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0,1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1,254)}",
                    dst_ip=self.dst_ip, protocol=Protocol.TCP,
                    src_port=random.randint(1024,65535), dst_port=8080,
                    length=random.randint(200,500), flags="PA",
                )
```

#### Practice

1. Write the code above in `ddosguard/capture/base.py`
2. Test normal mode:
   ```bash
   python -c "
   from ddosguard.capture.base import SyntheticGenerator
   from datetime import datetime
   gen = SyntheticGenerator(mode='normal', base_rate=100)
   pkts = list(gen.iter_packets(1.0))
   print(f'{len(pkts)} packets in 1 second')
   print(f'Sample: {pkts[0].src_ip} -> {pkts[0].dst_ip} proto={pkts[0].protocol.name}')
   "
   ```
3. Test attack mode:
   ```bash
   python -c "
   from ddosguard.capture.base import SyntheticGenerator
   from datetime import datetime
   gen = SyntheticGenerator(mode='attack', attack_family='syn_flood',
                            attack_start=datetime.now(), attack_duration=10, attack_mult=50)
   pkts = list(gen.iter_packets(1.0))
   syn = sum(1 for p in pkts if p.is_syn)
   print(f'{len(pkts)} attack packets, {syn} are SYN')
   "
   ```
4. **Extend**: Add a `icmp_flood` attack family that generates ICMP packets. Test it.

**Verify**: Normal mode generates ~100 packets/sec. Attack mode generates many SYN packets.

**Time**: 30 minutes

---

## Phase 3: Windowing & Metrics

### Step 7: Learn About Time Windows

#### Learn

You can't detect a DDoS from a single packet. A SYN packet is normal. A million SYN packets in 10 seconds is an attack.

**Time windows** solve this: you collect packets for a fixed duration (say 10 seconds), then compute statistics for that window.

```
Packet 1 ─┐
Packet 2 ─┤  →  Window 1 (10 sec)  →  Statistics  →  Detection
Packet 3 ─┤
...       ─┘
```

The **finalize pattern**:
1. Accumulate packets into a window (call `add()` for each packet)
2. When the window is "full" (time elapsed exceeds window size), call `finalize()`
3. `finalize()` returns a `TrafficStats` snapshot and resets for the next window

This separation — **collection** vs **analysis** — makes both easier to test. You can test collection separately from analysis.

#### Build

Create `ddosguard/metrics/window.py`:

```python
from __future__ import annotations
from datetime import datetime
from typing import Optional
from ddosguard.core import PacketRecord, TrafficStats, TrafficWindow

class WindowAggregator:
    def __init__(self, window_seconds=10.0):
        self.window_seconds = window_seconds
        self._window = None
        self._first_ts = None

    def add(self, pkt):
        if self._window is None:
            self._window = TrafficWindow(start=pkt.ts, end=pkt.ts)
            self._first_ts = pkt.ts
        self._window.add(pkt)
        self._window.end = pkt.ts

    def is_complete(self, pkt_ts):
        if self._window is None or self._first_ts is None:
            return False
        return (pkt_ts - self._first_ts).total_seconds() >= self.window_seconds

    def finalize(self):
        if self._window is None:
            raise RuntimeError("No window to finalize")
        stats = self._window.finalize()
        self._window = None
        self._first_ts = None
        return stats

    def reset(self):
        self._window = None
        self._first_ts = None
```

You also need to add `finalize()` to `TrafficWindow` in `core.py`. Add this method to the `TrafficWindow` class:

```python
    def finalize(self) -> "TrafficStats":
        return TrafficStats(
            window=self,
            per_proto={k.value: v for k, v in self.protocol_counts.items()},
            syn_ratio=(self.syn_count / self.packet_count) if self.packet_count else 0.0,
            byte_rate=(self.byte_count / self._seconds) if self._seconds else 0.0,
        )
```

And add `_seconds` property to `TrafficWindow`:
```python
    @property
    def _seconds(self) -> float:
        return max(0.001, (self.end.timestamp() - self.start.timestamp()))
```

Also need to add `TrafficStats` and `TrafficWindow` to core.py. Add them after `PacketRecord`:

```python
@dataclass
class TrafficWindow:
    start: datetime
    end: datetime
    packet_count: int = 0
    byte_count: int = 0
    protocol_counts: dict[Protocol, int] = field(default_factory=dict)
    syn_count: int = 0
    rst_count: int = 0
    src_ports: dict[int, int] = field(default_factory=dict)
    dst_ports: dict[int, int] = field(default_factory=dict)

    def add(self, pkt: PacketRecord) -> None:
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
        return TrafficStats(
            window=self,
            per_proto={k.value: v for k, v in self.protocol_counts.items()},
            syn_ratio=(self.syn_count / self.packet_count) if self.packet_count else 0.0,
            byte_rate=(self.byte_count / self._seconds) if self._seconds else 0.0,
        )

@dataclass
class TrafficStats:
    window: TrafficWindow
    per_proto: dict[int, int] = field(default_factory=dict)
    syn_ratio: float = 0.0
    byte_rate: float = 0.0

    @property
    def packet_rate(self) -> float:
        return self.window.packet_count / self.window._seconds
```

#### Practice

1. Write the code above (both `core.py` additions AND `metrics/window.py`)
2. Test the window aggregator:
   ```bash
   python -c "
   from ddosguard.metrics.window import WindowAggregator
   from ddosguard.capture.base import SyntheticGenerator
   from datetime import datetime, timedelta

   gen = SyntheticGenerator(mode='normal', base_rate=200)
   agg = WindowAggregator(window_seconds=1.0)

   for pkt in gen.iter_packets(3.0):
       agg.add(pkt)
       if agg.is_complete(pkt.ts):
           stats = agg.finalize()
           print(f'Window: {stats.packet_rate:.1f} pps, {stats.byte_rate:.0f} B/s')
           agg.reset()
   "
   ```
3. **Break it**: Call `finalize()` without adding any packets. See the error. Fix it by adding packets first.
4. **Experiment**: Change `window_seconds=0.5` and see how the stats change. Shorter windows = more granular but noisier data.

**Verify**: The test prints window stats with packet rate around 200 pps.

**Time**: 20 minutes

---

### Step 8: Rolling Windows

#### Learn

A **fixed window** gives you discrete snapshots: "here's the stats for seconds 0-10, now here's seconds 10-20."

A **rolling window** keeps the last N snapshots in a buffer and lets you compute trend statistics:
- **Mean**: average packet rate over the last N windows
- **Max**: highest packet rate in the last N windows
- **Trend**: is traffic increasing or decreasing? (last minus first)

This matters because attacks sometimes ramp up gradually. A fixed window might miss the early stages. A rolling window catches the trend.

**Ring buffer** (`collections.deque(maxlen=N)`): automatically discards old items when full. You add new items and old ones fall off the end. Perfect for "keep the last N things."

#### Build

Add `RollingAggregator` to `ddosguard/metrics/window.py`:

```python
from collections import deque

class RollingAggregator:
    def __init__(self, window_seconds=10.0, num_windows=5):
        self.window_seconds = window_seconds
        self.num_windows = num_windows
        self._buffer = deque(maxlen=num_windows)
        self._current = WindowAggregator(window_seconds)
        self._first_ts = None

    def add(self, pkt):
        if self._first_ts is None:
            self._first_ts = pkt.ts
        self._current.add(pkt)

    def add_and_commit(self, pkt):
        self.add(pkt)
        if self._current and self._first_ts and \
           (pkt.ts - self._first_ts).total_seconds() >= self.window_seconds:
            stats = self._current.finalize()
            self._buffer.append(stats)
            self._current = WindowAggregator(self.window_seconds)
            self._first_ts = pkt.ts
            return stats
        return None

    @property
    def mean_rate(self):
        if not self._buffer:
            return 0.0
        return sum(w.packet_rate for w in self._buffer) / len(self._buffer)

    @property
    def max_rate(self):
        if not self._buffer:
            return 0.0
        return max(w.packet_rate for w in self._buffer)

    @property
    def trend(self):
        if len(self._buffer) < 2:
            return 0.0
        return self._buffer[-1].packet_rate - self._buffer[0].packet_rate
```

#### Practice

1. Add `RollingAggregator` to `metrics/window.py`
2. Test it:
   ```bash
   python -c "
   from ddosguard.metrics.window import RollingAggregator
   from ddosguard.capture.base import SyntheticGenerator

   gen = SyntheticGenerator(mode='normal', base_rate=100)
   roll = RollingAggregator(window_seconds=1.0, num_windows=5)

   for i in range(7):
       for pkt in gen.iter_packets(1.0):
           roll.add_and_commit(pkt)

   print(f'Mean: {roll.mean_rate:.1f} pps')
   print(f'Max: {roll.max_rate:.1f} pps')
   print(f'Trend: {roll.trend:.1f} (positive = increasing)')
   "
   ```
3. **Break it**: Create a `RollingAggregator` and immediately check `mean_rate`. It should be 0 (empty buffer). Verify.
4. **Experiment**: Create a `RollingAggregator(window_seconds=0.5, num_windows=3)`. Feed it packets and watch how quickly the buffer fills and changes.

**Verify**: Mean and max rates are positive. Trend is near zero (normal traffic doesn't trend).

**Time**: 20 minutes

---

### Step 9: Write Tests for Windowing

#### Learn

**Unit tests** verify that individual pieces of code work correctly. The key principles:
- Test one thing at a time (one behavior per test)
- Use clear names that say what's being tested
- Use a helper function to reduce repetition
- Test edge cases (empty input, max input, boundary conditions)

**pytest** discovers tests by looking for functions/classes starting with `test_`. `assert` statements check conditions. If an assert fails, the test fails.

**"No network, no permissions"** means: these tests use fake data and pure computation. They never touch the network, never read files (except test fixtures you create), never need special OS permissions. They can run anywhere, anytime.

#### Build

Create `tests/test_metrics.py`:

```python
import pytest
from datetime import datetime, timedelta
from ddosguard.metrics.window import WindowAggregator, RollingAggregator
from ddosguard.core import PacketRecord, Protocol

def mk(ts, proto=Protocol.TCP, flags="", length=100):
    return PacketRecord(ts=ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                        protocol=proto, src_port=12345, dst_port=80,
                        length=length, flags=flags)

class TestWindowAggregator:
    def test_add_increments_count(self):
        agg = WindowAggregator(10.0)
        agg.add(mk(datetime.now()))
        assert agg._window.packet_count == 1
        assert agg._window.byte_count == 100

    def test_finalize_gives_stats(self):
        agg = WindowAggregator(10.0)
        for i in range(10):
            agg.add(mk(datetime.now() + timedelta(seconds=i)))
        stats = agg.finalize()
        assert stats.packet_rate > 0
        assert stats.window.packet_count == 10

    def test_syn_tracked(self):
        agg = WindowAggregator(10.0)
        ts = datetime.now()
        agg.add(mk(ts, flags="S"))
        agg.add(mk(ts + timedelta(seconds=1), flags="PA"))
        agg.add(mk(ts + timedelta(seconds=2), flags="S"))
        stats = agg.finalize()
        assert stats.window.syn_count == 2

    def test_reset_clears(self):
        agg = WindowAggregator(10.0)
        agg.add(mk(datetime.now()))
        agg.reset()
        assert agg._window is None

class TestRollingAggregator:
    def test_empty_means_zero(self):
        roll = RollingAggregator(1.0, 3)
        assert roll.mean_rate == 0.0
        assert roll.max_rate == 0.0
        assert roll.trend == 0.0

    def test_trend_up(self):
        roll = RollingAggregator(1.0, 3)
        base = datetime.now()
        for window, rate in enumerate([10, 20, 30]):
            for i in range(rate):
                roll.add_and_commit(mk(base + timedelta(seconds=window + i*0.1)))
        assert roll.trend > 0

    def test_trend_down(self):
        roll = RollingAggregator(1.0, 3)
        base = datetime.now()
        for window, rate in enumerate([30, 20, 10]):
            for i in range(rate):
                roll.add_and_commit(mk(base + timedelta(seconds=window + i*0.1)))
        assert roll.trend < 0
```

#### Practice

1. Create `tests/` directory and `tests/test_metrics.py`
2. Run the tests: `python -m pytest tests/test_metrics.py -v`
3. **Break a test on purpose**: Change `assert stats.window.packet_count == 10` to `== 9` and run. See it fail. Fix it back.
4. **Write your own test**: Add a test that verifies `is_complete` works correctly (add packets spanning less than the window duration, assert `is_complete` returns False).

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 30 minutes

---

## Phase 4: Baseline System

### Step 10: Learn About Statistical Baselines

#### Learn

A **baseline** is a model of "normal" traffic. It answers: "What packet rate should I expect right now?"

**Why time matters**: A web server at 2pm gets way more traffic than at 2am. If you compare 2am traffic to the 2pm baseline, you'll think 2am is suspiciously quiet. Wrong.

**Diurnal buckets**: We split time into buckets:
- `weekday-8` = weekdays at 8am
- `weekday-14` = weekdays at 2pm
- `weekend-3` = weekends at 3am

Each bucket stores statistics (mean, stdev, percentiles) for the traffic observed during that time slot.

**Z-score**: How many standard deviations away from the mean is a value?
```
z = (value - mean) / stdev
```
- z = 0: exactly average
- z = 2: 2 standard deviations above average (unusual)
- z = 3: 3 standard deviations above average (very unusual)

A common threshold: z > 2 means "this is anomalous."

**WORKED EXAMPLE**: Let's say your baseline for `weekday-14` (weekdays at 2pm) is:
- mean = 1000 packets/sec
- stdev = 100 packets/sec

At 2:05pm, you measure 1300 pps. Is this normal?

```
z = (1300 - 1000) / 100 = 3.0
```

z = 3 means "3 standard deviations above normal." This is very unusual — likely an attack.

If you measured 1100 pps:
```
z = (1100 - 1000) / 100 = 1.0
```

z = 1 is within normal variation. Not anomalous.

**Reservoir sampling**: To keep memory bounded, we keep a fixed-size sample of observations (say 1000). When full, oldest values are evicted. Statistics are recomputed from whatever is in the reservoir.

#### Practice (Concept Check)

1. If the mean packet rate for `weekday-14` is 1000 pps with stdev 100, what's the z-score for 1300 pps? **Answer: 3.0**
2. If z > 2 is "anomalous", what packet rate would trigger an alert for this bucket? **Answer: 1000 + 2*100 = 1200 pps**
3. Why can't we use one baseline for all times of day? **Answer: Because 2am ≠ 2pm — different traffic patterns**

Write down your answers before reading the ones above. If you got them right, you understand the concept. If not, re-read the worked example.

**Time**: 10 minutes

---

### Step 11: Build the Baseline Store

#### Learn

The **baseline store** maintains diurnal buckets, observes traffic, and persists to disk.

Key design decisions:
- **Buckets are keyed by time**: `_bucket_key(ts)` returns `"weekday-14"` or `"weekend-3"` etc.
- **Multiple metrics per bucket**: we track `packet_rate`, `byte_rate`, `syn_ratio` separately
- **Persistence**: save to JSON so the baseline survives restarts
- **Graceful fallback**: if no baseline data exists for a bucket, return 0 (don't crash)

#### Build

Create `ddosguard/baseline/store.py`:

```python
from __future__ import annotations
import json
import os
from datetime import datetime
from typing import Dict, Optional
from ddosguard.core import BaselineStats, TrafficStats
from ddosguard.config import Config

class BaselineStore:
    def __init__(self, config: Config, data_dir="data"):
        self.config = config
        self.data_dir = data_dir
        self.buckets: Dict[str, BaselineStats] = {}
        self._ready = False

    def set_ready(self, ready: bool):
        self._ready = ready

    @property
    def is_ready(self) -> bool:
        return self._ready

    def _bucket_key(self, ts: datetime) -> str:
        weekday = ts.weekday() < 5  # Mon-Fri
        hour = ts.hour
        prefix = "weekday" if weekday else "weekend"
        return f"{prefix}-{hour}"

    def observe(self, stats: TrafficStats, ts: datetime):
        for metric_name, value in [
            ("packet_rate", stats.packet_rate),
            ("byte_rate", stats.byte_rate),
            ("syn_ratio", stats.syn_ratio),
        ]:
            key = f"{self._bucket_key(ts)}:{metric_name}"
            if key not in self.buckets:
                self.buckets[key] = BaselineStats()
            self.buckets[key].add(value)

    def expected(self, metric: str, ts: datetime) -> float:
        key = f"{self._bucket_key(ts)}:{metric}"
        if key in self.buckets:
            return self.buckets[key].mean
        return 0.0

    def expected_with_stdev(self, metric: str, ts: datetime) -> tuple[float, float]:
        key = f"{self._bucket_key(ts)}:{metric}"
        if key in self.buckets:
            model = self.buckets[key]
            return model.mean, model.stdev
        return 0.0, 0.0

    def all(self) -> Dict[str, BaselineStats]:
        return dict(self.buckets)

    def save(self):
        os.makedirs(self.data_dir, exist_ok=True)
        path = os.path.join(self.data_dir, "baseline.json")
        data = {}
        for key, stats in self.buckets.items():
            data[key] = {
                "mean": stats.mean, "stdev": stats.stdev, "count": stats.count,
                "p5": stats.p5, "p25": stats.p25, "p75": stats.p75,
                "p95": stats.p95, "p99": stats.p99, "samples": stats.samples,
            }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self):
        path = os.path.join(self.data_dir, "baseline.json")
        if not os.path.exists(path):
            return
        with open(path) as f:
            data = json.load(f)
        for key, vals in data.items():
            self.buckets[key] = BaselineStats(
                mean=vals.get("mean", 0), stdev=vals.get("stdev", 0),
                count=vals.get("count", 0), p5=vals.get("p5", 0),
                p25=vals.get("p25", 0), p75=vals.get("p75", 0),
                p95=vals.get("p95", 0), p99=vals.get("p99", 0),
                samples=vals.get("samples", []),
            )
```

You need `BaselineStats` in core.py. Add it:

```python
@dataclass
class BaselineStats:
    mean: float = 0.0
    stdev: float = 0.0
    count: int = 0
    p5: float = 0.0
    p25: float = 0.0
    p75: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    samples: list[float] = field(default_factory=list)

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
        self.stdev = (sum((v - self.mean)**2 for v in self.samples) / (n-1))**0.5 if n > 1 else 0.0
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
```

#### Practice

1. Write `baseline/store.py` and add `BaselineStats` to `core.py`
2. Test it:
   ```bash
   python -c "
   from ddosguard.baseline.store import BaselineStore
   from ddosguard.config import Config
   from ddosguard.core import TrafficStats, TrafficWindow
   from datetime import datetime, timedelta

   config = Config.load(None)
   store = BaselineStore(config, data_dir='data')
   store.set_ready(True)

   # Observe 10 windows of normal traffic
   now = datetime.now()
   for i in range(10):
       ts = now + timedelta(seconds=i*10)
       w = TrafficWindow(start=ts - timedelta(seconds=10), end=ts)
       for j in range(50):
           w.add(type('P', (), {'ts':ts,'length':100,'protocol':6,'is_syn':False,
                                 'is_rst':False,'src_port':12345,'dst_port':80,
                                 'src_ip':'10.0.0.1','dst_ip':'10.0.0.2'})())
       store.observe(w.finalize(), ts)

   print(f'Buckets: {len(store.all())}')
   print(f'Expected packet_rate: {store.expected(\"packet_rate\", datetime.now()):.2f}')
   store.save()
   print('Saved to data/baseline.json')

   # Reload
   store2 = BaselineStore(config, data_dir='data')
   store2.load()
   print(f'After reload: {store2.expected(\"packet_rate\", datetime.now()):.2f}')
   "
   ```
3. **Break it**: Call `expected()` for a metric that was never observed. It should return 0. Verify.
4. **Experiment**: Observe traffic with different rates (50, 100, 150 pps) and check how the mean changes.

**Verify**: After observing, expected value matches the observed rate. Save/load round-trips correctly.

**Time**: 30 minutes

---

### Step 12: Write Baseline Tests

#### Learn

Testing a baseline store involves:
- **Bucket key correctness**: verify `weekday-14` for Mondays at 2pm, `weekend-3` for Saturdays at 3am
- **Persistence**: save to JSON, load back, verify values match
- **Statistics**: adding multiple values updates mean, stdev, percentiles correctly
- **Edge cases**: empty store returns 0, not crash

#### Build

Create `tests/test_baseline.py`:

```python
import json, os, pytest, tempfile
from datetime import datetime
from ddosguard.baseline.store import BaselineStore
from ddosguard.core import BaselineStats, TrafficStats, TrafficWindow
from ddosguard.config import Config

def fake_stats(pr=100.0, br=50000.0, sr=0.1):
    now = datetime.now()
    w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
    w.packet_count = int(pr*10)
    w.byte_count = int(br*10)
    return TrafficStats(window=w, per_proto={6:70, 17:30}, syn_ratio=sr, byte_rate=br)

class TestBaselineStore:
    def test_bucket_key_weekday(self):
        store = BaselineStore(Config.load(None))
        assert store._bucket_key(datetime(2026,11,2,14,30)) == "weekday-14"

    def test_bucket_key_weekend(self):
        store = BaselineStore(Config.load(None))
        assert store._bucket_key(datetime(2026,11,7,3,0)) == "weekend-3"

    def test_observe_creates_buckets(self):
        store = BaselineStore(Config.load(None))
        store.observe(fake_stats(100, 50000), datetime.now())
        assert len(store.all()) >= 3

    def test_expected_returns_mean(self):
        store = BaselineStore(Config.load(None))
        store.observe(fake_stats(200, 80000), datetime.now())
        assert store.expected("packet_rate", datetime.now()) == pytest.approx(200, abs=1)

    def test_expected_zero_when_empty(self):
        store = BaselineStore(Config.load(None))
        assert store.expected("packet_rate", datetime.now()) == 0.0

    def test_persistence(self):
        d = tempfile.mkdtemp()
        store = BaselineStore(Config.load(None), data_dir=d)
        store.observe(fake_stats(300, 120000), datetime.now())
        store.save()
        store2 = BaselineStore(Config.load(None), data_dir=d)
        store2.load()
        assert store2.expected("packet_rate", datetime.now()) == pytest.approx(300, abs=1)

    def test_multiple_observations(self):
        store = BaselineStore(Config.load(None))
        ts = datetime.now()
        for r in [100, 110, 120, 90, 105]:
            store.observe(fake_stats(float(r), float(r*500)), ts)
        model = list(store.buckets.values())[0]
        assert model.count == 5
        assert model.mean == pytest.approx(105, abs=2)
```

#### Practice

1. Create `tests/test_baseline.py` and run: `python -m pytest tests/test_baseline.py -v`
2. **Write your own test**: Test that `expected_with_stdev` returns a tuple of (mean, stdev). Add it.
3. **Break it**: Change the bucket key logic to always return `"weekday-0"` and run the test. See `test_bucket_key_weekend` fail. Fix it.

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 20 minutes

---

## Phase 5: Anomaly Detection

### Step 13: Learn About Detection Signals

#### Learn

A **signal** is a function that looks at traffic statistics and returns a score from 0 (normal) to 1 (highly anomalous).

We use 5 signals because different attacks look different:

| Signal | Detects | How |
|--------|---------|-----|
| **Volume** | Traffic way above baseline | z-score of packet_rate and byte_rate |
| **Protocol** | Unusual protocol mix | One protocol dominating (>80% of traffic) |
| **Source** | Many unique sources | High unique source count in a short window |
| **Port** | Traffic concentrated on one port | One port gets >70% of traffic |
| **SYN** | SYN flood | SYN ratio > 0.3 (normal is < 0.3) |

**Composite scoring**: Each signal returns a 0..1 score. We weight them (volume=30%, protocol=20%, etc.) and sum. The total determines severity:
- 0.0-0.30: INFO (normal)
- 0.30-0.50: LOW
- 0.50-0.70: MEDIUM
- 0.70-0.85: HIGH
- 0.85-1.0: CRITICAL

**Confirmation damping**: To prevent flapping (rapidly switching between "attack!" and "all clear"), we smooth the score. If the new score is higher, we move toward it slowly (multiply the increase by 0.8). If lower, we move faster. This means brief spikes don't trigger immediate alerts.

#### Practice (Concept Check)

1. If volume signal returns 0.8 and its weight is 0.30, what's its weighted contribution? **Answer: 0.24**
2. If all 5 signals fire at 0.9, what's the total (before damping)? **Answer: 0.9 * 1.0 = 0.9**
3. What severity would a score of 0.75 map to? **Answer: HIGH, since 0.70-0.85**

Write down your answers before reading the ones above. If you got them right, you understand the concept. If not, re-read the explanation.

**Time**: 10 minutes

---

### Step 14: Build Detection Signals

#### Learn

Each signal is a self-contained function. They all take `(stats, baseline)` and return a `SignalResult`.

**Volume signal** uses z-score:
```python
z = max(0, stats.packet_rate - mean) / stdev
score = min(1.0, z / 5.0)  # z=5+ saturates at 1.0
```

#### Build

Create `ddosguard/detect/signals.py`:

```python
from __future__ import annotations
from typing import Dict, List
from ddosguard.core import BaselineStats, SignalResult, TrafficStats
from ddosguard.baseline.store import BaselineStore

def _severity_from_score(total: float):
    if total >= 0.85: return "CRITICAL"
    if total >= 0.70: return "HIGH"
    if total >= 0.50: return "MEDIUM"
    if total >= 0.30: return "LOW"
    return "INFO"

def volume_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    mean_pr, stdev_pr = baseline.expected_with_stdev("packet_rate", stats.window.start)
    mean_br, stdev_br = baseline.expected_with_stdev("byte_rate", stats.window.start)
    score = 0.0
    if stdev_pr > 0:
        z = max(0, stats.packet_rate - mean_pr) / stdev_pr
        score = min(1.0, z / 5.0)
    if stdev_br > 0:
        z = max(0, stats.byte_rate - mean_br) / stdev_br
        score = max(score, min(1.0, z / 5.0))
    return SignalResult("volume", score, {
        "packet_rate_z": round(max(0, stats.packet_rate - mean_pr) / stdev_pr, 2) if stdev_pr > 0 else 0,
        "baseline_mean_packet_rate": round(mean_pr, 2),
        "current_packet_rate": round(stats.packet_rate, 2),
    })

def syn_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    score = 0.0
    if stats.syn_ratio > 0.3:
        score = min(1.0, (stats.syn_ratio - 0.3) / 0.6)
    return SignalResult("syn", score, {"syn_ratio": round(stats.syn_ratio, 3)})

def protocol_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    score = 0.0
    if stats.per_proto:
        total = sum(stats.per_proto.values())
        if total > 0:
            max_prop = max(stats.per_proto.values()) / total
            if max_prop > 0.8:
                score = min(1.0, (max_prop - 0.8) / 0.2)
    return SignalResult("protocol", score, {"max_protocol_proportion": round(max(stats.per_proto.values())/sum(stats.per_proto.values()), 3) if stats.per_proto else 0})

def source_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    unique = len(stats.window.src_ports) if hasattr(stats.window, 'src_ports') else 0
    score = min(1.0, (unique - 10) / 90.0) if unique > 10 else 0.0
    return SignalResult("source", score, {"unique_sources": unique})

def port_signal(stats: TrafficStats, baseline: BaselineStore) -> SignalResult:
    score = 0.0
    if stats.window.dst_ports:
        total = sum(stats.window.dst_ports.values())
        if total > 0:
            max_port = max(stats.window.dst_ports, key=stats.window.dst_ports.get)
            max_prop = stats.window.dst_ports[max_port] / total
            if max_prop > 0.7:
                score = min(1.0, (max_prop - 0.7) / 0.3)
            return SignalResult("port", score, {"max_port": max_port, "max_port_proportion": round(max_prop, 3)})
    return SignalResult("port", score, {})

def run_all_signals(stats: TrafficStats, baseline: BaselineStore) -> List[SignalResult]:
    return [volume_signal(stats, baseline), protocol_signal(stats, baseline),
            source_signal(stats, baseline), port_signal(stats, baseline), syn_signal(stats, baseline)]
```

#### Practice

1. Write `detect/signals.py`
2. Test volume signal:
   ```bash
   python -c "
   from ddosguard.detect.signals import volume_signal, syn_signal
   from ddosguard.baseline.store import BaselineStore
   from ddosguard.config import Config
   from ddosguard.core import TrafficStats, TrafficWindow
   from datetime import datetime, timedelta

   config = Config.load(None)
   baseline = BaselineStore(config, data_dir='data')
   baseline.set_ready(True)

   # Train baseline with normal traffic
   now = datetime.now()
   for i in range(10):
       w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
       w.packet_count = 500
       w.byte_count = 250000
       baseline.observe(w.finalize(), now)

   # Test with high traffic
   w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w.packet_count = 5000
   w.byte_count = 2500000
   stats = w.finalize()
   result = volume_signal(stats, baseline)
   print(f'Volume score: {result.score:.3f} (should be high)')
   print(f'Detail: {result.detail}')

   # Test SYN signal
   w2 = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w2.packet_count = 1000
   w2.syn_count = 900
   stats2 = w2.finalize()
   result2 = syn_signal(stats2, baseline)
   print(f'SYN score: {result2.score:.3f} (should be high, syn_ratio=0.9)')
   "
   ```
3. **Break it**: Set `stdev_pr = 0` (no baseline variation) and observe what the z-score calculation does. Fix it by handling the zero-stdev case (already done in the code above with `if stdev_pr > 0`).
4. **Experiment**: Change the SYN threshold from 0.3 to 0.5. Test with syn_ratio=0.4. See the score drop.

**Verify**: Volume signal gives high score for 10x traffic. SYN signal gives high score for 90% SYN ratio.

**Time**: 30 minutes

---

### Step 15: Build the Composite Scorer

#### Learn

The **composite scorer** combines all signals into one score:
1. Run all 5 signals
2. Weight each signal's score
3. Sum the weighted scores
4. Apply confirmation damping
5. Classify severity and attack type

**Weights** (configurable):
- Volume: 0.30
- Protocol: 0.20
- Source: 0.20
- Port: 0.15
- SYN: 0.15
(Total = 1.0)

**Attack classification**:
- Volume high + SYN high → "mixed"
- Volume high only → "volumetric"
- SYN high only → "protocol"
- Port concentration → "application"
- Default → "unknown"

#### Build

Create `ddosguard/detect/scorer.py`:

```python
from __future__ import annotations
from typing import Dict, List, Optional
from ddosguard.core import CompositeScore, SignalResult, Severity, TrafficStats
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.signals import run_all_signals

class CompositeScorer:
    def __init__(self, config=None):
        self.weights = {"volume": 0.30, "protocol": 0.20, "source": 0.20, "port": 0.15, "syn": 0.15}
        self.damping = 0.8
        self._prev = None
        if config:
            try:
                det = config.detection
                if "weights" in det and isinstance(det["weights"], dict):
                    for k, v in det["weights"].items():
                        if k in self.weights:
                            self.weights[k] = float(v)
                if "confirmation_damping" in det:
                    self.damping = float(det["confirmation_damping"])
            except:
                pass

    def score(self, stats: TrafficStats, baseline: BaselineStore) -> CompositeScore:
        signals = run_all_signals(stats, baseline)
        total = 0.0
        scores = {}
        names = []
        for sig in signals:
            w = self.weights.get(sig.name, 0.0)
            total += sig.score * w
            scores[sig.name] = sig.score
            names.append(sig.name)

        # Damping
        if self._prev is None:
            self._prev = total
        elif total > self._prev:
            total = self._prev + (total - self._prev) * self.damping
        else:
            total = self._prev + (total - self._prev) * (2 - self.damping)
        self._prev = max(0.0, min(1.0, total))

        # Severity
        if total >= 0.85: sev = Severity.CRITICAL
        elif total >= 0.70: sev = Severity.HIGH
        elif total >= 0.50: sev = Severity.MEDIUM
        elif total >= 0.30: sev = Severity.LOW
        else: sev = Severity.INFO

        # Classification
        fired = {s.name for s in signals if s.score > 0.3}
        if total < 0.30:
            cls = "none"
        elif "volume" in fired and "syn" in fired:
            cls = "mixed"
        elif "volume" in fired:
            cls = "volumetric"
        elif "syn" in fired:
            cls = "protocol"
        elif "port" in fired or "protocol" in fired:
            cls = "application"
        else:
            cls = "unknown"

        return CompositeScore(
            signal_names=names, signal_scores=scores, total=total,
            severity=sev, classification=cls, window=stats,
        )
```

#### Practice

1. Write `detect/scorer.py`
2. Test it:
   ```bash
   python -c "
   from ddosguard.detect.scorer import CompositeScorer
   from ddosguard.baseline.store import BaselineStore
   from ddosguard.config import Config
   from ddosguard.core import TrafficStats, TrafficWindow, Severity
   from datetime import datetime, timedelta

   config = Config.load(None)
   baseline = BaselineStore(config, data_dir='data')
   baseline.set_ready(True)
   scorer = CompositeScorer(config)

   # Train with normal
   now = datetime.now()
   for i in range(20):
       w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
       w.packet_count = 500
       w.byte_count = 250000
       baseline.observe(w.finalize(), now)

   # Normal traffic
   w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w.packet_count = 550
   w.byte_count = 275000
   stats = w.finalize()
   s = scorer.score(stats, baseline)
   print(f'Normal: {s.total:.3f} {s.severity.name} {s.classification}')

   # Attack traffic (SYN flood)
   w2 = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w2.packet_count = 5000
   w2.syn_count = 4500
   w2.protocol_counts[6] = 5000
   stats2 = w2.finalize()
   s2 = scorer.score(stats2, baseline)
   print(f'Attack: {s2.total:.3f} {s2.severity.name} {s2.classification}')
   print(f'Signals: {s2.signal_scores}')
   "
   ```
3. **Experiment**: Change weights to make SYN signal dominate (`"syn": 0.50`). Test the same attack traffic. See how the score changes.

**Verify**: Normal traffic scores < 0.3. Attack traffic scores > 0.5.

**Time**: 25 minutes

---

## Phase 6: Rate Limiting & Mitigation

### Step 16: Learn About Token Buckets

#### Learn

A **token bucket** is a rate-limiting algorithm:
- A bucket holds tokens (permission to send data)
- Tokens are added at a fixed rate (e.g., 100 tokens/second)
- Each request consumes tokens (e.g., 1 token per packet)
- If the bucket is empty, the request is denied

```
Bucket (capacity = burst)
  ↑
  │  tokens added at "rate" per second
  │  max tokens = "burst"
  │
  └─────────── consume tokens on each request
```

**Parameters**:
- `rate`: sustained rate (tokens added per second)
- `burst`: maximum bucket capacity (max burst allowed)

**Behavior**:
- `burst > 0`: bucket starts with burst tokens → first burst requests allowed immediately
- `burst = 0`: bucket starts empty → strict rate limiting from the start

**Refill** (analytical, not tick-based):
```
tokens = min(burst, tokens + elapsed_time * rate)
```
This is accurate regardless of how often you check.

**Per-source buckets**: Each source IP gets its own bucket. Attackers can't consume tokens allocated to legitimate users.

#### Practice (Concept Check)

1. A bucket has rate=100, burst=200. How many requests can it handle in the first second? **Answer: 200 — the burst**
2. After the burst is consumed, what's the sustained rate? **Answer: 100/sec**
3. If burst=0, what happens on the first request? **Answer: denied — no tokens yet**

Write down your answers before reading the ones above. If you got them right, you understand the concept. If not, re-read the explanation.

**Time**: 10 minutes

---

### Step 17: Build Token Bucket & Rate Limiter

#### Build

Create `ddosguard/mitigate/ratelimit.py`:

```python
from __future__ import annotations
from datetime import datetime
from typing import Dict, Optional

class TokenBucket:
    def __init__(self, rate=100.0, burst=200.0):
        self.rate = rate
        self.burst = burst
        self._tokens = burst if burst > 0 else 0.0
        self._last = datetime.now()
        self._refill()

    def _refill(self):
        now = datetime.now()
        elapsed = (now - self._last).total_seconds()
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last = now

    def consume(self, tokens=1.0) -> bool:
        if tokens <= 0:
            return True
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens

class RateLimiter:
    def __init__(self, default_rate=100.0, default_burst=200.0):
        self.default_rate = default_rate
        self.default_burst = default_burst
        self._buckets: Dict[str, TokenBucket] = {}
        self._whitelist: set = set()
        self._admitted = 0
        self._denied = 0

    def add_whitelist(self, key: str):
        self._whitelist.add(key)

    def remove_whitelist(self, key: str) -> bool:
        if key in self._whitelist:
            self._whitelist.discard(key)
            return True
        return False

    def is_whitelisted(self, key: str) -> bool:
        return key in self._whitelist

    def admit(self, key: str, tokens=1.0) -> bool:
        if key in self._whitelist:
            self._admitted += 1
            return True
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(self.default_rate, self.default_burst)
        allowed = self._buckets[key].consume(tokens)
        if allowed:
            self._admitted += 1
        else:
            self._denied += 1
        return allowed

    def stats(self, key=None):
        if key:
            if key in self._whitelist:
                return {"key": key, "whitelisted": True}
            if key in self._buckets:
                b = self._buckets[key]
                return {"key": key, "whitelisted": False, "tokens": b.available,
                        "rate": b.rate, "burst": b.burst}
            return {"key": key, "whitelisted": False, "bucket": "not seen"}
        return {"total_admitted": self._admitted, "total_denied": self._denied,
                "active_buckets": len(self._buckets), "whitelisted": len(self._whitelist)}

    def clear(self):
        self._buckets.clear()
        self._whitelist.clear()
        self._admitted = 0
        self._denied = 0
```

#### Practice

1. Write `mitigate/ratelimit.py`
2. Test TokenBucket:
   ```bash
   python -c "
   from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter
   import time

   # Test burst
   b = TokenBucket(rate=10, burst=5)
   print(f'Initial: {b.available:.1f}')
   for i in range(5):
       print(f'Consume {i+1}: {b.consume(1)} (tokens left: {b.available:.1f})')
   print(f'6th: {b.consume(1)} (should be False)')

   # Test RateLimiter
   print()
   limiter = RateLimiter(default_rate=100, default_burst=200)
   limiter.add_whitelist('10.0.0.1')
   print(f'Whitelist admit: {limiter.admit(\"10.0.0.1\", 1)} (should be True)')
   admitted = sum(limiter.admit('10.0.0.2', 1) for _ in range(250))
   print(f'250 requests from 10.0.0.2: {admitted} admitted (should be ~200)')
   print(f'Stats: {limiter.stats()}')
   "
   ```
3. **Break it**: Set `burst=0` and try to consume. See it deny. Then set `burst=1` and verify it allows 1.

**Verify**: TokenBucket allows burst then enforces rate. RateLimiter whitelists bypass limiting.

**Time**: 30 minutes

---

### Step 18: Write Rate Limiter Tests

#### Build

Create `tests/test_ratelimit.py`:

```python
import pytest, time
from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter

class TestTokenBucket:
    def test_burst_available(self):
        b = TokenBucket(rate=10, burst=5)
        assert b.available == pytest.approx(5.0, abs=0.01)

    def test_zero_burst_empty(self):
        b = TokenBucket(rate=10, burst=0)
        assert b.available == 0.0
        assert not b.consume(1)

    def test_consume_denied_when_empty(self):
        b = TokenBucket(rate=100, burst=5)
        for _ in range(5):
            assert b.consume(1)
        assert not b.consume(1)

    def test_refill(self):
        b = TokenBucket(rate=100, burst=50)
        for _ in range(50):
            b.consume(1)
        assert b.available == pytest.approx(0.0, abs=0.01)
        time.sleep(0.5)
        assert b.available >= 40

class TestRateLimiter:
    def test_whitelist_bypass(self):
        lim = RateLimiter(1, 1)
        lim.add_whitelist("10.0.0.1")
        for _ in range(100):
            assert lim.admit("10.0.0.1", 1)

    def test_non_whitelisted_limited(self):
        lim = RateLimiter(10, 5)
        admitted = sum(lim.admit("10.0.0.2", 1) for _ in range(20))
        assert admitted <= 20
        assert admitted >= 5

    def test_independent_buckets(self):
        lim = RateLimiter(10, 5)
        for _ in range(5):
            lim.admit("10.0.0.1", 1)
        assert lim.admit("10.0.0.2", 1)
```

#### Practice

1. Create `tests/test_ratelimit.py` and run: `python -m pytest tests/test_ratelimit.py -v`
2. **Write your own test**: Test that `remove_whitelist` returns `True` when removing a whitelisted key and `False` for a non-whitelisted one.
3. **Break it**: Change `admit` to not check the whitelist. Run the whitelist test. See it fail (the whitelisted IP should be limited but isn't). Fix it back.

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 20 minutes

---

## Phase 7: Firewall Rules

### Step 19: Build Firewall Rule Generation

#### Learn

**iptables** is the Linux firewall. Rules are specified as:
```
-A CHAIN condition -j ACTION
```

For DDoS mitigation, we generate rules per stage:
- Stage 0: no rules
- Stage 1: lenient per-IP rate limit (ACCEPT up to limit, then drop)
- Stage 2: strict per-IP + recent module (track and block repeat offenders)
- Stage 3: service-port rate limits (limit traffic to specific ports)
- Stage 4: full DROP (aggressive)

**Whitelist first**: whitelist ACCEPT rules must come BEFORE DROP rules, otherwise the DROP catches whitelisted traffic.

**Dry-run**: Generate rules but don't execute them. This is critical for safety — a bad rule can lock you out of your server.

#### Build

Create `ddosguard/mitigate/firewall.py`:

```python
from __future__ import annotations
import subprocess
from typing import Dict, List, Optional

class FirewallManager:
    def __init__(self, dry_run=True, chain="INPUT"):
        self.dry_run = dry_run
        self.chain = chain
        self._active: List[str] = []

    def generate_rules(self, stage: int, severity: str = "",
                       config: Optional[Dict] = None,
                       whitelist: Optional[List[str]] = None) -> List[str]:
        wl = whitelist or []
        rules = []
        if stage == 0:
            return rules
        rules.append(f"# ddosguard: stage={stage} severity={severity}")
        for ip in wl:
            rules.append(f"-A {self.chain} -s {ip} -j ACCEPT  # ddosguard: whitelist {ip}")
        if stage >= 1:
            rate = self._get(config, stage, "rate", 100)
            burst = self._get(config, stage, "burst", 200)
            rules.append(f"-A {self.chain} -p tcp -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT  # ddosguard: stage={stage}")
            rules.append(f"-A {self.chain} -p udp -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT  # ddosguard: stage={stage}")
        if stage >= 2:
            r = self._get(config, stage, "rate", 50)
            rules.append(f"-A {self.chain} -p tcp -m recent --set --name DDOSGUARD  # ddosguard: stage={stage}")
            rules.append(f"-A {self.chain} -p tcp -m recent --update --seconds 10 --hitcount {r} --name DDOSGUARD -j DROP  # ddosguard: stage={stage}")
        if stage >= 4:
            rules.append(f"-A {self.chain} -p tcp --syn -j DROP  # ddosguard: stage={stage} full drop")
        return rules

    def _get(self, config, stage, key, default):
        if config and "rate_limits" in config:
            for rl in config["rate_limits"]:
                if rl.get("stage") == stage:
                    return float(rl.get(key, default))
        return float(default)

    def apply(self, rules: List[str]) -> bool:
        if self.dry_run:
            print(f"[DRY RUN] Would apply {len(rules)} rules:")
            for r in rules:
                print(f"  {r}")
            self._active = rules
            return True
        success = True
        for r in rules:
            if r.startswith("#"):
                continue
            try:
                subprocess.run(f"iptables {r}", shell=True, check=True, capture_output=True)
                self._active.append(r)
            except subprocess.CalledProcessError as e:
                print(f"Failed: {r} — {e.stderr.decode()}")
                success = False
        return success

    def clear(self) -> bool:
        if self.dry_run:
            print(f"[DRY RUN] Would clear {len(self._active)} rules")
            self._active.clear()
            return True
        self._active.clear()
        return True
```

#### Practice

1. Write `mitigate/firewall.py`
2. Test rule generation:
   ```bash
   python -c "
   from ddosguard.mitigate.firewall import FirewallManager
   fw = FirewallManager(dry_run=True)
   for stage in [0, 1, 2, 4]:
       rules = fw.generate_rules(stage=stage, severity='HIGH', whitelist=['192.168.1.1'])
       print(f'\\nStage {stage}: {len(rules)} rules')
       for r in rules:
           print(f'  {r}')
   "
   ```
3. **Verify ordering**: In stage 2 rules, the whitelist rule should appear before any DROP rule. Check the output.

**Verify**: Stage 0 = 0 rules. Stage 1 = rate limit rules. Stage 4 = DROP rules. Whitelist always first.

**Time**: 25 minutes

---

## Phase 8: Alerting & Escalation

### Steps 20-22 Summary

Due to length, these are condensed. Key concepts:

**Step 20 — AlertManager** (`ddosguard/alert/manager.py`): Signature-based dedup (hash of alert characteristics), cooldown (don't resend same alert within N seconds), max_per_minute (cap notifications), multi-channel (console, file JSONL, desktop, Slack, email).

**Step 21 — AlertDirector** (`ddosguard/alert/director.py`): Ranking alerts by severity. `get_urgent()` returns only CRITICAL alerts. `get_timeline()` returns all alerts sorted by severity.

**Step 22 — Testing** (`tests/test_alert.py`): Test that dedup suppresses duplicates, rate limiting caps alerts, and the director ranks correctly.

The key skill here is **signature generation**:
```python
def _signature(self, alert: Alert) -> str:
    data = f"{alert.severity.name}:{alert.title}:{alert.summary}"
    return hash(data)[:16]  # Short hash as signature
```

This is how you tell if two alerts are "the same event." The hash combines the characteristics that define the alert. Two alerts about the same attack at the same severity will have the same signature → deduplicated.

**Time**: ~60 minutes total for these three steps

---

## Phase 9: Dashboard & Controls

### Steps 23-25 Summary

**Step 23 — FastAPI app** (`ddosguard/dashboard/app.py`): API endpoints for `/api/status`, `/api/stats`, `/api/baseline`, `/api/alerts`, `/api/mitigations`, `/api/whitelist` (GET/POST), `/api/control/pause|resume`. Uses `MonitorState` (thread-safe shared state) for live data.

**Step 24 — HTML dashboard** (`ddosguard/dashboard/static/index.html`): Dark-themed dashboard with live polling (every 2 seconds), sparkline chart (canvas), alert list, baseline table, whitelist controls, pause/resume buttons.

**Step 25 — MonitorRunner** (`ddosguard/monitor.py`): The main loop that ties everything together: capture → window → baseline → score → mitigate → alert → update state. Runs in a background thread. `MonitorState` uses `threading.Lock` for thread safety.

The key skill here is **thread-safe state sharing**:
```python
class MonitorState:
    def __init__(self):
        self._lock = threading.Lock()
        ...

    def update_stats(self, stats):
        with self._lock:
            self.current_stats = stats
```

The lock ensures that writes from the monitor thread and reads from the dashboard thread don't conflict. Without it, you could read partially-updated data.

**Time**: ~90 minutes total for these three steps

---

## Phase 10: CLI & Packaging

### Steps 26-28 Summary

**Step 26 — CLI** (`ddosguard/cli.py`): Uses `argparse` with subparsers for `baseline`, `monitor`, `replay`, `simulate`, `alert` commands. Each command maps to a handler function.

**Step 27 — `__main__.py`**: Entry point so `python -m ddosguard` works. Just imports and calls `main()` from `cli.py`.

**Step 28 — `config.yaml`**: YAML configuration with sections for capture, baseline, detection, mitigation, alerting, dashboard. Drives all behavior without code changes.

The key skill here is **argparse subparsers**:
```python
parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="command")
baseline = sub.add_parser("baseline")
baseline.add_argument("--seconds", type=int, default=600)
```

Each subparser gets its own arguments. The `dest="command"` tells argparse to put the chosen command name in `args.command`.

**Time**: ~35 minutes total for these three steps

---

## Phase 11: Testing & Polish

### Steps 29-31 Summary

**Step 29 — Detection tests** (`tests/test_detection.py`): Test each signal with controlled inputs. Test composite scorer with normal and attack traffic.

**Step 30 — Alert & firewall tests** (`tests/test_alert.py`, `tests/test_firewall.py`): Test dedup, rate limiting, rule generation per stage.

**Step 31 — Full suite**: Run all 19 tests. Verify CLI works.

```bash
python -m pytest tests/ -v
python -m ddosguard --help
```

**Time**: ~40 minutes total for these three steps

---

## Roadmap Summary

| Phase | Steps | Time | You Build |
|-------|-------|------|-----------|
| 1. Foundations | 1–3 | 35 min | Project structure, dependencies, git |
| 2. Data & Traffic | 4–6 | 1h 20min | Dataclasses, packets, synthetic generator |
| 3. Windowing | 7–9 | 1h 10min | Window aggregator, rolling window, tests |
| 4. Baseline | 10–12 | 1h 20min | Diurnal buckets, baseline store, tests |
| 5. Detection | 13–15 | 1h 5min | 5 signals, composite scorer |
| 6. Rate Limiting | 16–18 | 1h 20min | Token bucket, rate limiter, tests |
| 7. Firewall | 19 | 25 min | iptables-style rule generation |
| 8. Alerting | 20–22 | 1h 5min | AlertManager, AlertDirector |
| 9. Dashboard | 23–25 | 1h 35min | FastAPI, HTML/JS, MonitorRunner |
| 10. CLI | 26–28 | 35 min | argparse, `__main__.py`, config |
| 11. Polish | 29–31 | 40 min | Detection/alert/firewall tests, full suite |
| **TOTAL** | | **~13 hours** | |

---

## What You'll Know After Completing This

### Python
- Building multi-module packages with proper `__init__.py` exports
- Dataclasses, enums, properties, type hints, default factories
- ABCs (abstract base classes) for defining interfaces
- Generators (`yield`) for streaming data
- `collections.deque` for ring buffers
- `argparse` for CLI construction
- `threading` with `Event` and `Lock`
- `logging` for operational messages
- JSON/JSONL persistence
- Pydantic `BaseModel` for request validation

### Networking & Security
- IP packet structure (IP header, TCP/UDP headers, flags, payload)
- TCP handshake (SYN → SYN-ACK → ACK) and flags
- Three DDoS types: volumetric, protocol, application layer
- Diurnal patterns and why time matters for baselines
- Z-scores and statistical thresholds (mean + 2*stdev)
- Token bucket rate limiting (rate, burst, analytical refill)
- iptables rule structure (chains, conditions, actions)
- Alert dedup, cooldown, rate limiting
- Multi-channel alerting

### Engineering Practices
- Test-driven understanding: tests that define expected behavior
- Unit tests with no external dependencies
- pytest: discovery, assertions, approximate comparisons
- Dry-run patterns for safety-critical code
- Configuration-driven behavior (YAML config)
- Version control (git init, add, commit, push)
- Separation of concerns (detection vs mitigation vs alerting vs dashboard)

### Tooling
- Scapy for packet creation/inspection
- FastAPI for web APIs
- uvicorn for ASGI serving
- PyYAML for config files
- pytest for testing

---

*This guide teaches by making you do. The code is in `ddosguard/` if you need to compare, but the learning happens when you write it yourself. The Practice sections are where real understanding happens — don't skip them.*
