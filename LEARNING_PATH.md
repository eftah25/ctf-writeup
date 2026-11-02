# Learning Path: Build DDoS Detection & Mitigation From Scratch

**A complete beginner-to-advanced guide. You read every step top-to-bottom, write the code as you go, and answer the questions embedded in each step before moving on.**

> This guide does not tell you what to build and then give you the code.
>
> Each step is organized the same way:
> - **Motivation** — why this exists, what problem it solves
> - **Concepts** — the ideas, explained in plain language with worked examples
> - **Questions you would ask** — the things a beginner would wonder, with answers
> - **Build** — the code to write yourself, in order
> - **Practice** — break it, fix it, extend it
>
> Do not skip the "Questions" section. If you cannot answer those questions, you do not yet understand the step.

---

## Before You Start

### What "beginner" means here

You should be able to:
- Write a function: `def foo(x): return x + 1`
- Write a class: `class Foo: def __init__(self, x): self.x = x`
- Use `import`: `import math; math.sqrt(9)`
- Run a `.py` file from the terminal: `python foo.py`
- Open a terminal, `cd` to a folder, and run commands

If that list is unfamiliar, spend a few hours on a Python tutorial first, then come back. This guide assumes you can write basic Python but does not assume you know networking, statistics, or system administration.

### What you need installed

```
python --version     # should be 3.14+
pip --version
git --version
```

If any of those fail, install the missing tool first. On Windows with Python from python.org, `pip` is included. `git` is a separate install from git-scm.com.

### A note on Windows

This project runs on Windows. A few notes:
- Scapy works on Windows for creating/inspecting packets. Live packet capture needs Npcap — if you don't install it, the capture steps will fall back to synthetic generators, which is fine for learning.
- `iptables` commands in Step 19 are dry-run on Windows (no iptables on Windows). That's intentional — the rules are still generated correctly, and you learn the structure. On Linux you would run them for real.
- File paths use forward slashes in code (`data/baseline.json`) which works on any OS.

### How to use this guide

1. Read the entire step before writing any code.
2. Answer the "Questions you would ask" in your head or on paper. If you cannot, re-read the Concepts section.
3. Write the code. Type it. Do not copy-paste.
4. Run the verification command. It must succeed.
5. Do the Practice exercises.
6. Move to the next step.

Each step builds on the one before. If Step 7 doesn't work, Step 8 will not work either.

### Estimated time

| Your background | Time |
|---|---|
| Complete beginner (knows basic Python) | 40–60 hours |
| Knows Python, new to networking/stats | 15–25 hours |
| Knows Python + networking | 8–15 hours |

---

## Phase 1: Foundations (Steps 1–3)

### Step 1: Why a project needs a structure, and what structure

#### Motivation

You are about to write a Python project with many files. Without a standard layout, two problems hit you immediately:
1. Python doesn't know your folder is importable.
2. Other tools (installers, test runners, IDEs) don't know your project exists.

Both are solved by a few specific files in specific places.

#### Concepts

Python looks for packages by checking whether a folder contains `__init__.py`. If it does, that folder is a package. You can then write `import ddosguard` and Python finds `ddosguard/__init__.py`.

```
ddosguard/              ← folder
└── __init__.py         ← empty file, makes this a package
```

The `pyproject.toml` is the modern way to describe a Python project. It replaces the older `setup.py`. It says: "this is a project called ddosguard, here is its version, here are its dependencies, here is how to build it."

```toml
[project]
name = "ddosguard"
version = "0.1.0"
```

The `requirements.txt` is a flat list of pip packages. It's not read by Python at runtime. It's read by humans and by `pip install -r requirements.txt`. It answers the question: "what do I need to install before running this?"

#### Questions you would ask

**Q: Why not just put everything in one file?**
A: You could for a tiny script. But this project has 20+ modules, tests, config, and a dashboard. One file would be unreadable. More importantly, modules let different parts of the code have separate responsibilities — detection code shouldn't be mixed with CLI code.

**Q: Does `__init__.py` need to contain anything?**
A: No. An empty file works. Its presence is what matters. Later, you may add imports to it so that `from ddosguard import PacketRecord` works without the user needing to know the internal module structure.

**Q: What's the difference between `pyproject.toml` and `requirements.txt`?**
A: `pyproject.toml` describes the project itself (name, version, how to build it, what it depends on). `requirements.txt` is just a flat list of packages for pip to install. In this project, `pyproject.toml` lists no runtime dependencies (we use `requirements.txt` for that). This is a simplification for learning — real projects often put dependencies in `pyproject.toml`.

**Q: Why two dependency files?**
A: `pyproject.toml` is the official standard. `requirements.txt` is the legacy format that many deployment tools still expect. Having both is common. In this guide, `requirements.txt` is the one we actually use to install.

**Q: What happens if I forget `__init__.py`?**
A: Python treats the folder as a regular directory, not a package. `import ddosguard` fails with "ModuleNotFoundError".

#### Build

Create this structure:

```
ddosguard/
└── __init__.py          (empty file)
pyproject.toml
requirements.txt        (comment only, for now)
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

**`requirements.txt`**:
```
# Dependencies added in Step 2
```

#### Practice

1. Create the files above.
2. From the parent folder, run:
   ```
   python -c "import ddosguard; print(ddosguard.__file__)"
   ```
   You should see a path ending in `ddosguard/__init__.py`.
3. Delete `__init__.py`. Run the same command again. It should fail.
4. Restore `__init__.py`. The import should work again.

**Verify**: The import command succeeds and prints a path containing `ddosguard/__init__.py`.

**Time**: 15 minutes

---

### Step 2: Dependencies — why we need them and how pip works

#### Motivation

Python ships with a standard library: `os`, `json`, `datetime`, `dataclasses`, and so on. When you need something outside that — packet manipulation, a web server, a test runner — you use a third-party library. `pip` is the tool that downloads and installs those libraries.

#### Concepts

`pip install scapy` does three things:
1. Downloads the scapy package from PyPI (the Python Package Index).
2. Installs it into your Python's site-packages directory.
3. Makes it importable: `import scapy`.

After installation, every Python script you run can `import scapy`. The library is available globally for your user.

**Version specifiers**:
- `scapy>=2.5.0` — "at least 2.5.0, any newer version is fine"
- `scapy==2.5.0` — "exactly 2.5.0, no other version"
- `scapy~=2.5.0` — "2.5.0 or newer, but not 3.0"

We use `>=` because exact pinning causes dependency conflicts. If library A needs scapy 2.5 and library B needs scapy 2.6, exact pins break. With `>=`, pip finds a version that satisfies everyone.

**What each library does in this project**:

| Library | Installed for | Used in |
|---|---|---|
| scapy | Packet creation and inspection | Step 5 (explore packets), Step 6 (synthetic generator uses its types conceptually) |
| fastapi | Web API framework | Step 23 (dashboard API) |
| uvicorn | ASGI server that runs FastAPI | Step 23 (dashboard server) |
| pyyaml | Read/write YAML files | Step 28 (config file) |
| pytest | Running tests | Steps 9, 12, 18, and all test steps |

**A note on uvicorn[standard]**: The `[standard]` extra installs additional dependencies for the server (like `httptools` and `uvloop` on Linux, or equivalent on Windows). Without it, uvicorn works but may be slower. We include it for correctness.

#### Questions you would ask

**Q: Why not write everything from scratch?**
A: You could write your own HTTP server, your own YAML parser, your own test runner. You would spend months on things that already exist and are well-tested. Using established libraries is normal professional practice. The skill is knowing which library to use and how to use it correctly — not reinventing wheels.

**Q: What if pip install fails?**
A: Common causes: no internet, proxy issues, Python version too old, permission errors. On Windows without a virtual environment, pip installs to your user site-packages. If you get a permission error, try `pip install --user ...`. If it says "requirement already satisfied", the package is already installed.

**Q: Do I need to install these in a specific order?**
A: No. pip resolves dependencies automatically. `pip install a b c` works the same as three separate commands.

**Q: What is PyPI?**
A: The Python Package Index — the default repository pip pulls from. It's at pypi.org. When you run `pip install scapy`, pip queries PyPI for the scapy package.

**Q: Where do the packages actually go?**
A: In your Python installation's `site-packages` directory. You can see it with:
```
python -c "import site; print(site.getsitepackages())"
```
You normally don't need to know this. You just `import` the package by name.

#### Build

Install all dependencies in one command:

```
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

1. Run the pip install command above.
2. Verify each import works:
   ```
   python -c "import scapy; print('scapy OK')"
   python -c "import fastapi; print('fastapi OK')"
   python -c "import yaml; print('pyyaml OK')"
   python -c "import pytest; print('pytest OK')"
   ```
3. Break it intentionally: uninstall scapy with `pip uninstall scapy -y`, then try `python -c "import scapy"`. Observe the `ModuleNotFoundError`. Reinstall it.

**Verify**: All four imports succeed. The uninstall-then-reinstall cycle shows the expected error.

**Time**: 10 minutes (plus download time)

---

### Step 3: Git — why version control matters and what the basic commands do

#### Motivation

Without version control, you save files like `core.py`, `core_v2.py`, `core_final.py`, `core_REAL_final.py`. You lose track of what changed and when. Git records every change with a timestamp and a message, so you can always go back.

#### Concepts

The Git workflow has three states:

```
Working directory  →  git add  →  Staging area  →  git commit  →  Repository (permanent history)
```

- **Working directory**: your actual files on disk, where you edit.
- **Staging area**: a list of changes you've selected to include in the next commit. `git add` moves changes from working directory to staging.
- **Repository**: the permanent history. `git commit` takes everything in staging and saves it with a message.

Think of staging as a shopping cart. You put changes in the cart with `git add`. When you're ready, you check out with `git commit`.

**`.gitignore`**: A file that lists patterns for files Git should ignore. Without it, Git tries to track everything — cache files, editor config, build artifacts, environment files. Many of these should never be in version control.

**SSH vs HTTPS for remotes**: This project uses HTTPS with a token for GitHub. The remote URL looks like `https://github.com/user/repo.git`. SSH would be `git@github.com:user/repo.git`. HTTPS is simpler to set up if you have a token. SSH requires an SSH key. Either works; we use HTTPS here.

#### Questions you would ask

**Q: Why not just save copies of files?**
A: You could, but you lose the history. With Git, `git log` shows every change with a message. `git diff` shows exactly what changed between any two points. `git revert` undoes a commit. File copies don't give you any of that.

**Q: What does `git add -A` do?**
A: It stages all changes in the working directory — new files, modified files, deleted files. It's a shortcut. You can also add specific files: `git add ddosguard/core.py`.

**Q: What goes in a commit message?**
A: A short summary of what changed and why. Not "updated file" — that tells you nothing. Better: "Add PacketRecord dataclass with is_tcp and is_syn properties". The first line should be concise; if you need more, add a blank line and then details.

**Q: What if I commit something by mistake?**
A: `git revert <commit-hash>` creates a new commit that undoes the old one. The history still shows both commits, which is honest. `git reset` can also undo commits but rewrites history — more dangerous, use with care.

**Q: What is the difference between `git init` and `git clone`?**
A: `git init` creates a new empty repository in the current folder. `git clone` copies an existing repository from a remote (like GitHub) to your machine. This guide starts with `git init` because we're creating the project from scratch.

**Q: Why does .gitignore matter?**
A: Without it, `__pycache__` directories, `.pyc` files, virtual environments, and editor configs all get tracked. This bloats the repository and can expose secrets (like `.env` files). `.gitignore` keeps the repository clean.

#### Build

```
git init
git config user.name "Your Name"
git config user.email "you@example.com"
```

Create `.gitignore`:
```
__pycache__/
*.py[cod]
*.egg-info/
.eggs/
venv/
.venv/
.vscode/
.idea/
.DS_Store
Thumbs.db
data/
.env
.env.local
.pytest_cache/
.coverage
htmlcov/
*.log
logs/
```

Make the first commit:
```
git add -A
git commit -m "Initial project structure"
```

#### Practice

1. Run the commands above.
2. Check history: `git log --oneline`.
3. Modify `pyproject.toml` (add a comment line). Run `git status`. See the modified file listed as unstaged. Run `git add pyproject.toml` then `git status` again. See it as staged. Commit it.
4. Create `junk.txt`, add and commit it. Then `git rm junk.txt` and commit. Check `git log --oneline` — you'll see two new commits.

**Verify**: `git log --oneline` shows at least one commit. `git status` shows a clean working tree after commits.

**Time**: 10 minutes

---

## Phase 2: Data Models & Traffic (Steps 4–6)

### Step 4: Data classes — a cleaner way to hold data

#### Motivation

You will model network packets as Python objects. A packet has a timestamp, source IP, destination IP, protocol, ports, length, and flags. Without data classes, you write a lot of boilerplate to store and display these fields. Data classes automate that boilerplate.

#### Concepts

**The old way** (before data classes):

```python
class Packet:
    def __init__(self, ts, src_ip, dst_ip, protocol):
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol

    def __repr__(self):
        return f"Packet(ts={self.ts}, src={self.src_ip}, dst={self.dst_ip}, proto={self.protocol})"
```

You write `__init__` to store fields, `__repr__` to print them, `__eq__` if you want comparison. That's boilerplate — it's the same pattern for every data-holding class.

**The data class way**:

```python
from dataclasses import dataclass

@dataclass
class Packet:
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: int
```

The `@dataclass` decorator writes `__init__`, `__repr__`, `__eq__`, and a few other methods for you, based on the type-annotated fields.

**Type hints**: `ts: datetime` means "this field should be a datetime". Python doesn't enforce this at runtime (it will happily store a string), but tools like IDEs, type checkers (mypy), and readers benefit from knowing the intended type.

**Default values**:

```python
@dataclass
class Packet:
    protocol: int = 0          # default 0
    flags: str = ""            # default empty string
    length: int = 0            # default 0
```

Fields with defaults must come after fields without defaults.

**Mutable defaults — the trap**:

```python
# WRONG - every instance shares the SAME list
@dataclass
class Bad:
    items: list = []   # all instances share one list!

# RIGHT - each instance gets its own list
@dataclass
class Good:
    items: list = field(default_factory=list)
```

Python evaluates default values once at class definition time. `[]` creates one list object. Every `Bad()` instance gets that same list. `field(default_factory=list)` calls `list()` each time a new instance is created, giving each its own list.

**`@property`**: A method that reads like an attribute.

```python
@dataclass
class Packet:
    protocol: int = 0

    @property
    def is_tcp(self) -> bool:
        return self.protocol == 6
```

Usage: `pkt.is_tcp` — looks like accessing a field, but it's actually calling a method. This is useful for derived values (values computed from other fields).

**Enums**: Named constants. `Protocol.TCP` is clearer than the magic number `6`.

```python
from enum import IntEnum

class Protocol(IntEnum):
    OTHER = 0
    TCP = 6
    UDP = 17
    ICMP = 1
```

`IntEnum` means these are also integers — you can compare `Protocol.TCP == 6` and it's true. But `Protocol.TCP` prints as `Protocol.TCP`, not `6`, which is much more readable.

#### Questions you would ask

**Q: When should I use a dataclass vs a regular class?**
A: Use dataclass when the class mainly holds data with little or no custom behavior. Use a regular class when you need custom `__init__`, complex initialization, or significant methods. Dataclasses save boilerplate for data containers.

**Q: What if I need to validate a field?**
A: Dataclasses don't validate. You can add `__post_init__` to run code after `__init__`:

```python
@dataclass
class Packet:
    ts: datetime

    def __post_init__(self):
        if not isinstance(self.ts, datetime):
            raise TypeError(f"ts must be datetime, got {type(self.ts)}")
```

**Q: Why use IntEnum instead of just a regular Enum?**
A: `IntEnum` members are also integers. This means you can use them in places that expect integers (like indexing a list, or comparing to protocol numbers from Scapy). A regular `Enum` member is not an integer — `Protocol.TCP == 6` would be False.

**Q: Can a dataclass have methods?**
A: Yes. Any method works the same as in a regular class. The `@dataclass` decorator only affects the auto-generated `__init__`, `__repr__`, `__eq__`, etc. Your own methods are untouched.

**Q: What does `__repr__` do?**
A: It returns a string representation of the object, used when you `print(obj)` or type `obj` in the Python REPL. A good `__repr__` should be unambiguous and, ideally, show enough to recreate the object. Dataclasses generate one automatically.

#### Build

Add to `ddosguard/core.py` (create the file):

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

1. Write the code above in `ddosguard/core.py`.
2. Test it:
   ```
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
3. Add `is_udp` and `is_rst` properties yourself. Look at how `is_tcp` works — `is_udp` checks `protocol == Protocol.UDP`, `is_rst` checks `"R" in self.flags`.
4. Break it: try `PacketRecord(ts="not a date", ...)`. Observe the error (it will fail later when something tries to use the string as a datetime). The fix: always pass a real `datetime`.

**Verify**: The test prints the packet and shows `is_tcp: True`, `is_syn: True`.

**Time**: 30 minutes

---

### Step 5: What a network packet actually is

#### Motivation

You are building a DDoS detector. DDoS attacks are made of network packets. To detect them, you must understand what a packet contains — which fields tell you it's an attack, and which fields are normal.

#### Concepts

A packet is a structured chunk of bytes sent over a network. It has layers:

```
[ Ethernet header (14 bytes) ] [ IP header (20 bytes) ] [ TCP/UDP header (8-20 bytes) ] [ Payload (variable) ]
```

For this project, we care about the IP layer and the transport layer:

**IP header fields we use**:
- Source IP address (who sent it)
- Destination IP address (who it's for)
- Protocol number: `6` = TCP, `17` = UDP, `1` = ICMP

**TCP header fields we use**:
- Source port (which port on the sender)
- Destination port (which port on the receiver)
- Flags: control bits that say what kind of TCP message this is

**UDP header fields we use**:
- Source port
- Destination port
- (UDP has no flags — it's simpler than TCP)

**TCP flags and what they mean**:

| Flag letter | Name | Meaning |
|---|---|---|
| S | SYN | "I want to start a connection" — first packet of the three-way handshake |
| A | ACK | "I acknowledge your data" |
| SA | SYN-ACK | "I acknowledge your SYN and send my own SYN" — second step of handshake |
| F | FIN | "I'm done sending data" |
| R | RST | "Reset this connection immediately" |
| PA | PSH-ACK | "Here's data, and please deliver it now" |

**The TCP three-way handshake**:
1. Client → Server: SYN ("let's connect")
2. Server → Client: SYN-ACK ("OK, let's connect")
3. Client → Server: ACK ("confirmed")

A SYN flood attack sends step 1 many times but never sends step 3. The server allocates resources for each half-open connection. Too many half-open connections = server can't handle legitimate traffic.

**Three DDoS attack types**:

| Type | Mechanism | What the packets look like |
|---|---|---|
| Volumetric (UDP flood) | Saturate bandwidth with massive traffic | Many UDP packets, high byte count, random ports |
| Protocol (SYN flood) | Exhaust server connection state | Many TCP SYN packets, never completed handshakes |
| Application layer (HTTP flood) | Exhaust the application | Many TCP packets to port 80/443/8080 with data payloads |

#### Questions you would ask

**Q: Why do we need protocol numbers?**
A: The IP header has a "protocol" field that tells the receiver which transport layer protocol to use. 6 means "pass this to TCP", 17 means "pass this to UDP", 1 means "pass this to ICMP". Without it, the receiver wouldn't know how to interpret the rest of the packet.

**Q: What's the difference between a port and an IP address?**
A: An IP address identifies a device on the network (like a street address). A port identifies a specific service or application on that device (like an apartment number). `10.0.0.1:80` means "the HTTP service on device 10.0.0.1". Port 80 is HTTP, 443 is HTTPS, 22 is SSH, 53 is DNS.

**Q: Why are SYN floods effective?**
A: Each incoming SYN makes the server allocate memory for a half-open connection and wait for the ACK that completes the handshake. The server has limited memory and connection slots. If an attacker sends 10,000 SYNs per second and the server can only handle 1,000 connections, legitimate users can't connect.

**Q: What's the difference between volumetric and protocol attacks?**
A: Volumetric attacks try to fill the network pipe — the goal is bandwidth saturation. Protocol attacks target the server's ability to process connections — the goal is resource exhaustion. A volumetric attack needs high byte rates. A protocol attack needs high packet rates of a specific type (SYN).

**Q: Why do we model packets as dataclasses rather than raw bytes?**
A: Working with raw bytes requires parsing headers manually — error-prone and hard to read. A dataclass gives named fields: `pkt.src_ip`, `pkt.dst_port`, `pkt.flags`. The code is self-documenting. Later, if you load real pcap files, you parse the bytes into these dataclasses once, then work with the dataclasses everywhere.

#### Build

Write `explore_packets.py` at the project root (a temporary exploration script — you'll delete or ignore it later):

```python
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, RandIP, RandShort, sniff, conf

conf.verb = 0

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
print("TCP flags: S=SYN, A=ACK, R=RST, F=FIN, P=PSH")
```

#### Practice

1. Run `python explore_packets.py`. You should see three packet descriptions with IPs, ports, and flags.
2. Create a packet with `flags="SA"` (SYN-ACK). Print it. Notice it has both S and A flags — this is the server's response in the handshake.
3. Create a packet with `flags="R"` (RST). Print it. Notice only the R flag — this is a connection reset.
4. (Optional) Try `sniff(timeout=2, prn=describe)`. This captures live packets for 2 seconds. If Npcap isn't installed on Windows, this may fail with a permission error — that's expected. The synthetic generators in Step 6 don't need live capture.

**Verify**: The script prints three descriptions with correct IP/port/flag information.

**Time**: 20 minutes

---

### Step 6: Why we need a synthetic packet generator

#### Motivation

To test your detection system, you need packets. You could capture real traffic, but that requires network access, may contain sensitive data, and is hard to control (you can't make an attack happen on demand). A synthetic generator creates packets programmatically — you control exactly what traffic the detector sees.

#### Concepts

**The PacketSource interface (ABC)**:

An abstract base class defines what any packet source must provide, without saying how it provides it:

```python
from abc import ABC, abstractmethod

class PacketSource(ABC):
    @abstractmethod
    def iter_packets(self, window_seconds, delay=0.0):
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...
```

Any class that inherits from `PacketSource` must implement `iter_packets()` and `name`. Code that uses a `PacketSource` doesn't care what concrete type it is — it just calls `iter_packets()`. This lets you swap a synthetic generator for a real pcap reader later without changing the detection code.

**Generators (`yield`)**:

A function that uses `yield` instead of `return` is a generator. Each time `yield` is hit, it produces a value and pauses. The caller gets one value at a time:

```python
def count_to_three():
    yield 1
    yield 2
    yield 3

for n in count_to_three():
    print(n)   # prints 1, 2, 3
```

Compare to returning a list:

```python
def count_to_three_list():
    return [1, 2, 3]   # builds the entire list in memory first
```

For 10,000 packets, a list uses memory for all 10,000 at once. A generator uses memory for one packet at a time. For a long-running monitor, generators are essential.

**Diurnal patterns**:

Network traffic varies by time of day. A web server has more traffic during business hours than at 3am. A synthetic generator should reflect this, because the baseline system (Step 11) will learn these patterns. If the generator only produces constant-rate traffic, the baseline won't learn time-based patterns, and the detector won't be tested against realistic scenarios.

Our generator uses a simple diurnal model:
- 8am–8pm (daytime): 1.5x base rate
- 6am–8am and 8pm–10pm (shoulder): 1.0x base rate
- Everything else (night): 0.4x base rate

**Attack families**:

The generator produces three attack types, each with a distinct packet signature:
- **Volumetric** (UDP flood): UDP packets with large payloads, random destination ports
- **SYN flood**: TCP SYN packets to port 80, no payload
- **Application layer**: TCP packets to port 8080 with small data payloads

Each has a different `attack_mult` (how many times above normal) and different packet characteristics.

#### Questions you would ask

**Q: Why not just read a pcap file?**
A: You could, and later you might. But pcaps require you to have captured traffic, which means you need a network interface in capture mode, which on Windows requires Npcap, and the traffic is whatever happened to be on the network — you can't control when an attack occurs. A synthetic generator gives you repeatable, controlled test scenarios. A pcap reader is a nice addition later (it would also implement `PacketSource`).

**Q: What does `yield from` do?**
A: It delegates to another generator. `yield from self._attack(...)` means "yield all values from the _attack generator". It's equivalent to:

```python
for pkt in self._attack(window_seconds, now):
    yield pkt
```

But shorter and slightly more efficient.

**Q: Why are base_rate and attack_mult separate?**
A: `base_rate` is the normal traffic level (packets per second). `attack_mult` is how many times above normal the attack is. If base_rate is 50 and attack_mult is 20, the attack generates 50 * 20 = 1000 packets per second. Separating them lets you test different base rates with the same attack multiplier.

**Q: What's the difference between `mode="normal"` and `mode="attack"`?**
A: In `normal` mode, the generator always produces normal traffic (with diurnal variation). In `attack` mode, it produces attack traffic during the `attack_start` to `attack_end` window, and normal traffic outside that window. This lets you test the detector's response to an attack starting at a specific time.

**Q: Why do we track `src_ip_base` separately from `dst_ip`?**
A: In a realistic scenario, many sources send traffic to one destination (the target). `src_ip_base` is the network the sources are on (e.g., "192.168.1"), and each packet gets a random host from that network. `dst_ip` is the single target all traffic goes to. This models an attack where many machines flood one target.

#### Build

Create `ddosguard/capture/__init__.py` (empty) and `ddosguard/capture/base.py`:

```python
from __future__ import annotations
import random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Iterator
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
        if 8 <= hour < 20:
            mult = 1.5
        elif 6 <= hour < 8 or 20 <= hour < 22:
            mult = 1.0
        else:
            mult = 0.4
        target = int(self.base_rate * mult * window_seconds)
        ports = [80, 443, 22, 53, 8080, 3306, 5432]
        protos = [Protocol.TCP] * 70 + [Protocol.UDP] * 25 + [Protocol.ICMP] * 5
        for _ in range(target):
            ts = now - timedelta(seconds=random.uniform(0, window_seconds))
            proto_choice = random.choice(protos)
            flags = random.choice(["S", "SA", "PA", "A", "F", "R"]) if proto_choice == Protocol.TCP else ""
            yield PacketRecord(
                ts=ts,
                src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                dst_ip=self.dst_ip,
                protocol=proto_choice,
                src_port=random.randint(1024, 65535),
                dst_port=random.choice(ports),
                length=random.randint(40, 1500),
                flags=flags,
            )

    def _attack(self, window_seconds, now):
        target = int(self.base_rate * self.attack_mult * window_seconds)
        if self.attack_family == "volumetric":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0, 1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                    dst_ip=self.dst_ip,
                    protocol=Protocol.UDP,
                    src_port=random.randint(1024, 65535),
                    dst_port=random.randint(1, 65535),
                    length=random.randint(512, 1500),
                    flags="",
                )
        elif self.attack_family == "syn_flood":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0, 1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                    dst_ip=self.dst_ip,
                    protocol=Protocol.TCP,
                    src_port=random.randint(1024, 65535),
                    dst_port=80,
                    length=64,
                    flags="S",
                )
        elif self.attack_family == "application":
            for _ in range(target):
                yield PacketRecord(
                    ts=now - timedelta(seconds=random.uniform(0, 1)),
                    src_ip=f"{self.src_ip_base}.{random.randint(1, 254)}",
                    dst_ip=self.dst_ip,
                    protocol=Protocol.TCP,
                    src_port=random.randint(1024, 65535),
                    dst_port=8080,
                    length=random.randint(200, 500),
                    flags="PA",
                )
```

#### Practice

1. Write the code above in `ddosguard/capture/base.py`. Make sure `ddosguard/capture/__init__.py` exists.
2. Test normal mode:
   ```
   python -c "
   from ddosguard.capture.base import SyntheticGenerator
   gen = SyntheticGenerator(mode='normal', base_rate=100)
   pkts = list(gen.iter_packets(1.0))
   print(f'{len(pkts)} packets in 1 second')
   print(f'Sample: {pkts[0].src_ip} -> {pkts[0].dst_ip} proto={pkts[0].protocol.name}')
   "
   ```
   Expected: around 150 packets (100 * 1.5 diurnal multiplier for daytime).
3. Test attack mode (SYN flood):
   ```
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
   Expected: around 5000 packets (50 * 50 * 2), almost all SYN.
4. Extend: add an `icmp_flood` attack family that generates ICMP packets. Add a new `elif self.attack_family == "icmp_flood":` branch that yields `Protocol.ICMP` packets. Test it.

**Verify**: Normal mode produces ~150 packets/sec. SYN flood produces thousands of SYN packets.

**Time**: 30 minutes

---

## Phase 3: Windowing & Metrics (Steps 7–9)

### Step 7: Why we need time windows

#### Motivation

A single packet tells you almost nothing. A SYN packet is normal — your browser sends one every time you visit a website. A million SYN packets in 10 seconds is an attack. The difference is not in any individual packet — it's in the rate over time.

Time windows let you aggregate packets over a fixed period and compute statistics for that period. Then you compare those statistics to a baseline to decide if the traffic is normal or suspicious.

#### Concepts

**The window lifecycle**:

1. Create a window (start time = now).
2. For each incoming packet, add it to the window (increment counts, update end time).
3. When enough time has passed (e.g., 10 seconds), the window is "complete."
4. Call `finalize()` — this computes the statistics and returns a snapshot.
5. Create a new window for the next period.

```
Time:    |---- 10 sec ----|---- 10 sec ----|---- 10 sec ----|
Window:  [ Window 1 ]     [ Window 2 ]     [ Window 3 ]
Stats:   [ stats 1 ]       [ stats 2 ]       [ stats 3 ]
```

**What a TrafficWindow accumulates**:
- `packet_count`: total packets seen
- `byte_count`: total bytes (sum of packet lengths)
- `protocol_counts`: how many of each protocol (TCP, UDP, ICMP)
- `syn_count`: how many packets had the SYN flag
- `rst_count`: how many packets had the RST flag
- `src_ports`: how many packets per source port
- `dst_ports`: how many packets per destination port

**What TrafficStats computes from the window**:
- `packet_rate`: packets per second = packet_count / window_duration
- `byte_rate`: bytes per second = byte_count / window_duration
- `syn_ratio`: fraction of packets that are SYN = syn_count / packet_count
- `per_proto`: protocol counts as a dict (converted from Protocol enum to integer keys)

**The finalize pattern**:

```python
class WindowAggregator:
    def add(self, pkt):
        if self._window is None:
            self._window = TrafficWindow(start=pkt.ts, end=pkt.ts)
        self._window.add(pkt)
        self._window.end = pkt.ts

    def is_complete(self, pkt_ts):
        if self._window is None:
            return False
        return (pkt_ts - self._window.start).total_seconds() >= self.window_seconds

    def finalize(self):
        if self._window is None:
            raise RuntimeError("No window to finalize")
        stats = self._window.finalize()
        self._window = None  # reset for next window
        return stats
```

The window object is replaced (set to `None`) after finalization. The next packet creates a fresh window.

**Why separate collection and analysis**:

`TrafficWindow.add()` just counts — it knows nothing about detection. `TrafficStats` is computed once at finalize time — it's a snapshot. This separation means:
- You can test counting logic without detection logic.
- You can test detection logic with pre-built stats (no need to simulate packets).

#### Questions you would ask

**Q: Why not just count packets continuously?**
A: You can — that's what byte_rate and packet_rate are. But you need a defined period to compute a rate. If you count "since the start," the rate changes every second as the denominator grows. A window gives you a fixed denominator: "packets in the last 10 seconds." This is stable and comparable across windows.

**Q: What window size should I use?**
A: Shorter windows (1–5 seconds) catch attacks faster but are noisier — a brief spike might trigger a false alarm. Longer windows (30–60 seconds) are smoother but react slower. This project uses 10 seconds as a default — a compromise. Production systems often use multiple window sizes in parallel.

**Q: Why track syn_count and rst_count separately?**
A: SYN count is the key signal for SYN flood detection. RST count can indicate a different kind of attack (RST floods to tear down legitimate connections, or to probe the network). Tracking them separately lets the SYN signal (Step 14) look at syn_ratio without being affected by other packet types.

**Q: What happens if a window has zero packets?**
A: `packet_rate` is 0. `syn_ratio` is 0 (we guard against division by zero: `if packet_count else 0.0`). `byte_rate` is 0. A zero-packet window is normal during quiet periods — it shouldn't trigger detection.

**Q: Why does `is_complete` take a `pkt_ts` argument instead of checking `datetime.now()`?**
A: It should check the packet's timestamp, not the current time. Packets might be processed out of order, or there might be a delay between capture and processing. Using the packet's own timestamp means the window is based on when the packets actually arrived (in packet time), not when the code runs (in wall clock time).

#### Build

First, add `TrafficWindow` and `TrafficStats` to `ddosguard/core.py` (after `PacketRecord`):

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

Then create `ddosguard/metrics/__init__.py` (empty) and `ddosguard/metrics/window.py`:

```python
from __future__ import annotations
from ddosguard.core import PacketRecord, TrafficStats, TrafficWindow

class WindowAggregator:
    def __init__(self, window_seconds=10.0):
        self.window_seconds = window_seconds
        self._window: TrafficWindow | None = None
        self._first_ts: datetime | None = None

    def add(self, pkt: PacketRecord) -> None:
        if self._window is None:
            self._window = TrafficWindow(start=pkt.ts, end=pkt.ts)
            self._first_ts = pkt.ts
        self._window.add(pkt)
        self._window.end = pkt.ts

    def is_complete(self, pkt_ts: datetime) -> bool:
        if self._window is None or self._first_ts is None:
            return False
        return (pkt_ts - self._first_ts).total_seconds() >= self.window_seconds

    def finalize(self) -> TrafficStats:
        if self._window is None:
            raise RuntimeError("No window to finalize")
        stats = self._window.finalize()
        self._window = None
        self._first_ts = None
        return stats

    def reset(self) -> None:
        self._window = None
        self._first_ts = None
```

#### Practice

1. Add both the `core.py` additions and the new `metrics/window.py` file.
2. Test with synthetic traffic:
   ```
   python -c "
   from ddosguard.metrics.window import WindowAggregator
   from ddosguard.capture.base import SyntheticGenerator

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
   Expected: around 200–300 pps depending on time of day.
3. Break it: create a `WindowAggregator`, don't add any packets, call `finalize()`. It raises `RuntimeError("No window to finalize")`. This is the correct behavior — you can't finalize an empty window.
4. Experiment: change `window_seconds=0.5`. Rerun. Notice the stats change more erratically — shorter windows = noisier data.

**Verify**: The test prints window stats with packet rate around the base_rate.

**Time**: 20 minutes

---

### Step 8: Rolling windows — seeing trends

#### Motivation

A single window tells you the current rate. But attacks don't always start at full intensity — they ramp up. A rolling window keeps the last several window snapshots so you can see whether traffic is increasing, decreasing, or stable. This catches attacks in their early ramp-up phase.

#### Concepts

**Fixed windows vs rolling windows**:

Fixed windows (Step 7): each window is independent. Window 1 covers seconds 0–10, window 2 covers seconds 10–20. You get a sequence of independent snapshots.

Rolling windows: keep the last N snapshots in a buffer. From the buffer, you can compute:
- **Mean rate**: average of the last N windows — smoother than any single window
- **Max rate**: highest rate in the last N windows — catches the peak
- **Trend**: last window rate minus first window rate — is traffic going up or down?

**The ring buffer**:

```python
from collections import deque

buffer = deque(maxlen=5)   # holds at most 5 items
buffer.append(1)
buffer.append(2)
buffer.append(3)
buffer.append(4)
buffer.append(5)
buffer.append(6)   # 1 falls off, buffer is now [2, 3, 4, 5, 6]
```

`deque(maxlen=N)` automatically discards the oldest item when you append the (N+1)th item. This is perfect for "keep the last N windows."

**Why trend matters**:

If an attack starts at 100 pps and ramps to 1000 pps over 5 windows, each individual window might be below your detection threshold. But the trend (last - first) is 900 pps — a clear signal that something is escalating, even if no single window is alarming.

#### Questions you would ask

**Q: Why not just use a longer fixed window?**
A: A longer window averages over more time, which smooths noise but also delays detection. A rolling window of short windows gives you both: short windows for responsiveness, and the rolling buffer for smoothing. You get fast detection without as much noise.

**Q: What does `add_and_commit` do differently from `add`?**
A: `add()` just adds a packet to the current window. `add_and_commit()` adds a packet, then checks if the window is complete. If it is, it finalizes the window, adds it to the rolling buffer, and starts a new window. It returns the finalized stats (or `None` if the window isn't complete yet).

**Q: What happens when the buffer is empty?**
A: `mean_rate` returns 0, `max_rate` returns 0, `trend` returns 0. The code checks `if not self._buffer` before computing. This is the correct behavior — no data means no trend information.

**Q: Why is trend computed as last - first instead of using all windows?**
A: First-last gives a simple directional indicator: positive = increasing, negative = decreasing, near zero = stable. A more sophisticated approach would fit a line to all windows (linear regression), but first-last is simpler and works well enough for detection purposes. The key insight is direction, not exact slope.

**Q: Should I use mean_rate or max_rate for detection?**
A: Different purposes. `mean_rate` smooths out spikes — good for baseline comparison (is the average traffic higher than normal?). `max_rate` catches the peak — good for triggering urgent alerts (did traffic just spike?). In this project, both are available for the dashboard; detection uses the composite scorer (Step 15), which considers multiple factors.

#### Build

Add to `ddosguard/metrics/window.py`:

```python
from collections import deque

class RollingAggregator:
    def __init__(self, window_seconds=10.0, num_windows=5):
        self.window_seconds = window_seconds
        self.num_windows = num_windows
        self._buffer: deque = deque(maxlen=num_windows)
        self._current = WindowAggregator(window_seconds)
        self._first_ts: datetime | None = None

    def add(self, pkt: PacketRecord) -> None:
        if self._first_ts is None:
            self._first_ts = pkt.ts
        self._current.add(pkt)

    def add_and_commit(self, pkt: PacketRecord) -> TrafficStats | None:
        self.add(pkt)
        if self._current is not None and self._first_ts is not None \
           and (pkt.ts - self._first_ts).total_seconds() >= self.window_seconds:
            stats = self._current.finalize()
            self._buffer.append(stats)
            self._current = WindowAggregator(self.window_seconds)
            self._first_ts = pkt.ts
            return stats
        return None

    @property
    def mean_rate(self) -> float:
        if not self._buffer:
            return 0.0
        return sum(w.packet_rate for w in self._buffer) / len(self._buffer)

    @property
    def max_rate(self) -> float:
        if not self._buffer:
            return 0.0
        return max(w.packet_rate for w in self._buffer)

    @property
    def trend(self) -> float:
        if len(self._buffer) < 2:
            return 0.0
        return self._buffer[-1].packet_rate - self._buffer[0].packet_rate
```

#### Practice

1. Add the code above to `metrics/window.py`.
2. Test it:
   ```
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
3. Break it: create a `RollingAggregator` and immediately check `mean_rate`. It should be `0.0` (no windows in the buffer yet).
4. Experiment: create `RollingAggregator(window_seconds=0.5, num_windows=3)`. Feed it packets. Notice the buffer fills faster (shorter windows) but holds fewer snapshots.

**Verify**: Mean around 100–150 pps. Trend near zero (normal traffic doesn't trend).

**Time**: 20 minutes

---

### Step 9: Why and how to write tests

#### Motivation

Every piece of code you write can be wrong. Tests catch mistakes early, before they compound into harder-to-find bugs. Tests also serve as documentation: a test named `test_syn_tracked` tells the reader "this code is supposed to count SYN packets."

#### Concepts

**What pytest does**:

pytest scans your `tests/` directory for files named `test_*.py` and functions/classes named `test_*`. It runs each one. An `assert` statement that fails marks the test as failed. All other tests still run.

```python
def test_add_increments_count():
    agg = WindowAggregator(10.0)
    agg.add(mk(datetime.now()))
    assert agg._window.packet_count == 1   # if this is False, the test fails
```

**Helper functions to reduce repetition**:

```python
def mk(ts, proto=Protocol.TCP, flags="", length=100):
    return PacketRecord(ts=ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                        protocol=proto, src_port=12345, dst_port=80,
                        length=length, flags=flags)
```

Instead of writing 5 lines to create a packet in every test, you write one helper. When you need to change the defaults, you change them in one place.

**`pytest.approx` for floating point**:

```python
assert value == pytest.approx(200, abs=1)   # value is within 1 of 200
```

Floating point arithmetic is imprecise. `0.1 + 0.2 == 0.3` is False in Python. `pytest.approx` handles this by checking "close enough" rather than exact equality.

**"No network, no permissions" tests**:

These tests use only in-memory data. They don't:
- Touch the network (no sockets, no HTTP requests)
- Read or write files (except temp files created for the test, like in persistence tests)
- Need special OS permissions (no admin/root)

This means they run on any machine, in any environment, without setup. They're fast and reliable.

**Edge cases to test**:

| Situation | Why test it |
|---|---|
| Empty input | Does the code handle zero packets gracefully? |
| Single item | Does one packet produce the right counts? |
| Max/near-max values | Does the code handle large numbers without overflow? |
| Boundary conditions | Does `is_complete` trigger at exactly `window_seconds`? |

#### Questions you would ask

**Q: Why not just run the code and look at the output?**
A: You could for one-off checks, but tests are repeatable and automated. If you change the code later, running the tests tells you if you broke something — without manually re-checking output. A test suite that runs in 5 seconds and passes gives confidence that the code works.

**Q: What's the difference between a unit test and an integration test?**
A: A unit test checks one small piece of code in isolation (e.g., does `WindowAggregator.add()` increment the count?). An integration test checks multiple pieces working together (e.g., does the detector correctly flag attack traffic from the synthetic generator?). This guide starts with unit tests (simpler, faster) and the full pipeline test at the end acts as an integration test.

**Q: How many tests should I write?**
A: Enough to cover the important behaviors and edge cases. Not every line needs a test, but every behavior should have at least one test that exercises it. The test names should tell you what's being tested — if you can't name the behavior, it might not be well-defined.

**Q: What if a test fails?**
A: Read the failure message. pytest tells you which assert failed and what the actual vs expected values were. Fix the code so the test passes. If the test itself is wrong, fix the test. A failing test is information — it tells you something is wrong.

**Q: Should tests be in the same folder as the code?**
A: Convention is a `tests/` folder at the project root, mirroring the package structure. `tests/test_metrics.py` tests `ddosguard/metrics/`. This keeps tests separate from production code but easy to find.

#### Build

Create `tests/__init__.py` (empty) and `tests/test_metrics.py`:

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
        for window_idx, rate in enumerate([10, 20, 30]):
            for i in range(rate):
                roll.add_and_commit(mk(base + timedelta(seconds=window_idx + i*0.1)))
        assert roll.trend > 0

    def test_trend_down(self):
        roll = RollingAggregator(1.0, 3)
        base = datetime.now()
        for window_idx, rate in enumerate([30, 20, 10]):
            for i in range(rate):
                roll.add_and_commit(mk(base + timedelta(seconds=window_idx + i*0.1)))
        assert roll.trend < 0
```

#### Practice

1. Create `tests/` with `__init__.py` and `test_metrics.py`.
2. Run the tests: `python -m pytest tests/test_metrics.py -v`. All should pass.
3. Break a test intentionally: change `assert stats.window.packet_count == 10` to `== 9` in `test_finalize_gives_stats`. Run the tests. The test should fail with a clear message showing expected 9 but got 10. Fix it back to 10.
4. Write your own test: add a test that checks `is_complete` returns `False` when packets haven't spanned the full window duration.

**Verify**: All tests pass. You added at least one test yourself.

**Time**: 30 minutes

---

## Phase 4: Baseline System (Steps 10–12)

### Step 10: What a baseline is and why time matters

#### Motivation

To detect abnormal traffic, you need to know what normal traffic looks like. A baseline is a model of normal traffic: "at this time of day, the expected packet rate is X packets/sec, with a typical variation of Y."

Without a baseline, you have no reference point. You might see 500 pps and think it's high, but if the server normally handles 1000 pps at this hour, 500 is actually low. The baseline gives you context.

#### Concepts

**Why time of day matters**:

Network traffic is not constant. A public web server might have:
- 2am: 50 pps (almost no one is browsing)
- 10am: 500 pps (morning rush)
- 2pm: 800 pps (peak afternoon)
- 6pm: 300 pps (people go home)

If you average all of these into one "normal" value (410 pps), then at 2am, 50 pps looks like an anomaly (z-score would be very negative). At 2pm, 800 pps looks normal, but 1000 pps wouldn't trigger because the average is too high.

The solution: separate baselines for different times. This project uses **diurnal buckets** — one bucket per hour, split by weekday vs weekend.

**Diurnal buckets**:

```
Bucket key format: "{weekday|weekend}-{hour}"
Examples:
  weekday-8    = Monday-Friday at 8am
  weekday-14   = Monday-Friday at 2pm
  weekend-3    = Saturday-Sunday at 3am
```

Each bucket stores observed traffic statistics for that time slot. Over time, the bucket builds up a model of what traffic looks like at that hour.

**Z-score**:

How far is a value from the average, measured in standard deviations?

```
z = (value - mean) / stdev
```

Examples with mean=1000, stdev=100:
- value=1000: z = 0 (exactly average)
- value=1100: z = 1 (one stdev above — normal variation)
- value=1200: z = 2 (two stdev above — unusual, start watching)
- value=1300: z = 3 (three stdev above — very unusual, likely anomalous)
- value=1500: z = 5 (five stdev above — extreme)

**How z-score relates to alerts**:

A common rule: z > 2 means "this is statistically unusual." It doesn't guarantee an attack, but it warrants investigation. In this project, we translate z-scores into signal scores (Step 14) and composite severity (Step 15).

**Standard deviation (stdev)**:

A measure of how spread out the data is. Low stdev means most values are close to the mean. High stdev means values vary widely.

```
stdev = sqrt(sum((value - mean)^2) / (n - 1))
```

Why `n-1` (sample stdev) instead of `n` (population stdev)? Because we're estimating from a sample of observations, not the full population. `n-1` gives an unbiased estimate.

**Percentiles**:

The p50 (median) is the value below which 50% of observations fall. p95 is the value below which 95% fall — this is used to understand the upper range of normal traffic. If p95 = 1200 pps, then 95% of the time, traffic is below 1200 pps.

#### Questions you would ask

**Q: Why use z-score instead of just comparing to the mean?**
A: The mean alone doesn't tell you about variation. If mean=1000 and stdev=10, then 1100 is very unusual (z=10). If mean=1000 and stdev=200, then 1100 is normal (z=0.5). Z-score accounts for both the average and the spread.

**Q: What if I don't have enough data for a bucket yet?**
A: With 0 or 1 observations, stdev is 0 or undefined. In this project, `expected()` returns 0 if the bucket doesn't exist, and `expected_with_stdev()` returns (0, 0). This means early on, the detector won't flag anything based on baselines (since there's no baseline to compare against). The system needs a "warm-up" period to collect baseline data before it can detect anomalies. In production, you might start with a pre-trained baseline or use a default conservative threshold.

**Q: How many observations do I need for a reliable baseline?**
A: More is better. With 10 observations, the mean is rough and stdev is unreliable. With 100+, both are fairly stable. With 1000 (our reservoir limit), the statistics are quite stable. In practice, you collect baseline data over days or weeks to build reliable diurnal patterns.

**Q: What about holidays or special events?**
A: A weekday bucket might not match a holiday. Real systems handle this with more granular buckets (e.g., "holiday" as a separate category) or by gradually adapting the baseline. This project keeps it simple with weekday/weekend. In production, you'd add more categories.

**Q: What's the difference between p50 and mean?**
A: The mean is the arithmetic average — sum all values, divide by count. The p50 (median) is the middle value when sorted. If traffic is [100, 100, 100, 100, 1000], the mean is 280 but the median is 100. The mean is pulled up by the outlier; the median isn't. Both are useful: mean for "typical total load", median for "typical individual observation."

#### Practice — answer before reading

Answer these on paper before reading the answers:

1. Baseline for weekday-14: mean=1000 pps, stdev=100 pps. What's the z-score for 1300 pps?
2. Same baseline. At what packet rate does z exceed 2 (the "unusual" threshold)?
3. Why can't we use a single baseline for all 24 hours?

<details>
<summary>Answers</summary>

1. z = (1300 - 1000) / 100 = 3.0. Three standard deviations above normal — very unusual.
2. z > 2 when value > mean + 2*stdev = 1000 + 200 = 1200 pps.
3. Because traffic varies by time of day. A single average would be wrong for most hours. 2am traffic (50 pps) and 2pm traffic (800 pps) can't share a baseline.

</details>

**Time**: 10 minutes

---

### Step 11: The baseline store — observing, querying, persisting

#### Motivation

The baseline store is the component that maintains diurnal buckets, accepts observations from the windowing system, answers "what's normal right now?", and saves/loads from disk so the baseline survives restarts.

#### Concepts

**Bucket key computation**:

```python
def _bucket_key(self, ts: datetime) -> str:
    weekday = ts.weekday() < 5   # Monday=0, Sunday=6
    hour = ts.hour
    prefix = "weekday" if weekday else "weekend"
    return f"{prefix}-{hour}"
```

`datetime.weekday()`: Monday is 0, Sunday is 6. So `weekday < 5` means Monday through Friday.

**Observing traffic**:

Each time a window is finalized, we observe three metrics:
- `packet_rate`: packets per second in this window
- `byte_rate`: bytes per second in this window
- `syn_ratio`: fraction of packets that are SYN

Each metric gets its own bucket entry: `"weekday-14:packet_rate"`, `"weekday-14:byte_rate"`, `"weekday-14:syn_ratio"`.

**Querying the expected value**:

```python
def expected(self, metric: str, ts: datetime) -> float:
    key = f"{self._bucket_key(ts)}:{metric}"
    if key in self.buckets:
        return self.buckets[key].mean
    return 0.0
```

Given a metric name and a timestamp, compute the bucket key, look up the bucket, return the mean. If the bucket doesn't exist (no data yet), return 0.

**Persistence**:

The store saves all buckets to `data/baseline.json` as a JSON file. Each bucket entry stores mean, stdev, count, percentiles, and the raw samples. On load, it reconstructs the `BaselineStats` objects from the JSON.

Why save the samples? Because the statistics (mean, stdev, percentiles) are computed from the samples. If we only saved the statistics, we couldn't add new observations later (we'd need the raw samples to recompute). By saving samples, we can load the baseline, add more observations, and recompute.

**Reservoir sampling**:

We keep at most 1000 samples per bucket. When a new sample arrives and the reservoir is full, the oldest sample is evicted (FIFO — first in, first out). This bounds memory usage while keeping a representative recent sample.

This is a simplification — true reservoir sampling gives each item an equal probability of being in the reservoir regardless of order. FIFO is simpler and works well enough when observations arrive in chronological order (which they do in this system).

#### Questions you would ask

**Q: Why save to JSON instead of a database?**
A: JSON is simple and portable. For this project's scale (a few hundred buckets, each with 1000 samples), JSON is fast enough and easy to inspect (you can open it in a text editor). A database would be overkill. If the project grew to millions of buckets, you'd switch to a database.

**Q: What happens when the baseline is loaded from a file?**
A: The `load()` method reads `baseline.json`, parses the JSON, and reconstructs `BaselineStats` objects for each bucket. After loading, `expected()` returns the stored mean values. The system can resume detecting anomalies immediately after a restart, without re-learning the baseline from scratch.

**Q: Why is there a `set_ready()` method?**
A: The store starts with `_ready = False`. Code that uses the store can check `is_ready` before querying. This prevents the detector from using the baseline before it's been loaded or before the system has warmed up. In the full pipeline (Step 25), the runner sets `ready = True` after the baseline is loaded.

**Q: What if two observations arrive for the same bucket at the same time?**
A: Each observation is processed sequentially (in the single-threaded monitor loop, Step 25). There's no race condition. In a multi-threaded system, you'd need a lock. This project's architecture (single monitor thread) avoids that complexity.

**Q: Why track syn_ratio as a baseline metric?**
A: Normal traffic has a certain SYN ratio (typically low — most packets are data, not handshakes). An attack might have a very high SYN ratio (SYN flood). By baselining syn_ratio, the detector can tell whether a high SYN ratio is normal for this time of day or anomalous. For example, if a legitimate service does a lot of connection setup at 9am, the SYN ratio at 9am might be higher than at 3pm. The baseline captures that.

#### Build

Add `BaselineStats` to `ddosguard/core.py`:

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
        self.stdev = (sum((v - self.mean) ** 2 for v in self.samples) / (n - 1)) ** 0.5 if n > 1 else 0.0
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

Create `ddosguard/baseline/__init__.py` (empty) and `ddosguard/baseline/store.py`:

```python
from __future__ import annotations
import json
import os
from datetime import datetime
from typing import Dict
from ddosguard.core import BaselineStats, TrafficStats
from ddosguard.config import Config

class BaselineStore:
    def __init__(self, config: Config, data_dir: str = "data"):
        self.config = config
        self.data_dir = data_dir
        self.buckets: Dict[str, BaselineStats] = {}
        self._ready = False

    def set_ready(self, ready: bool) -> None:
        self._ready = ready

    @property
    def is_ready(self) -> bool:
        return self._ready

    def _bucket_key(self, ts: datetime) -> str:
        weekday = ts.weekday() < 5
        hour = ts.hour
        prefix = "weekday" if weekday else "weekend"
        return f"{prefix}-{hour}"

    def observe(self, stats: TrafficStats, ts: datetime) -> None:
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

    def save(self) -> None:
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

    def load(self) -> None:
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

#### Practice

1. Add `BaselineStats` to `core.py`. Create `baseline/__init__.py` and `baseline/store.py`.
2. Test the store:
   ```
   python -c "
   from ddosguard.baseline.store import BaselineStore
   from ddosguard.config import Config
   from ddosguard.core import TrafficStats, TrafficWindow
   from datetime import datetime, timedelta

   config = Config.load(None)
   store = BaselineStore(config, data_dir='data')
   store.set_ready(True)

   now = datetime.now()
   for i in range(10):
       ts = now + timedelta(seconds=i*10)
       w = TrafficWindow(start=ts - timedelta(seconds=10), end=ts)
       for j in range(50):
           w.add(type('P', (), {'ts': ts, 'length': 100, 'protocol': 6,
                                 'is_syn': False, 'is_rst': False,
                                 'src_port': 12345, 'dst_port': 80,
                                 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2'})())
       store.observe(w.finalize(), ts)

   print(f'Buckets: {len(store.all())}')
   print(f'Expected packet_rate: {store.expected(\"packet_rate\", datetime.now()):.2f}')
   store.save()
   print('Saved to data/baseline.json')

   store2 = BaselineStore(config, data_dir='data')
   store2.load()
   print(f'After reload: {store2.expected(\"packet_rate\", datetime.now()):.2f}')
   "
   ```
3. Break it: call `store.expected("packet_rate", datetime.now())` before observing anything. It should return `0.0` (no baseline data yet).
4. Experiment: observe with different rates (50, 100, 150 pps) and check how the mean changes after each observation.

**Verify**: After observing, `expected()` returns a value close to what was observed. Save/load round-trips correctly.

**Time**: 30 minutes

---

### Step 12: Testing the baseline store

#### Motivation

The baseline store involves time manipulation, file I/O, and statistical computation. Each of these can go wrong in subtle ways. Tests verify the bucket keys are correct, the statistics are computed right, and persistence round-trips without data loss.

#### Concepts

**Testing bucket keys**:

We use fixed dates so the test is deterministic. `datetime(2026, 11, 2, 14, 30)` is a Monday at 2:30pm — should map to `"weekday-14"`. `datetime(2026, 11, 7, 3, 0)` is a Saturday at 3:00am — should map to `"weekend-3"`.

Using fixed dates instead of `datetime.now()` is important: if you test with "now," the test result depends on what day you run it. A test that passes on Monday might fail on Saturday. Fixed dates make tests reliable regardless of when you run them.

**Testing persistence**:

```python
d = tempfile.mkdtemp()   # create a temporary directory
store = BaselineStore(config, data_dir=d)
store.observe(...)
store.save()             # writes to d/baseline.json
store2 = BaselineStore(config, data_dir=d)  # new store, same directory
store2.load()           # reads from d/baseline.json
assert store2.expected(...) == pytest.approx(...)
```

We use a temporary directory so the test doesn't pollute the real `data/` directory. After the test, the temp directory is cleaned up automatically.

**Testing statistics**:

After observing values [100, 110, 120, 90, 105], the mean should be 105 and count should be 5. We use `pytest.approx` because floating point mean calculation might give 105.0000000001 or 104.9999999999.

#### Questions you would ask

**Q: Why test bucket keys so carefully?**
A: The entire detection system depends on bucket keys being correct. If `_bucket_key` returns the wrong key, observations go into the wrong bucket, and `expected()` returns the wrong baseline. The detector then makes decisions based on incorrect baselines. A bug here cascades through the whole system.

**Q: Should I test the percentile calculation?**
A: It's tested indirectly — `BaselineStats.add()` calls `_recompute()` which calls `_percentile()`. If you add values and check the resulting p50, p95, etc., you're testing the percentile implementation. For this project, the percentiles are available on the dashboard but not used in detection, so they're lower priority. The mean and stdev (used in detection) are tested more directly.

**Q: What if the JSON file is corrupted?**
A: This project doesn't handle corrupted JSON gracefully — `json.load()` would raise an exception. In production, you'd add error handling (try/except around load, maybe fall back to an empty baseline). This project keeps it simple for learning.

**Q: How do I test file persistence without leaving files around?**
A: `tempfile.mkdtemp()` creates a temporary directory. Use it for the `data_dir`. After the test, the directory can be cleaned up. On some systems, the temp directory persists until reboot — but it's isolated from your real data, so it doesn't matter for the test.

#### Build

Create `tests/test_baseline.py`:

```python
import pytest
import tempfile
from datetime import datetime
from ddosguard.baseline.store import BaselineStore
from ddosguard.core import TrafficStats, TrafficWindow
from ddosguard.config import Config

def fake_stats(pr=100.0, br=50000.0, sr=0.1):
    now = datetime.now()
    w = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    w.packet_count = int(pr * 10)
    w.byte_count = int(br * 10)
    return TrafficStats(window=w, per_proto={6: 70, 17: 30}, syn_ratio=sr, byte_rate=br)

class TestBaselineStore:
    def test_bucket_key_weekday(self):
        store = BaselineStore(Config.load(None))
        assert store._bucket_key(datetime(2026, 11, 2, 14, 30)) == "weekday-14"

    def test_bucket_key_weekend(self):
        store = BaselineStore(Config.load(None))
        assert store._bucket_key(datetime(2026, 11, 7, 3, 0)) == "weekend-3"

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
            store.observe(fake_stats(float(r), float(r * 500)), ts)
        model = list(store.buckets.values())[0]
        assert model.count == 5
        assert model.mean == pytest.approx(105, abs=2)
```

#### Practice

1. Create `tests/test_baseline.py` and run: `python -m pytest tests/test_baseline.py -v`. All should pass.
2. Write your own test: add a test that verifies `expected_with_stdev` returns a tuple `(mean, stdev)` where both are floats.
3. Break it: change `_bucket_key` to always return `"weekday-0"`. Run the tests. `test_bucket_key_weekend` should fail. Fix it back.

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 20 minutes

---

## Phase 5: Anomaly Detection (Steps 13–15)

### Step 13: What "detection" means — signals and scores

#### Motivation

Now that you have baselines (Step 11) and traffic statistics (Step 7), you can compare the two. If current traffic is very different from the baseline, it might be an attack. But "very different" needs to be defined precisely — and different attacks look different, so you need multiple ways to detect them.

#### Concepts

**What is a signal**:

A signal is a function that takes traffic statistics and a baseline, and returns a score from 0 (normal) to 1 (highly anomalous). Each signal looks for a specific kind of anomaly:

| Signal | What it detects | How it works |
|---|---|---|
| Volume | Traffic much higher than baseline | Compares packet_rate and byte_rate to baseline mean, computes z-score |
| Protocol | Unusual protocol distribution | Checks if one protocol dominates (>80% of traffic) |
| Source | Too many unique sources | Counts unique source ports in the window |
| Port | Traffic concentrated on one port | Checks if one destination port gets >70% of traffic |
| SYN | SYN flood | Checks if syn_ratio > 0.3 (normal is much lower) |

**Why 5 signals**:

Different attacks have different signatures:
- A UDP flood triggers **Volume** (high byte rate) and possibly **Protocol** (mostly UDP).
- A SYN flood triggers **Volume** (high packet rate) and **SYN** (high syn_ratio).
- An HTTP flood triggers **Volume** (high packet rate to port 80) and **Port** (concentrated on one port).

No single signal catches everything. Using multiple signals and combining them gives broader coverage.

**Composite scoring**:

Each signal returns a 0..1 score. We multiply each by a weight and sum:

```
total = volume_score * 0.30 + protocol_score * 0.20 + source_score * 0.20
      + port_score * 0.15 + syn_score * 0.15
```

Weights reflect confidence and importance. Volume is weighted highest (0.30) because it's the most general indicator. SYN is weighted lower (0.15) because it's specific to one attack type.

The total maps to severity:
- 0.00–0.30: INFO (normal)
- 0.30–0.50: LOW
- 0.50–0.70: MEDIUM
- 0.70–0.85: HIGH
- 0.85–1.00: CRITICAL

**Confirmation damping**:

To prevent "flapping" (rapidly switching between attack and normal), we smooth the score:

```python
if total > self._prev:
    total = self._prev + (total - self._prev) * self.damping   # slow rise
else:
    total = self._prev + (total - self._prev) * (2 - self.damping)   # faster fall
```

With damping=0.8: if the raw score jumps from 0.2 to 0.8, the damped score moves to 0.2 + (0.8 - 0.2) * 0.8 = 0.6. It takes several windows for the damped score to catch up to a sudden spike. This prevents a brief spike from immediately triggering a CRITICAL alert.

When the score falls, it falls faster (multiplier 2 - 0.8 = 1.2), so the system recovers quickly once the attack stops.

#### Questions you would ask

**Q: Why not just use one threshold on packet rate?**
A: Because different attacks look different. A SYN flood might have a high packet rate but low byte rate (small packets). A UDP flood has high byte rate. An HTTP flood targets a specific port. A single threshold on packet rate misses attacks that don't spike packet rate but do spike byte rate, or that target a specific service.

**Q: What if two signals disagree?**
A: They're combined by weighted sum, so they don't "disagree" — they contribute to a total. If volume says 0.9 (attack) but SYN says 0.1 (normal), the total is still high because volume is weighted heavily. The total reflects the preponderance of evidence.

**Q: Why is the score capped at 1.0?**
A: Scores are normalized to 0..1 for consistency. Each signal is capped at 1.0 independently (e.g., `min(1.0, z / 5.0)` for volume). The weighted sum of values in 0..1, with weights summing to 1.0, is also in 0..1. This makes severity thresholds simple: 0.85 = CRITICAL, regardless of which signals fired.

**Q: What does damping=0.8 actually mean?**
A: It means "when the score rises, move 80% of the way toward the new value." If previous=0.2 and new=0.8, the rise is 0.6. Moving 80% of that rise: 0.2 + 0.6 * 0.8 = 0.68. The damped score is 0.68, not 0.8. It takes multiple windows to fully rise. On the fall side, the multiplier is 2 - 0.8 = 1.2, so it overshoots slightly downward — faster recovery.

**Q: Can I tune the weights?**
A: Yes. The weights are configurable (Step 15 reads them from config). If you care more about SYN floods, increase the SYN weight and decrease others. If you care more about volumetric attacks, increase volume. The defaults are a reasonable starting point.

#### Practice — answer before reading

1. Volume signal returns 0.8, weight is 0.30. What's the weighted contribution?
2. All 5 signals return 0.9. What's the total before damping?
3. A total score of 0.75 maps to which severity?

<details>
<summary>Answers</summary>

1. 0.8 * 0.30 = 0.24
2. 0.9 * (0.30 + 0.20 + 0.20 + 0.15 + 0.15) = 0.9 * 1.0 = 0.9
3. HIGH (0.70 ≤ 0.75 < 0.85)

</details>

**Time**: 10 minutes

---

### Step 14: Writing the detection signals

#### Motivation

Now you implement the 5 signal functions. Each is independent — it takes stats and a baseline, returns a score and details. The independence makes them testable individually.

#### Concepts

**Volume signal**:

```python
def volume_signal(stats, baseline):
    mean_pr, stdev_pr = baseline.expected_with_stdev("packet_rate", stats.window.start)
    mean_br, stdev_br = baseline.expected_with_stdev("byte_rate", stats.window.start)

    score = 0.0
    if stdev_pr > 0:
        z = max(0, stats.packet_rate - mean_pr) / stdev_pr
        score = min(1.0, z / 5.0)
    if stdev_br > 0:
        z = max(0, stats.byte_rate - mean_br) / stdev_br
        score = max(score, min(1.0, z / 5.0))
    return SignalResult("volume", score, {...})
```

The signal computes z-scores for both packet_rate and byte_rate, and takes the higher of the two. Why the higher? Because an attack might spike byte rate without spiking packet rate (large UDP packets), or spike packet rate without spiking byte rate (small SYN packets). Taking the max ensures we catch both.

`z / 5.0`: a z-score of 5 maps to a score of 1.0. This means "5 standard deviations above normal = maximum anomaly." Lower z-scores map proportionally.

`max(0, ...)`: we only care about values above the mean. Values below the mean (low traffic) are not attacks.

**SYN signal**:

```python
def syn_signal(stats, baseline):
    score = 0.0
    if stats.syn_ratio > 0.3:
        score = min(1.0, (stats.syn_ratio - 0.3) / 0.6)
    return SignalResult("syn", score, {"syn_ratio": ...})
```

The threshold is 0.3 (30% of packets are SYN). Normal traffic has a much lower SYN ratio. The score rises linearly from 0 at ratio=0.3 to 1.0 at ratio=0.9.

**Protocol signal**:

```python
def protocol_signal(stats, baseline):
    if stats.per_proto:
        total = sum(stats.per_proto.values())
        max_prop = max(stats.per_proto.values()) / total
        if max_prop > 0.8:
            score = min(1.0, (max_prop - 0.8) / 0.2)
```

If one protocol is more than 80% of traffic, that's unusual. Normal traffic is mixed (TCP, UDP, sometimes ICMP). An attack might be 100% UDP (volumetric) or 100% TCP (SYN flood). The signal catches protocol imbalance.

**Source signal**:

```python
def source_signal(stats, baseline):
    unique = len(stats.window.src_ports)
    score = min(1.0, (unique - 10) / 90.0) if unique > 10 else 0.0
```

This counts unique source ports. A high number of unique sources suggests many machines are sending traffic — typical of a distributed attack (DDoS = Distributed Denial of Service). The threshold starts at 10 unique sources.

**Port signal**:

```python
def port_signal(stats, baseline):
    if stats.window.dst_ports:
        total = sum(stats.window.dst_ports.values())
        max_port = max(stats.window.dst_ports, key=stats.window.dst_ports.get)
        max_prop = stats.window.dst_ports[max_port] / total
        if max_prop > 0.7:
            score = min(1.0, (max_prop - 0.7) / 0.3)
```

If one destination port gets more than 70% of traffic, that's concentrated. Normal traffic goes to many ports (80, 443, 22, 53, etc.). An attack might target one port (e.g., port 80 for HTTP flood, port 8080 for application layer attack).

#### Questions you would ask

**Q: Why does volume_signal use both packet_rate and byte_rate?**
A: Because different attacks spike different things. A SYN flood has many small packets — high packet rate, low byte rate. A UDP flood has large packets — high byte rate. Using both ensures we catch both types. The signal takes the max z-score of the two.

**Q: What's the significance of the 0.3 threshold for SYN ratio?**
A: It's an empirical threshold. Normal traffic typically has a SYN ratio well below 0.3 (most packets are data, not handshakes). A SYN ratio above 0.3 suggests an unusual number of connection attempts. The exact value is tunable — you might lower it for a more sensitive detector or raise it to reduce false positives.

**Q: What if there's no baseline data yet (expected returns 0)?**
A: The signal handles this: if `stdev_pr` is 0 (no baseline), the z-score calculation is skipped and score stays 0.0. This means the detector doesn't flag anything based on volume until a baseline exists. Other signals (SYN, protocol, source, port) don't depend on baseline and can fire immediately.

**Q: Why is source_signal based on source ports, not source IPs?**
A: In the synthetic generator, source IPs are in a small range (192.168.1.1–254). Many packets share the same IP but have different source ports. Counting unique source ports gives a better measure of how many distinct connections are being made. In a real deployment with diverse source IPs, you'd count unique source IPs instead. The signal is a placeholder for the concept — adapt it to your environment.

**Q: What does the `detail` dict in SignalResult contain?**
A: Debugging information — the values used to compute the score. For volume: the z-score, the baseline mean, and the current rate. This is shown on the dashboard so an operator can understand why a signal fired. It's not used in detection logic, just for human inspection.

#### Build

Create `ddosguard/detect/__init__.py` (empty) and `ddosguard/detect/signals.py`:

```python
from __future__ import annotations
from typing import Dict, List
from ddosguard.core import SignalResult, TrafficStats
from ddosguard.baseline.store import BaselineStore

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
    max_prop = max(stats.per_proto.values()) / sum(stats.per_proto.values()) if stats.per_proto else 0
    return SignalResult("protocol", score, {"max_protocol_proportion": round(max_prop, 3)})

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
    return [
        volume_signal(stats, baseline),
        protocol_signal(stats, baseline),
        source_signal(stats, baseline),
        port_signal(stats, baseline),
        syn_signal(stats, baseline),
    ]
```

#### Practice

1. Create `detect/__init__.py` and `detect/signals.py`.
2. Test the volume signal:
   ```
   python -c "
   from ddosguard.detect.signals import volume_signal, syn_signal
   from ddosguard.baseline.store import BaselineStore
   from ddosguard.config import Config
   from ddosguard.core import TrafficStats, TrafficWindow
   from datetime import datetime, timedelta

   config = Config.load(None)
   baseline = BaselineStore(config, data_dir='data')
   baseline.set_ready(True)

   now = datetime.now()
   for i in range(10):
       w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
       w.packet_count = 500
       w.byte_count = 250000
       baseline.observe(w.finalize(), now)

   w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w.packet_count = 5000
   w.byte_count = 2500000
   stats = w.finalize()
   result = volume_signal(stats, baseline)
   print(f'Volume score: {result.score:.3f} (should be high)')
   print(f'Detail: {result.detail}')

   w2 = TrafficWindow(start=now-timedelta(seconds=10), end=now)
   w2.packet_count = 1000
   w2.syn_count = 900
   stats2 = w2.finalize()
   result2 = syn_signal(stats2, baseline)
   print(f'SYN score: {result2.score:.3f} (should be high, syn_ratio=0.9)')
   "
   ```
3. Break it: observe that if you don't train the baseline first, `volume_signal` returns score 0 (because stdev is 0). This is correct — no baseline, no volume detection.
4. Experiment: change the SYN threshold from 0.3 to 0.5 in the code. Test with `syn_ratio=0.4`. The score should drop to 0 (below threshold). Change it back to 0.3.

**Verify**: Volume signal scores high for 10x traffic. SYN signal scores high for 90% SYN ratio.

**Time**: 30 minutes

---

### Step 15: The composite scorer — combining signals into a decision

#### Motivation

Individual signals tell you specific things. The composite scorer combines them into a single decision: what's the overall severity, and what type of attack is it (if any)?

#### Concepts

**The scoring process**:

1. Run all 5 signals (Step 14).
2. For each signal, multiply its score by its weight.
3. Sum the weighted scores → raw total.
4. Apply confirmation damping → damped total.
5. Map damped total to severity.
6. Classify attack type based on which signals fired.

**Weights** (from config, with defaults):

```python
self.weights = {
    "volume": 0.30,
    "protocol": 0.20,
    "source": 0.20,
    "port": 0.15,
    "syn": 0.15,
}
```

These sum to 1.0. The weighted sum of scores (each in 0..1) is also in 0..1.

**Damping formula**:

```python
if total > self._prev:
    total = self._prev + (total - self._prev) * self.damping
else:
    total = self._prev + (total - self._prev) * (2 - self.damping)
self._prev = max(0.0, min(1.0, total))
```

`self._prev` is the previous damped score. It's updated each time `score()` is called. The first call sets `_prev` to the raw total (no damping on the first call).

**Attack classification**:

```python
fired = {s.name for s in signals if s.score > 0.3}   # signals that are "active"

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
```

Classification is based on which signals crossed the 0.3 threshold. It's a rough categorization — enough to tell the operator what kind of attack they're looking at.

#### Questions you would ask

**Q: Why is classification separate from severity?**
A: Severity tells you how bad it is (CRITICAL vs INFO). Classification tells you what it is (SYN flood vs UDP flood). They're different questions. A SYN flood could be LOW severity (small attack) or CRITICAL (large attack). The severity drives the response (alert, mitigate), the classification drives the response type (SYN-specific mitigation vs volumetric mitigation).

**Q: What if no signals fire but the total is above 0.3?**
A: That can't happen — if no signals fire (all scores below 0.3), the total is below 0.3 because weights sum to 1.0. The maximum total with all signals at 0.3 is 0.3 exactly. So `total < 0.30` and `no signals fired` are equivalent.

**Q: Why is the damping state stored in the scorer (`self._prev`)?**
A: Because damping is stateful — it depends on the previous score. The scorer is a class (not a function) so it can hold state. Each call to `score()` updates `_prev`. If you create a new scorer, damping starts fresh. In the full pipeline (Step 25), the scorer is created once and reused for the lifetime of the monitor.

**Q: What happens if I change the weights in config?**
A: The scorer reads weights from config in `__init__`. If the config specifies different weights, they override the defaults. The total is still in 0..1 because the weights still sum to 1.0 (if you change them, make sure they still sum to 1.0, or the total could exceed 1.0). The classification logic doesn't depend on weights — it depends on which signals fire (score > 0.3).

**Q: Is 0.3 the right threshold for "signal fired"?**
A: It's a reasonable default. A signal with score 0.3 is "mildly anomalous." For classification, you want signals that are clearly indicative of a specific attack type. 0.3 is a middle ground — not so low that noise triggers classification, not so high that real attacks are missed. Tune it based on your environment.

#### Build

Create `ddosguard/detect/scorer.py`:

```python
from __future__ import annotations
from typing import Dict, List, Optional
from ddosguard.core import CompositeScore, SignalResult, Severity, TrafficStats
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.signals import run_all_signals

class CompositeScorer:
    def __init__(self, config: Optional[object] = None):
        self.weights = {"volume": 0.30, "protocol": 0.20, "source": 0.20, "port": 0.15, "syn": 0.15}
        self.damping = 0.8
        self._prev: float | None = None
        if config is not None:
            try:
                det = config.detection
                if "weights" in det and isinstance(det["weights"], dict):
                    for k, v in det["weights"].items():
                        if k in self.weights:
                            self.weights[k] = float(v)
                if "confirmation_damping" in det:
                    self.damping = float(det["confirmation_damping"])
            except Exception:
                pass

    def score(self, stats: TrafficStats, baseline: BaselineStore) -> CompositeScore:
        signals = run_all_signals(stats, baseline)
        total = 0.0
        scores: Dict[str, float] = {}
        names: List[str] = []
        for sig in signals:
            w = self.weights.get(sig.name, 0.0)
            total += sig.score * w
            scores[sig.name] = sig.score
            names.append(sig.name)

        # Confirmation damping
        if self._prev is None:
            self._prev = total
        elif total > self._prev:
            total = self._prev + (total - self._prev) * self.damping
        else:
            total = self._prev + (total - self._prev) * (2.0 - self.damping)
        self._prev = max(0.0, min(1.0, total))

        # Severity
        if total >= 0.85:
            sev = Severity.CRITICAL
        elif total >= 0.70:
            sev = Severity.HIGH
        elif total >= 0.50:
            sev = Severity.MEDIUM
        elif total >= 0.30:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        # Attack classification
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
            signal_names=names,
            signal_scores=scores,
            total=total,
            severity=sev,
            classification=cls,
            window=stats,
        )
```

#### Practice

1. Create `detect/scorer.py`.
2. Test it:
   ```
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

   # Train baseline
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

   # SYN flood attack
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
3. Experiment: change weights in the scorer to make SYN dominate (`"syn": 0.50, "volume": 0.10`). Rerun the attack test. See how the total changes (SYN flood should score higher now because SYN weight is higher).

**Verify**: Normal traffic scores < 0.3 (INFO). Attack traffic scores > 0.5 (at least MEDIUM, likely HIGH or CRITICAL).

**Time**: 25 minutes

---

## Phase 6: Rate Limiting & Mitigation (Steps 16–18)

### Step 16: Token buckets — how rate limiting works

#### Motivation

Detection tells you there's an attack. Mitigation stops it. The most common mitigation is rate limiting — allowing each source to send only so many packets per second. The token bucket is the standard algorithm for this.

#### Concepts

**The token bucket algorithm**:

Imagine a bucket that holds tokens. Tokens are added at a steady rate (e.g., 100 tokens per second). Each packet that wants to pass through must consume one token. If the bucket is empty, the packet is dropped.

```
State:  tokens = 5,  rate = 10/sec,  burst = 5

Time 0:  bucket has 5 tokens (burst)
Request 1: consume 1 token → bucket has 4
Request 2: consume 1 token → bucket has 3
...
Request 5: consume 1 token → bucket has 0
Request 6: bucket empty → DENIED
(time passes, tokens refill)
After 0.5 sec: tokens = min(5, 0 + 0.5 * 10) = 5
Request 7: consume 1 token → bucket has 4
```

**Parameters**:
- `rate`: how many tokens are added per second (sustained rate)
- `burst`: how many tokens the bucket can hold (maximum burst)

With `burst > 0`: the bucket starts full. The first `burst` requests are allowed immediately. After that, the rate limits to `rate` per second.

With `burst = 0`: the bucket starts empty. Even the first request is denied until enough time passes for tokens to accumulate.

**Refill calculation**:

```python
elapsed = now - last_update
tokens = min(burst, tokens + elapsed * rate)
```

This is "analytical" refill — it computes exactly how many tokens should have accumulated based on elapsed time, regardless of how often you check. It's accurate even if you check irregularly.

**Per-source buckets**:

Each source (IP address, or any key) gets its own bucket. This means one aggressive source can't consume tokens allocated to another source. Each source is limited independently.

```
Source A: bucket with 5 tokens → A can send 5 packets, then wait
Source B: bucket with 5 tokens → B can send 5 packets, then wait
A and B don't interfere with each other.
```

**Whitelist**:

Some sources should never be rate-limited (e.g., your monitoring system, known good services). The whitelist bypasses the bucket check entirely — whitelisted sources always get through.

#### Questions you would ask

**Q: Why use a token bucket instead of just counting requests per second?**
A: A simple counter ("allow 100 requests per second, reset every second") is a fixed window. It has a problem: if 100 requests arrive in the first millisecond, they're all allowed, then nothing is allowed for the rest of the second. A token bucket smooths this out — tokens accumulate gradually, so requests are allowed at a steady rate, not in bursts (except for the initial burst).

**Q: What's the difference between rate and burst?**
A: `rate` is the sustained speed — how fast tokens are added. `burst` is the capacity — how many tokens can be stored. A bucket with rate=100 and burst=200 can handle an initial burst of 200 requests, then sustains at 100/sec. A bucket with rate=100 and burst=100 has no burst capacity — it starts with 100 tokens and refills at 100/sec.

**Q: What happens when burst=0?**
A: The bucket starts with 0 tokens. The first request is denied. After 0.01 seconds, the bucket has 0.01 * rate tokens. If rate=100, that's 1 token after 0.01 seconds. So the first request is allowed after a brief delay. This is "strict" rate limiting — no initial burst.

**Q: Why track whitelisted sources separately?**
A: A whitelist is a set of keys that bypass rate limiting entirely. This is important for infrastructure services (monitoring, logging, health checks) that must always get through. Without a whitelist, these services could be rate-limited during an attack, causing a cascade of failures.

**Q: What key should I use for per-source limiting?**
A: In this project, we use the source IP as the key. In practice, attackers can spoof IPs, so IP-based limiting isn't perfect. More sophisticated approaches use other identifiers (session tokens, API keys, etc.). For a network-level DDoS defense, IP-based limiting is the standard first line of defense.

#### Practice — answer before reading

1. Bucket: rate=100, burst=200. How many requests pass in the first instant?
2. After the burst is consumed, what's the sustained rate?
3. Bucket: rate=100, burst=0. What happens on the very first request?

<details>
<summary>Answers</summary>

1. 200 requests — the burst capacity is available immediately.
2. 100 requests per second — the rate at which tokens are added.
3. The first request is denied — bucket starts empty with 0 tokens.

</details>

**Time**: 10 minutes

---

### Step 17: Implementing the token bucket and rate limiter

#### Motivation

Now you write the code. The `TokenBucket` class implements the algorithm. The `RateLimiter` class manages per-source buckets and a whitelist.

#### Concepts

**TokenBucket class**:

```python
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
```

`_refill()` is called at the start of `consume()` to ensure the token count is up to date. The `_last` timestamp is updated after refilling, so the next call computes elapsed time correctly.

**RateLimiter class**:

```python
class RateLimiter:
    def __init__(self, default_rate=100.0, default_burst=200.0):
        self.default_rate = default_rate
        self.default_burst = default_burst
        self._buckets: Dict[str, TokenBucket] = {}
        self._whitelist: set = set()
        self._admitted = 0
        self._denied = 0

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
```

When `admit()` is called for a new key, a new `TokenBucket` is created for that key with the default rate and burst. Each key gets its own independent bucket.

#### Questions you would ask

**Q: Why does TokenBucket call _refill() in __init__?**
A: To initialize `_last` to the current time. Without this, the first `consume()` call would compute elapsed time from whenever the object was created (which could be a while ago if the object was created and stored before being used). Calling `_refill()` in init sets `_last = now`, so the first consume computes elapsed from "now."

**Q: What happens if consume(0) is called?**
A: It returns True immediately (the `if tokens <= 0: return True` check). This is a safety measure — consuming 0 tokens should always succeed. It's also a no-op that doesn't affect the bucket.

**Q: Why track _admitted and _denied counts?**
A: For monitoring and debugging. The dashboard (Step 23) shows these stats so an operator can see how much traffic is being allowed vs blocked. In a real deployment, you'd export these to a monitoring system.

**Q: Should the RateLimiter have a method to remove old buckets?**
A: It could — buckets for sources that haven't been seen in a while could be cleaned up to save memory. This project doesn't implement that (the number of sources is bounded in a DDoS scenario by the attack itself — there are only so many attacking IPs). In a long-running system with many short-lived sources, you'd add cleanup.

**Q: What if the same key is admitted from multiple threads?**
A: This project's architecture uses a single monitor thread (Step 25), so there's no concurrency. In a multi-threaded system, you'd need a lock around the `_buckets` dictionary and each bucket's token count. The `TokenBucket._refill()` and `consume()` methods would need to be atomic.

#### Build

Create `ddosguard/mitigate/__init__.py` (empty) and `ddosguard/mitigate/ratelimit.py`:

```python
from __future__ import annotations
from datetime import datetime
from typing import Dict, Optional

class TokenBucket:
    def __init__(self, rate: float = 100.0, burst: float = 200.0):
        self.rate = rate
        self.burst = burst
        self._tokens = burst if burst > 0 else 0.0
        self._last = datetime.now()
        self._refill()

    def _refill(self) -> None:
        now = datetime.now()
        elapsed = (now - self._last).total_seconds()
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last = now

    def consume(self, tokens: float = 1.0) -> bool:
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
    def __init__(self, default_rate: float = 100.0, default_burst: float = 200.0):
        self.default_rate = default_rate
        self.default_burst = default_burst
        self._buckets: Dict[str, TokenBucket] = {}
        self._whitelist: set = set()
        self._admitted = 0
        self._denied = 0

    def add_whitelist(self, key: str) -> None:
        self._whitelist.add(key)

    def remove_whitelist(self, key: str) -> bool:
        if key in self._whitelist:
            self._whitelist.discard(key)
            return True
        return False

    def is_whitelisted(self, key: str) -> bool:
        return key in self._whitelist

    def admit(self, key: str, tokens: float = 1.0) -> bool:
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

    def stats(self, key: Optional[str] = None) -> dict:
        if key is not None:
            if key in self._whitelist:
                return {"key": key, "whitelisted": True}
            if key in self._buckets:
                b = self._buckets[key]
                return {"key": key, "whitelisted": False, "tokens": b.available,
                        "rate": b.rate, "burst": b.burst}
            return {"key": key, "whitelisted": False, "bucket": "not seen"}
        return {"total_admitted": self._admitted, "total_denied": self._denied,
                "active_buckets": len(self._buckets), "whitelisted": len(self._whitelist)}

    def clear(self) -> None:
        self._buckets.clear()
        self._whitelist.clear()
        self._admitted = 0
        self._denied = 0
```

#### Practice

1. Create `mitigate/__init__.py` and `mitigate/ratelimit.py`.
2. Test TokenBucket:
   ```
   python -c "
   from ddosguard.mitigate.ratelimit import TokenBucket, RateLimiter
   import time

   b = TokenBucket(rate=10, burst=5)
   print(f'Initial tokens: {b.available:.1f}')
   for i in range(5):
       print(f'Consume {i+1}: {b.consume(1)} (tokens left: {b.available:.1f})')
   print(f'6th consume: {b.consume(1)} (should be False)')

   print()
   limiter = RateLimiter(default_rate=100, default_burst=200)
   limiter.add_whitelist('10.0.0.1')
   print(f'Whitelist admit: {limiter.admit(\"10.0.0.1\", 1)} (should be True)')
   admitted = sum(limiter.admit('10.0.0.2', 1) for _ in range(250))
   print(f'250 requests from 10.0.0.2: {admitted} admitted (should be ~200)')
   print(f'Stats: {limiter.stats()}')
   "
   ```
3. Break it: create a `TokenBucket(rate=10, burst=0)`. Try `consume(1)` immediately — it should return False. Wait a moment, try again — it might succeed (1 token has accumulated). Set `burst=1` and verify the first consume succeeds.
4. Experiment: create a `RateLimiter(default_rate=10, default_burst=5)`. Admit 100 requests from key "A". Count how many succeed (should be around 5 + a few more from refill). Then admit from key "B" — it should have its own bucket with full burst.

**Verify**: TokenBucket allows burst then enforces rate. RateLimiter whitelists bypass limiting. Different keys have independent buckets.

**Time**: 30 minutes

---

### Step 18: Testing rate limiting

#### Motivation

Rate limiting has clear expected behavior: burst should be available, consumption should deplete tokens, refill should add tokens back, whitelists should bypass, different keys should be independent. Tests verify each of these.

#### Concepts

**Testing burst availability**:

```python
def test_burst_available(self):
    b = TokenBucket(rate=10, burst=5)
    assert b.available == pytest.approx(5.0, abs=0.01)
```

Right after creation, the bucket should have `burst` tokens. The `abs=0.01` is for floating point — `available` might be 5.0000000001 due to the refill calculation.

**Testing zero burst**:

```python
def test_zero_burst_empty(self):
    b = TokenBucket(rate=10, burst=0)
    assert b.available == 0.0
    assert not b.consume(1)
```

With burst=0, the bucket starts empty and the first consume is denied.

**Testing consumption depletes tokens**:

```python
def test_consume_denied_when_empty(self):
    b = TokenBucket(rate=100, burst=5)
    for _ in range(5):
        assert b.consume(1)   # first 5 succeed
    assert not b.consume(1)   # 6th fails
```

**Testing refill**:

```python
def test_refill(self):
    b = TokenBucket(rate=100, burst=50)
    for _ in range(50):
        b.consume(1)
    assert b.available == pytest.approx(0.0, abs=0.01)
    time.sleep(0.5)   # wait for tokens to accumulate
    assert b.available >= 40   # at least 50 * 0.5 = 25 tokens, but capped at burst
```

**Testing independent buckets**:

```python
def test_independent_buckets(self):
    lim = RateLimiter(10, 5)
    for _ in range(5):
        lim.admit("A", 1)   # deplete A's bucket
    assert lim.admit("B", 1)   # B's bucket is still full
```

#### Questions you would ask

**Q: Why use time.sleep in the refill test?**
A: To verify that tokens accumulate over time. Without sleeping, the elapsed time would be negligible and no tokens would be added. The sleep gives enough time for a measurable amount of tokens to refill.

**Q: Why not test refill more precisely?**
A: Because `datetime.now()` has limited precision, and the test environment might not have consistent timing. Asserting `>= 40` after a 0.5 second sleep with rate=100 is robust — even if the timing is slightly off, 40 tokens should have accumulated (100 * 0.5 = 50, capped at burst=50). The exact value doesn't matter; the fact that refill works is what matters.

**Q: How do I test the whitelist without testing rate limiting at the same time?**
A: Test them separately. `test_whitelist_bypass` uses a rate limiter with rate=1, burst=1 (very restrictive). The whitelisted key should bypass this and get all 100 requests through. `test_non_whitelisted_limited` tests that a non-whitelisted key is limited.

#### Build

Create `tests/test_ratelimit.py`:

```python
import pytest
import time
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

1. Create `tests/test_ratelimit.py` and run: `python -m pytest tests/test_ratelimit.py -v`. All should pass.
2. Write your own test: test that `remove_whitelist` returns `True` for a whitelisted key and `False` for a non-whitelisted key.
3. Break it: temporarily modify `admit()` to skip the whitelist check. Run `test_whitelist_bypass`. It should fail (the whitelisted key should be limited by the rate=1, burst=1 limiter, but it's not being checked). Restore the whitelist check.

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 20 minutes

---

## Phase 7: Firewall Rules (Step 19)

### Step 19: Generating iptables-style rules

#### Motivation

Detection (Phase 5) tells you there's an attack. Rate limiting (Phase 6) slows it down per-source. Firewall rules are the network-level response — they tell the server's firewall to drop or limit traffic matching certain patterns. This is the actual mitigation that protects the server.

On Linux, `iptables` is the standard firewall. Rules are added with `iptables -A CHAIN ... -j ACTION`. This step generates those rules programmatically based on the attack severity and mitigation stage.

#### Concepts

**iptables rule structure**:

```
-A INPUT -p tcp --dport 80 -m limit --limit 100/s -j ACCEPT
│      │     │      │                                              │
│      │     │      └─ match condition                            action
│      │     └─ protocol                                       module
│      └─ chain (INPUT = incoming packets)
└─ action: append
```

- `-A INPUT`: append to the INPUT chain (incoming packets to this host)
- `-p tcp`: match TCP protocol
- `--dport 80`: destination port 80
- `-m limit`: use the "limit" module
- `--limit 100/s`: allow 100 per second
- `-j ACCEPT`: jump to ACCEPT (allow the packet)

**Mitigation stages**:

| Stage | Meaning | Example rules |
|---|---|---|
| 0 | No mitigation | (no rules) |
| 1 | Lenient rate limit | ACCEPT tcp/udp with limit 100/s, burst 200 |
| 2 | Strict per-IP | Track with recent module, DROP repeat offenders |
| 3 | Service-port limits | Limit traffic to specific ports |
| 4 | Full DROP | Drop all SYN packets aggressively |

The stage is determined by the severity of the detected attack. Higher severity → higher stage → more aggressive rules.

**Why whitelist rules come first**:

iptables processes rules in order. The first matching rule wins. If a whitelist rule (ACCEPT for a specific IP) comes after a DROP rule, the DROP matches first and the whitelist is never reached. Whitelist rules must be early in the chain.

**Dry-run mode**:

Generating rules is safe. Applying them is dangerous — a wrong rule can lock you out of your server. Dry-run mode prints the rules without executing them. On Windows (this project's development environment), dry-run is the only mode that works (no iptables). On Linux in production, you'd set `dry_run=False` after verifying the rules look correct.

#### Questions you would ask

**Q: Why generate rules instead of writing them manually?**
A: Because the rules depend on the attack severity and stage, which change dynamically. A manual approach would require an operator to look at the alert and type rules. Automated generation responds immediately and consistently. The operator can review the generated rules (in dry-run mode or in the dashboard) before they're applied.

**Q: What does the "recent" module do?**
A: It tracks recent connections from each IP. `-m recent --set --name DDOSGUARD` adds the source IP to a list named DDOSGUARD. `-m recent --update --seconds 10 --hitcount 50 --name DDOSGUARD -j DROP` checks if the IP has been seen 50 times in the last 10 seconds — if so, drop the packet. This is a per-IP rate limit implemented by the kernel.

**Q: Why not just use the rate limiting from Step 17?**
A: The rate limiter in Step 17 is application-level — it runs in your Python process. Firewall rules are kernel-level — they're enforced by the OS before packets reach your application. Firewall rules are more efficient (they drop packets before they consume any application resources) and they protect against attacks that would otherwise overwhelm the application before it can rate-limit. Both are useful: application-level for fine-grained control, firewall-level for broad protection.

**Q: What happens on Windows?**
A: Windows doesn't have iptables. The `apply()` method runs in dry-run mode by default, which prints the rules without executing them. The rules are still generated correctly — they're valid iptables syntax. If you deploy this to a Linux server, you'd switch to `dry_run=False` (carefully, after testing).

**Q: What if I apply a bad rule?**
A: On a remote server, you could lock yourself out. This is why dry-run is the default and why you should always review generated rules before applying them. In production, you'd also have a fallback: a Cron job or systemd timer that clears ddosguard rules every few minutes, so a bad rule doesn't persist forever.

#### Build

Create `ddosguard/mitigate/firewall.py`:

```python
from __future__ import annotations
import subprocess
from typing import Dict, List, Optional

class FirewallManager:
    def __init__(self, dry_run: bool = True, chain: str = "INPUT"):
        self.dry_run = dry_run
        self.chain = chain
        self._active: List[str] = []

    def generate_rules(self, stage: int, severity: str = "",
                       config: Optional[Dict] = None,
                       whitelist: Optional[List[str]] = None) -> List[str]:
        wl = whitelist or []
        rules: List[str] = []
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

1. Create `mitigate/firewall.py`.
2. Test rule generation:
   ```
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
3. Verify ordering: in stage 2 output, the whitelist rule (`-A INPUT -s 192.168.1.1 -j ACCEPT`) should appear before any DROP rules.
4. Experiment: generate stage 3 rules (service-port limits). This stage isn't implemented in the current code — that's a limitation you could address by adding stage 3 rule generation.

**Verify**: Stage 0 = 0 rules. Stage 1 = rate limit rules. Stage 2 = recent module rules. Stage 4 = SYN DROP. Whitelist always first.

**Time**: 25 minutes

---

## Phase 8: Alerting & Escalation (Steps 20–22)

### Step 20: AlertManager — turning detections into notifications

#### Motivation

When the composite scorer (Step 15) decides there's an attack, someone needs to know. The AlertManager handles this: it creates alerts, deduplicates them (so you don't get 100 notifications for the same attack), enforces cooldown and rate limits, and sends them through multiple channels.

#### Concepts

**Alert structure**:

```python
@dataclass
class Alert:
    id: str                     # unique identifier
    severity: Severity          # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title: str                  # short description
    summary: str                # detailed description
    timestamp: datetime         # when it was created
    stage: int                  # mitigation stage to apply
    source_ip: str = ""         # attacking source, if known
```

**Signature-based deduplication**:

To avoid sending the same alert multiple times, each alert gets a "signature" — a hash of its key characteristics. If two alerts have the same signature, they're the same event.

```python
def _signature(self, alert: Alert) -> str:
    data = f"{alert.severity.name}:{alert.title}:{alert.summary}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]
```

The signature includes severity, title, and summary. Two CRITICAL alerts about the same SYN flood at the same time will have the same signature → deduplicated.

**Cooldown**:

After sending an alert, don't send another alert with the same signature for N seconds. This prevents notification spam during a long-lasting attack.

**Rate limiting**:

Max alerts per minute. Even with different signatures, you don't want to send 60 alerts in a minute. This caps the total notification rate.

**Multi-channel delivery**:

- **Console**: print to stdout (always available, good for development)
- **JSONL file**: append to a file, one JSON object per line (persistent, can be processed later)
- **Desktop notification**: platform-native notification (if supported)
- **Slack**: webhook to a Slack channel (optional, requires configuration)
- **Email**: SMTP email (optional, requires configuration)

Each channel is tried independently. If one fails (e.g., Slack webhook is down), the others still work.

#### Questions you would ask

**Q: Why not just send every alert?**
A: During a sustained attack, the scorer might produce a high score every window (every 10 seconds). Without dedup, you'd get 6 alerts per minute for the same attack. With cooldown, you get one alert when the attack starts, then another after the cooldown period if it's still ongoing. This is manageable.

**Q: What's the difference between dedup and rate limiting?**
A: Dedup is per-signature — "don't send the same alert twice." Rate limiting is global — "don't send more than N alerts total per minute." Dedup prevents spam from the same event. Rate limiting prevents spam from many different events (e.g., many small attacks).

**Q: Why include the timestamp in the signature?**
A: Actually, we don't — the signature is based on severity, title, and summary, not timestamp. This means if the same attack triggers alerts at 10:00 and 10:05, they have the same signature and the second is deduplicated. If we included the timestamp, they'd have different signatures and both would be sent. The choice depends on whether you want to be notified of ongoing attacks (include timestamp) or just the initial detection (exclude timestamp). This project excludes it for less spam.

**Q: What if all channels fail?**
A: The alert is still recorded in the AlertManager's internal list (so `get_timeline()` can return it). It's just not delivered anywhere. In production, you'd add logging of delivery failures and alerting on delivery failures (meta-alerting).

#### Build

First, add `Alert` to `ddosguard/core.py`:

```python
@dataclass
class Alert:
    id: str
    severity: Severity
    title: str
    summary: str
    timestamp: datetime = field(default_factory=datetime.now)
    stage: int = 0
    source_ip: str = ""
```

Create `ddosguard/alert/__init__.py` (empty) and `ddosguard/alert/manager.py`:

```python
from __future__ import annotations
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from ddosguard.core import Alert, Severity

class AlertManager:
    def __init__(self, config: Optional[object] = None,
                 output_file: str = "data/alerts.jsonl",
                 console: bool = True):
        self._lock = threading.Lock()
        self.alerts: List[Alert] = []
        self._sent: Dict[str, datetime] = {}   # signature -> last sent time
        self._cooldown: float = 60.0
        self._max_per_minute: int = 10
        self._minute_bucket: List[datetime] = []
        self._output_file = output_file
        self._console = console
        if config is not None:
            try:
                if hasattr(config, 'alerting'):
                    a = config.alerting
                    if "cooldown_seconds" in a:
                        self._cooldown = float(a["cooldown_seconds"])
                    if "max_alerts_per_minute" in a:
                        self._max_per_minute = int(a["max_alerts_per_minute"])
                    if "console" in a:
                        self._console = bool(a["console"])
                    if "output_file" in a:
                        self._output_file = str(a["output_file"])
            except Exception:
                pass

    def _signature(self, alert: Alert) -> str:
        data = f"{alert.severity.name}:{alert.title}:{alert.summary}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _rate_limited(self) -> bool:
        now = datetime.now()
        self._minute_bucket = [t for t in self._minute_bucket if (now - t).total_seconds() < 60]
        return len(self._minute_bucket) >= self._max_per_minute

    def emit(self, alert: Alert) -> bool:
        sig = self._signature(alert)
        with self._lock:
            now = datetime.now()
            if sig in self._sent:
                if (now - self._sent[sig]).total_seconds() < self._cooldown:
                    return False
            if self._rate_limited():
                return False
            self.alerts.append(alert)
            self._sent[sig] = now
            self._minute_bucket.append(now)
            if self._console:
                print(f"[ALERT] {alert.severity.name}: {alert.title} — {alert.summary}")
            if self._output_file:
                try:
                    os.makedirs(os.path.dirname(self._output_file), exist_ok=True)
                    with open(self._output_file, "a") as f:
                        f.write(json.dumps({
                            "id": alert.id, "severity": alert.severity.name,
                            "title": alert.title, "summary": alert.summary,
                            "timestamp": alert.timestamp.isoformat(),
                            "stage": alert.stage, "source_ip": alert.source_ip,
                        }) + "\n")
                except Exception:
                    pass
            return True

    def get_timeline(self) -> List[Alert]:
        with self._lock:
            return sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)

    def get_urgent(self) -> List[Alert]:
        with self._lock:
            return [a for a in self.alerts if a.severity in (Severity.CRITICAL, Severity.HIGH)]

    def recent(self, seconds: float = 300) -> List[Alert]:
        with self._lock:
            cutoff = datetime.now() - timedelta(seconds=seconds)
            return [a for a in self.alerts if a.timestamp >= cutoff]
```

#### Practice

1. Add `Alert` to `core.py`. Create `alert/__init__.py` and `alert/manager.py`.
2. Test emit and dedup:
   ```
   python -c "
   from ddosguard.alert.manager import AlertManager
   from ddosguard.core import Alert, Severity
   import uuid

   am = AlertManager(console=False, output_file=None)
   a1 = Alert(id=str(uuid.uuid4()), severity=Severity.CRITICAL,
              title='SYN flood detected', summary='5000 pps from 10.0.0.0/24',
              stage=2)
   a2 = Alert(id=str(uuid.uuid4()), severity=Severity.CRITICAL,
              title='SYN flood detected', summary='5000 pps from 10.0.0.0/24',
              stage=2)

   print(f'First emit: {am.emit(a1)} (should be True)')
   print(f'Second emit (same sig): {am.emit(a2)} (should be False — deduped)')
   print(f'Timeline has {len(am.get_timeline())} alerts')
   "
   ```
3. Break it: reduce cooldown to 0 and max_per_minute to 0. Emit two different alerts quickly. The second should be rate-limited (max_per_minute=0 means no alerts allowed).

**Verify**: First emit succeeds. Second emit with same signature is deduplicated. Timeline contains only the first alert.

**Time**: 25 minutes

---

### Step 21: AlertDirector — ranking and filtering alerts

#### Motivation

As alerts accumulate, you need to find the important ones quickly. The AlertDirector provides views: all alerts sorted by severity, only the urgent ones, only recent ones. It's a query layer on top of the AlertManager's stored alerts.

#### Concepts

**Ranking by severity**:

```python
SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
```

Higher number = more severe. Sorting by this order puts CRITICAL alerts first.

**Filtering**:

- `get_urgent()`: only CRITICAL and HIGH severity
- `recent(seconds)`: only alerts in the last N seconds
- `get_timeline()`: all alerts, newest first

These are different views for different needs:
- Dashboard shows `get_timeline()` (all alerts, recent first)
- Phone notification shows `get_urgent()` (only the important ones)
- Status page shows `recent(60)` (alerts in the last minute)

#### Questions you would ask

**Q: Why not just filter the list manually?**
A: You could, but the director encapsulates the filtering logic. If you change the definition of "urgent" (e.g., include MEDIUM for certain classifications), you change it in one place — the director — not everywhere the alerts are displayed.

**Q: Should the director modify alerts?**
A: No. It only reads and filters. Modification (deduplication, cooldown) is the AlertManager's job. Separation of concerns: Manager = write/manage, Director = read/query.

#### Build

Create `ddosguard/alert/director.py`:

```python
from __future__ import annotations
from datetime import datetime, timedelta
from typing import List, Optional
from ddosguard.core import Alert, Severity

SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

class AlertDirector:
    def __init__(self, manager: Optional[object] = None):
        self._manager = manager

    def set_manager(self, manager: object) -> None:
        self._manager = manager

    def get_timeline(self) -> List[Alert]:
        if self._manager is None:
            return []
        return sorted(self._manager.get_timeline(), key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)

    def get_urgent(self) -> List[Alert]:
        if self._manager is None:
            return []
        return [a for a in self._manager.get_timeline()
                if a.severity in (Severity.CRITICAL, Severity.HIGH)]

    def recent(self, seconds: float = 300) -> List[Alert]:
        if self._manager is None:
            return []
        cutoff = datetime.now() - timedelta(seconds=seconds)
        return [a for a in self._manager.get_timeline() if a.timestamp >= cutoff]
```

#### Practice

1. Create `alert/director.py`.
2. Test it:
   ```
   python -c "
   from ddosguard.alert.manager import AlertManager
   from ddosguard.alert.director import AlertDirector
   from ddosguard.core import Alert, Severity
   import uuid

   am = AlertManager(console=False)
   am.emit(Alert(id=str(uuid.uuid4()), severity=Severity.INFO, title='Normal traffic', summary='50 pps'))
   am.emit(Alert(id=str(uuid.uuid4()), severity=Severity.CRITICAL, title='SYN flood', summary='5000 pps'))
   am.emit(Alert(id=str(uuid.uuid4()), severity=Severity.HIGH, title='UDP flood', summary='10000 Bps'))

   director = AlertDirector(am)
   print(f'All alerts: {len(director.get_timeline())}')
   print(f'Urgent: {len(director.get_urgent())} (should be 2: CRITICAL + HIGH)')
   print(f'Urgent severities: {[a.severity.name for a in director.get_urgent()]}')
   "
   ```
3. Break it: pass `None` to `AlertDirector`. `get_timeline()` should return an empty list (graceful handling of missing manager).

**Verify**: Timeline has 3 alerts sorted by severity (CRITICAL first). Urgent returns 2 (CRITICAL + HIGH).

**Time**: 15 minutes

---

### Step 22: Testing alerting

#### Motivation

Alerting has subtle behavior: dedup should suppress duplicates, cooldown should delay resends, rate limiting should cap the total. Tests verify each of these with controlled inputs.

#### Concepts

**Testing dedup**:

```python
def test_dedup_same_signature(self):
    am = AlertManager(console=False)
    a1 = Alert(id="1", severity=Severity.CRITICAL, title="X", summary="Y")
    a2 = Alert(id="2", severity=Severity.CRITICAL, title="X", summary="Y")   # same title+summary
    assert am.emit(a1)   # first one goes through
    assert not am.emit(a2)   # second is deduped (same signature)
    assert len(am.get_timeline()) == 1
```

**Testing cooldown**:

```python
def test_cooldown_blocks_resend(self):
    am = AlertManager(console=False, cooldown_seconds=60)
    a = Alert(id="1", severity=Severity.CRITICAL, title="X", summary="Y")
    assert am.emit(a)
    assert not am.emit(Alert(id="2", severity=Severity.CRITICAL, title="X", summary="Y"))
```

**Testing rate limiting**:

```python
def test_rate_limit(self):
    am = AlertManager(console=False, max_alerts_per_minute=2)
    for i in range(5):
        alert = Alert(id=str(i), severity=Severity.INFO, title=f"Alert {i}", summary="test")
        result = am.emit(alert)
    assert sum(1 for a in am.get_timeline()) == 2   # only 2 got through
```

#### Build

Create `tests/test_alert.py`:

```python
import pytest
from datetime import datetime
from ddosguard.alert.manager import AlertManager
from ddosguard.core import Alert, Severity

class TestAlertManager:
    def test_emit_stores_alert(self):
        am = AlertManager(console=False, output_file=None)
        a = Alert(id="1", severity=Severity.CRITICAL, title="Test", summary="Test alert")
        assert am.emit(a)
        assert len(am.get_timeline()) == 1

    def test_dedup_same_signature(self):
        am = AlertManager(console=False, output_file=None)
        a1 = Alert(id="1", severity=Severity.CRITICAL, title="X", summary="Y")
        a2 = Alert(id="2", severity=Severity.CRITICAL, title="X", summary="Y")
        assert am.emit(a1)
        assert not am.emit(a2)
        assert len(am.get_timeline()) == 1

    def test_cooldown_blocks_resend(self):
        am = AlertManager(console=False, output_file=None, cooldown_seconds=60)
        a = Alert(id="1", severity=Severity.CRITICAL, title="X", summary="Y")
        assert am.emit(a)
        assert not am.emit(Alert(id="2", severity=Severity.CRITICAL, title="X", summary="Y"))

    def test_rate_limit(self):
        am = AlertManager(console=False, output_file=None, max_alerts_per_minute=2)
        for i in range(5):
            am.emit(Alert(id=str(i), severity=Severity.INFO, title=f"Alert {i}", summary="test"))
        assert len(am.get_timeline()) == 2

class TestAlertDirector:
    def test_urgent_filters(self):
        from ddosguard.alert.director import AlertDirector
        am = AlertManager(console=False, output_file=None)
        am.emit(Alert(id="1", severity=Severity.INFO, title="info", summary="test"))
        am.emit(Alert(id="2", severity=Severity.CRITICAL, title="crit", summary="test"))
        am.emit(Alert(id="3", severity=Severity.HIGH, title="high", summary="test"))
        director = AlertDirector(am)
        urgent = director.get_urgent()
        assert len(urgent) == 2
        assert all(a.severity in (Severity.CRITICAL, Severity.HIGH) for a in urgent)
```

#### Practice

1. Create `tests/test_alert.py` and run: `python -m pytest tests/test_alert.py -v`. All should pass.
2. Write your own test: test that `AlertManager.recent(seconds=10)` returns only alerts from the last 10 seconds.
3. Break it: set `cooldown_seconds=0` and verify that two alerts with the same signature both get through (no dedup when cooldown is 0).

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 25 minutes

---

## Phase 9: Dashboard & Controls (Steps 23–25)

### Step 23: The FastAPI dashboard backend

#### Motivation

Operators need to see what's happening. A web dashboard shows: current traffic stats, recent alerts, baseline values, mitigation status, whitelist controls, and pause/resume buttons. FastAPI provides the API that the dashboard front-end queries.

#### Concepts

**FastAPI basics**:

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class StatusResponse(BaseModel):
    running: bool
    paused: bool
    severity: str
    stage: int

@app.get("/api/status")
def get_status():
    return StatusResponse(running=True, paused=False, severity="INFO", stage=0)
```

FastAPI automatically:
- Parses query parameters and JSON bodies
- Validates them against Pydantic models
- Serializes return values to JSON
- Generates OpenAPI documentation at `/docs`

**Endpoints in this dashboard**:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/status` | GET | Current monitor status (running, paused, severity, stage) |
| `/api/stats` | GET | Current traffic statistics |
| `/api/baseline` | GET | All baseline buckets |
| `/api/alerts` | GET | Recent alerts (via AlertDirector) |
| `/api/mitigations` | GET | Current mitigation stage and rules |
| `/api/whitelist` | GET | Current whitelist |
| `/api/whitelist` | POST | Add an IP to the whitelist |
| `/api/control/pause` | POST | Pause the monitor |
| `/api/control/resume` | POST | Resume the monitor |

**Pydantic models for request validation**:

```python
class WhitelistRequest(BaseModel):
    ip: str

class ControlRequest(BaseModel):
    command: str   # "pause" or "resume"
```

These ensure the API receives the expected data types. If a request is missing a field or has the wrong type, FastAPI returns a 422 error automatically.

**Thread-safe state**:

The monitor runs in a background thread (Step 25). The dashboard runs in uvicorn's thread pool. Both access shared state (`MonitorState`). A `threading.Lock` protects reads and writes:

```python
class MonitorState:
    def __init__(self):
        self._lock = threading.Lock()
        self.current_stats = None
        self.current_score = None
        self.running = False
        self.paused = False
        ...

    def update(self, stats, score):
        with self._lock:
            self.current_stats = stats
            self.current_score = score
```

Without the lock, the dashboard might read `current_stats` while the monitor is writing it, resulting in partially-updated data.

#### Questions you would ask

**Q: Why use Pydantic models instead of plain dicts?**
A: Pydantic validates the data. If the front-end sends `{"ip": 123}` (an integer instead of a string), Pydantic catches it and returns a validation error. Without Pydantic, you'd have to manually check every field. Pydantic also generates JSON schemas, which the front-end can use to generate API clients.

**Q: Why separate state from the API?**
A: The state is shared between the monitor thread and the API threads. If the API directly modified the monitor's internal state, it would be coupled to the monitor's implementation. Instead, the API calls methods on the monitor (pause, resume, add whitelist) through a clean interface. The state object is just data — it doesn't know about the monitor or the API.

**Q: What happens if the monitor is paused and the dashboard queries stats?**
A: The dashboard still returns the last known stats (from `MonitorState`). The monitor stops updating them while paused, but the last values are still available. This is correct — the dashboard should show the last known state even when the monitor is paused.

**Q: Do I need to know HTML to write the dashboard?**
A: The backend (FastAPI) doesn't need HTML knowledge. The front-end (Step 24) is a single HTML file with embedded JavaScript — you need basic HTML and JS for that. The backend just serves the HTML file and the JSON API.

#### Build

Create `ddosguard/dashboard/__init__.py` (empty) and `ddosguard/dashboard/app.py`:

```python
from __future__ import annotations
import os
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ddosguard.core import Severity
from ddosguard.alert.director import AlertDirector

app = FastAPI(title="DDoS Guard Dashboard")

class MonitorState:
    def __init__(self):
        self._lock = __import__('threading').Lock()
        self.current_stats = None
        self.current_score = None
        self.running = False
        self.paused = False
        self.severity: Severity = Severity.INFO
        self.stage = 0
        self.whitelist: list = []
        self.mitigation_rules: list = []
        self._baseline = {}
        self._director: Optional[AlertDirector] = None
        self._ratelimiter = None

    def update(self, stats, score, stage, rules, whitelist):
        with self._lock:
            self.current_stats = stats
            self.current_score = score
            self.stage = stage
            self.mitigation_rules = rules
            self.whitelist = whitelist
            if score is not None:
                self.severity = score.severity

    def set_ready(self, running: bool):
        with self._lock:
            self.running = running

    def set_paused(self, paused: bool):
        with self._lock:
            self.paused = paused

    def add_whitelist(self, ip: str):
        with self._lock:
            if ip not in self.whitelist:
                self.whitelist.append(ip)

    def remove_whitelist(self, ip: str) -> bool:
        with self._lock:
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                return True
            return False

    def set_director(self, director: AlertDirector):
        with self._lock:
            self._director = director

    def set_ratelimiter(self, rl):
        with self._lock:
            self._ratelimiter = rl

    def set_baseline(self, baseline):
        with self._lock:
            self._baseline = baseline

state = MonitorState()

class WhitelistRequest(BaseModel):
    ip: str

class ControlRequest(BaseModel):
    command: str

@app.get("/api/status")
def get_status():
    return {
        "running": state.running,
        "paused": state.paused,
        "severity": state.severity.name,
        "stage": state.stage,
    }

@app.get("/api/stats")
def get_stats():
    with state._lock:
        if state.current_stats is None:
            return {"packet_rate": 0, "byte_rate": 0, "syn_ratio": 0, "per_proto": {}}
        s = state.current_stats
        return {
            "packet_rate": round(s.packet_rate, 2),
            "byte_rate": round(s.byte_rate, 2),
            "syn_ratio": round(s.syn_ratio, 3),
            "per_proto": s.per_proto,
        }

@app.get("/api/baseline")
def get_baseline():
    with state._lock:
        result = {}
        for key, bs in state._baseline.items():
            result[key] = {
                "mean": bs.mean, "stdev": bs.stdev,
                "count": bs.count, "p50": bs.p5, "p95": bs.p95,
            }
        return result

@app.get("/api/alerts")
def get_alerts():
    with state._lock:
        if state._director is None:
            return []
        return [
            {
                "id": a.id, "severity": a.severity.name,
                "title": a.title, "summary": a.summary,
                "timestamp": a.timestamp.isoformat(),
                "stage": a.stage, "source_ip": a.source_ip,
            }
            for a in state._director.get_timeline()
        ]

@app.get("/api/mitigations")
def get_mitigations():
    with state._lock:
        return {
            "stage": state.stage,
            "rules": state.mitigation_rules,
            "whitelist": state.whitelist,
        }

@app.get("/api/whitelist")
def get_whitelist():
    with state._lock:
        return {"whitelisted": state.whitelist}

@app.post("/api/whitelist")
def add_whitelist(req: WhitelistRequest):
    state.add_whitelist(req.ip)
    return {"whitelisted": state.whitelist, "added": req.ip}

@app.post("/api/control")
def control(req: ControlRequest):
    if req.command == "pause":
        state.set_paused(True)
        return {"paused": True}
    elif req.command == "resume":
        state.set_paused(False)
        return {"paused": False}
    raise HTTPException(status_code=400, detail="Unknown command")

@app.get("/")
def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(html_path):
        with open(html_path) as f:
            return f.read()
    return {"error": "Dashboard not found"}
```

#### Practice

1. Create `dashboard/__init__.py` and `dashboard/app.py`.
2. Install pyantic if not already (it's a FastAPI dependency): `python -c "import pydantic; print(pydantic.__version__)"`.
3. Start the server briefly to test:
   ```
   python -c "
   from ddosguard.dashboard.app import app
   from uvicorn import Config
   import threading

   def run():
       config = Config(app=app, host='127.0.0.1', port=8787, log_level='warning')
       config.run()

   t = threading.Thread(target=run, daemon=True)
   t.start()
   import time; time.sleep(1)
   import urllib.request
   resp = urllib.request.urlopen('http://127.0.0.1:8787/api/status')
   print(resp.read().decode())
   "
   ```
   Expected: `{"running":false,"paused":false,"severity":"INFO","stage":0}`.

**Verify**: The API returns JSON status. The server starts and responds.

**Time**: 30 minutes

---

### Step 24: The dashboard front-end

#### Motivation

The API (Step 23) provides data. The front-end displays it. A single HTML file with embedded JavaScript polls the API every few seconds and updates the display. No build step, no framework — just HTML, CSS, and vanilla JS.

#### Concepts

**The dashboard layout**:

- Header: title, status badge (RUNNING/PAUSED, severity color)
- Stats panel: current packet rate, byte rate, SYN ratio, protocol breakdown
- Sparkline chart: packet rate over time (canvas-based)
- Alerts panel: list of recent alerts, color-coded by severity
- Baseline panel: table of bucket keys and their means
- Whitelist panel: list of whitelisted IPs, add/remove controls
- Control buttons: Pause / Resume

**Polling**:

```javascript
setInterval(() => {
    fetch('/api/stats').then(r => r.json()).then(data => {
        updateStats(data);
    });
}, 2000);
```

Every 2 seconds, fetch fresh data from the API and update the display. This is simple and works well for a dashboard that doesn't need real-time precision.

**Canvas sparkline**:

```javascript
const canvas = document.getElementById('sparkline');
const ctx = canvas.getContext('2d');
// ... draw line chart of recent values
```

The canvas element provides a drawing surface. You draw the sparkline by connecting data points with lines. This is more performant than SVG for simple charts and doesn't require an external library.

**Severity colors**:

- INFO: green
- LOW: blue
- MEDIUM: yellow/orange
- HIGH: orange
- CRITICAL: red

These colors are used for the status badge and alert items, so operators can assess severity at a glance.

#### Questions you would ask

**Q: Why not use a framework like React or Vue?**
A: For a single-page dashboard with simple polling, a framework is overkill. Vanilla JS is simpler, has no dependencies, and is easy to understand. If the dashboard grows complex (real-time updates via WebSocket, complex interactions), a framework would help. For this project, vanilla JS is sufficient.

**Q: Why poll every 2 seconds instead of using WebSocket?**
A: Polling is simpler to implement and works with any web server (no WebSocket support needed). For a dashboard that updates every few seconds, polling is fine. WebSocket would be better for sub-second updates or many concurrent clients. This project keeps it simple with polling.

**Q: What if the API is down?**
A: The `fetch()` call fails. In the current code, errors are caught and logged to the console. The dashboard keeps showing the last known data. In a more robust version, you'd show a "connection lost" indicator.

**Q: How do I add a new panel to the dashboard?**
A: Add HTML for the panel, add a fetch call for the data, add a render function to update the DOM. The pattern is consistent: fetch data → update DOM. Each panel is independent.

#### Build

Create `ddosguard/dashboard/static/__init__.py` (empty) and `ddosguard/dashboard/static/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DDoS Guard Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d1117; color: #c9d1d9; padding: 20px; }
.header { display: flex; justify-content: space-between; align-items: center;
           padding: 16px; background: #161b22; border-radius: 8px; margin-bottom: 20px; }
.title { font-size: 20px; font-weight: 600; }
.status-badge { padding: 6px 12px; border-radius: 20px; font-size: 13px;
                font-weight: 600; text-transform: uppercase; }
.badge-running { background: #238636; color: #fff; }
.badge-paused { background: #9e6a03; color: #fff; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 16px; margin-bottom: 20px; }
.card { background: #161b22; border-radius: 8px; padding: 16px; }
.card h3 { font-size: 14px; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; }
.stat { display: flex; justify-content: space-between; padding: 8px 0;
        border-bottom: 1px solid #21262d; }
.stat:last-child { border-bottom: none; }
.stat-value { font-weight: 600; }
.alert-item { padding: 8px; margin: 4px 0; border-radius: 4px;
              font-size: 13px; border-left: 3px solid; }
.alerts-critical { border-color: #da3633; background: rgba(218,54,51,0.1); }
.alerts-high { border-color: #f0883e; background: rgba(240,136,62,0.1); }
.alerts-medium { border-color: #d29922; background: rgba(210,153,34,0.1); }
.alerts-low { border-color: #58a6ff; background: rgba(88,166,255,0.1); }
.alerts-info { border-color: #3fb950; background: rgba(63,185,80,0.1); }
button { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer;
         font-size: 13px; font-weight: 500; margin: 4px; }
.btn-pause { background: #9e6a03; color: #fff; }
.btn-resume { background: #238636; color: #fff; }
.btn-add { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
input { padding: 8px; border-radius: 6px; border: 1px solid #30363d;
        background: #0d1117; color: #c9d1d9; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-weight: 500; }
</style>
</head>
<body>
<div class="header">
  <div class="title">DDoS Guard Dashboard</div>
  <div id="statusBadge" class="status-badge badge-paused">PAUSED</div>
</div>
<div class="grid">
  <div class="card">
    <h3>Traffic Stats</h3>
    <div id="statsPanel"></div>
  </div>
  <div class="card">
    <h3>Packet Rate (last 30s)</h3>
    <canvas id="sparkline" width="400" height="80"></canvas>
  </div>
  <div class="card">
    <h3>Recent Alerts</h3>
    <div id="alertsPanel"></div>
  </div>
  <div class="card">
    <h3>Baseline</h3>
    <div id="baselinePanel"></div>
  </div>
  <div class="card">
    <h3>Whitelist</h3>
    <div id="whitelistPanel"></div>
    <input id="whitelistInput" placeholder="IP address" style="width:100%;margin-top:8px;">
    <button class="btn-add" onclick="addWhitelist()">Add</button>
  </div>
  <div class="card">
    <h3>Control</h3>
    <button id="controlBtn" class="btn-pause" onclick="toggleControl()">Pause</button>
  </div>
</div>
<script>
const SEV_COLOR = {INFO:'#3fb950',LOW:'#58a6ff',MEDIUM:'#d29922',HIGH:'#f0883e',CRITICAL:'#da3633'};
const SEV_CLASS = {INFO:'alerts-info',LOW:'alerts-low',MEDIUM:'alerts-medium',HIGH:'alerts-high',CRITICAL:'alerts-critical'};
let history = [];
let controlLabel = 'Pause';

function fetchAll() {
  Promise.all([
    fetch('/api/status').then(r=>r.json()),
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/alerts').then(r=>r.json()),
    fetch('/api/baseline').then(r=>r.json()),
    fetch('/api/whitelist').then(r=>r.json()),
  ]).then(([status,stats,alerts,baseline,wl])=>{
    document.getElementById('statusBadge').textContent = status.running ? (status.paused?'PAUSED':'RUNNING') : 'STOPPED';
    document.getElementById('statusBadge').className = 'status-badge ' + (status.running?(status.paused?'badge-paused':'badge-running'):'badge-paused');
    document.getElementById('controlBtn').textContent = controlLabel;
    updateStats(stats);
    updateAlerts(alerts);
    updateBaseline(baseline);
    updateWhitelist(wl);
  });
}

function updateStats(s) {
  document.getElementById('statsPanel').innerHTML = `
    <div class="stat"><span>Packet Rate</span><span class="stat-value">${s.packet_rate.toFixed(1)} pps</span></div>
    <div class="stat"><span>Byte Rate</span><span class="stat-value">${(s.byte_rate/1024).toFixed(1)} KB/s</span></div>
    <div class="stat"><span>SYN Ratio</span><span class="stat-value">${(s.syn_ratio*100).toFixed(1)}%</span></div>
    <div class="stat"><span>TCP</span><span class="stat-value">${s.per_proto[6]||0}</span></div>
    <div class="stat"><span>UDP</span><span class="stat-value">${s.per_proto[17]||0}</span></div>`;
  history.push(s.packet_rate);
  if(history.length>30) history.shift();
  drawSparkline();
}

function drawSparkline() {
  const c = document.getElementById('sparkline');
  const ctx = c.getContext('2d');
  ctx.clearRect(0,0,c.width,c.height);
  if(history.length<2) return;
  const max = Math.max(...history, 1);
  const step = c.width / (history.length-1);
  ctx.beginPath();
  ctx.strokeStyle = SEV_COLOR[history.length>10?'HIGH':'INFO'];
  ctx.lineWidth = 2;
  ctx.moveTo(0, c.height - (history[0]/max)*c.height);
  for(let i=1;i<history.length;i++){
    ctx.lineTo(i*step, c.height - (history[i]/max)*c.height);
  }
  ctx.stroke();
}

function updateAlerts(alerts) {
  const panel = document.getElementById('alertsPanel');
  panel.innerHTML = alerts.slice(0,20).map(a=>`
    <div class="alert-item ${SEV_CLASS[a.severity]}" style="border-left-color:${SEV_COLOR[a.severity]}">
      <strong>${a.severity}</strong>: ${a.title}
    </div>`).join('') || '<div style="color:#8b949e;font-size:13px;">No alerts</div>';
}

function updateBaseline(b) {
  const panel = document.getElementById('baselinePanel');
  const entries = Object.entries(b).slice(0,10);
  panel.innerHTML = entries.length ? `<table><tr><th>Bucket</th><th>Mean</th><th>Stdev</th><th>Count</th></tr>
    ${entries.map(([k,v])=>`<tr><td>${k}</td><td>${v.mean.toFixed(1)}</td><td>${v.stdev.toFixed(1)}</td><td>${v.count}</td></tr>`).join('')}</table>` :
    '<div style="color:#8b949e;font-size:13px;">No baseline data</div>';
}

function updateWhitelist(wl) {
  const panel = document.getElementById('whitelistPanel');
  panel.innerHTML = wl.whitelisted.length ? `<table><tr><th>IP</th><th></th></tr>
    ${wl.whitelisted.map(ip=>`<tr><td>${ip}</td><td><button class="btn-add" onclick="removeWhitelist('${ip}')" style="padding:4px 8px;font-size:11px;">Remove</button></td></tr>`).join('')}</table>` :
    '<div style="color:#8b949e;font-size:13px;">No whitelisted IPs</div>';
}

function addWhitelist() {
  const ip = document.getElementById('whitelistInput').value.trim();
  if(ip) fetch('/api/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip})}).then(()=>fetchAll());
}

function removeWhitelist(ip) {
  fetch('/api/whitelist?remove='+encodeURIComponent(ip)).then(()=>fetchAll());
}

function toggleControl() {
  const cmd = controlLabel==='Pause'?'resume':'pause';
  fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({command:cmd})}).then(r=>r.json()).then(()=>{
    controlLabel = cmd==='pause'?'Pause':'Resume';
    fetchAll();
  });
}

setInterval(fetchAll, 2000);
fetchAll();
</script>
</body>
</html>
```

#### Practice

1. Create `dashboard/static/__init__.py` and `dashboard/static/index.html`.
2. Start the server (same as Step 23 practice) and open `http://127.0.0.1:8787` in a browser. You should see the dashboard with "STOPPED" status and empty panels.
3. The dashboard polls every 2 seconds. When the monitor is running (Step 25), the panels will populate with live data.

**Verify**: The dashboard HTML loads. The status badge shows "STOPPED" when no monitor is running.

**Time**: 20 minutes

---

### Step 25: MonitorRunner — the main loop

#### Motivation

All the pieces exist now: packet generator, windowing, baseline, detection, mitigation, alerting, dashboard. The MonitorRunner is the glue — it runs the main loop that ties everything together. It's the heart of the system.

#### Concepts

**The main loop**:

```python
def run(self):
    while self.running():
        pkt = next(self.source.iter_packets(0.1))
        self.aggregator.add(pkt)
        if self.aggregator.is_complete(pkt.ts):
            stats = self.aggregator.finalize()
            self.baseline.observe(stats, pkt.ts)
            score = self.scorer.score(stats, self.baseline)
            self.mitigator.apply(score, stats)
            self.alert_manager.emit(...)
            self.state.update(stats, score, ...)
```

Each iteration:
1. Get a packet from the source (with a small delay for realism).
2. Add it to the current window.
3. If the window is complete, finalize it.
4. Observe the stats in the baseline (trains the baseline).
5. Score the stats (detection).
6. Apply mitigation based on the score.
7. Emit alerts if severity is high enough.
8. Update the shared state (dashboard reads this).

**Thread safety**:

The monitor runs in one thread. The dashboard API runs in uvicorn's threads. They share `MonitorState`, which is protected by a `threading.Lock`. The monitor acquires the lock to write, the API acquires it to read. Neither can conflict.

**Pause/resume**:

```python
self.paused_event = threading.Event()

def running(self):
    return self.paused_event.is_set()

def pause(self):
    self.paused_event.clear()   # clear = not running

def resume(self):
    self.paused_event.set()   # set = running
```

`threading.Event` is a thread-safe boolean flag. `set()` makes it true, `clear()` makes it false, `is_set()` checks it. The main loop checks `running()` each iteration — if paused, it skips packet processing.

**Graceful shutdown**:

```python
def stop(self):
    self.paused_event.clear()
    self.done_event.set()   # signals the thread to exit
```

A separate `done_event` signals the thread to exit. The main loop checks `done_event` in addition to `running()`.

#### Questions you would ask

**Q: Why is the monitor a class with start/stop rather than just a function?**
A: Because it needs to manage state (the aggregator, scorer, baseline, etc.) and be controllable (pause, resume, stop) from the outside. A class encapsulates this state and behavior. The CLI (Step 26) creates a MonitorRunner, starts it, and can pause/resume it.

**Q: Why does the loop call `iter_packets(0.1)` with a delay?**
A: The `delay` parameter in `iter_packets` adds a small sleep between packets (for realism — real packets don't arrive instantly). In the monitor loop, we call it with a small window to get one packet at a time. The delay simulates real-time packet arrival.

**Q: What happens if the source runs out of packets?**
A: For the synthetic generator, it generates packets indefinitely (it loops forever). For a real pcap source, it would eventually exhaust the file and stop. The monitor should handle this gracefully — either loop the pcap or stop when exhausted.

**Q: Why does the baseline observe every window?**
A: Because the baseline learns from every observation. Even during an attack, observing the traffic trains the baseline (though you might not want to train on attack traffic — in production, you'd only observe when the score is below a threshold, so the baseline represents normal traffic, not attack traffic). This project observes everything for simplicity. In production, you'd filter.

#### Build

Create `ddosguard/monitor.py`:

```python
from __future__ import annotations
import logging
import threading
import time
from datetime import datetime
from ddosguard.capture.base import PacketSource, SyntheticGenerator
from ddosguard.metrics.window import WindowAggregator
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.scorer import CompositeScorer
from ddosguard.mitigate.ratelimit import RateLimiter
from ddosguard.mitigate.firewall import FirewallManager
from ddosguard.alert.manager import AlertManager
from ddosguard.dashboard.app import MonitorState

logger = logging.getLogger("ddosguard")

class MonitorRunner:
    def __init__(self, config=None):
        self._config = config
        self._source: PacketSource = SyntheticGenerator()
        self._aggregator = WindowAggregator(window_seconds=10.0)
        self._baseline = BaselineStore(config) if config else BaselineStore.__new__(BaselineStore)
        self._scorer = CompositeScorer(config)
        self._ratelimiter = RateLimiter()
        self._firewall = FirewallManager(dry_run=True)
        self._alert_manager = AlertManager(config)
        self._state = MonitorState()
        self._pause_event = threading.Event()
        self._done_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._stage = 0
        if config is not None:
            try:
                cap = config.capture
                self._source = SyntheticGenerator(
                    mode=cap.get("mode", "normal"),
                    attack_family=cap.get("attack_family", "volumetric"),
                    base_rate=float(cap.get("base_rate", 50)),
                )
            except Exception:
                pass

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._pause_event.set()
        self._done_event.clear()
        self._baseline.set_ready(True)
        self._state.set_ready(True)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Monitor started")

    def stop(self):
        self._done_event.set()
        self._pause_event.clear()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._state.set_ready(False)
        logger.info("Monitor stopped")

    def pause(self):
        self._pause_event.clear()
        self._state.set_paused(True)
        logger.info("Monitor paused")

    def resume(self):
        self._pause_event.set()
        self._state.set_paused(False)
        logger.info("Monitor resumed")

    def _running(self) -> bool:
        return self._pause_event.is_set() and not self._done_event.is_set()

    def _run(self):
        logger.info("Monitor loop starting")
        while self._running():
            try:
                pkt = next(self._source.iter_packets(0.1))
                self._aggregator.add(pkt)
                if self._aggregator.is_complete(pkt.ts):
                    stats = self._aggregator.finalize()
                    self._baseline.observe(stats, pkt.ts)
                    score = self._scorer.score(stats, self._baseline)
                    self._apply_mitigation(score, stats, pkt.ts)
                    self._emit_alert(score, stats, pkt.ts)
                    self._state.update(stats, score, self._stage,
                                       self._firewall._active, self._ratelimiter.stats()["whitelisted"])
                    self._aggregator.reset()
            except StopIteration:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(1)
        logger.info("Monitor loop exited")

    def _apply_mitigation(self, score, stats, ts):
        stage = 0
        if score.severity == Severity.CRITICAL:
            stage = 4
        elif score.severity == Severity.HIGH:
            stage = 2
        elif score.severity == Severity.MEDIUM:
            stage = 1
        self._stage = stage
        if stage > 0:
            rules = self._firewall.generate_rules(stage, score.severity.name,
                                                   config=self._config,
                                                   whitelist=self._state.whitelist if hasattr(self._state, 'whitelist') else [])
            self._firewall.apply(rules)

    def _emit_alert(self, score, stats, ts):
        if score.severity in (Severity.CRITICAL, Severity.HIGH):
            alert = Alert(
                id=f"alert-{int(ts.timestamp())}",
                severity=score.severity,
                title=f"{score.severity.name} {score.classification or 'anomaly'} detected",
                summary=f"Score: {score.total:.2f}, Rate: {stats.packet_rate:.1f} pps, Stage: {self._stage}",
                timestamp=ts,
                stage=self._stage,
            )
            self._alert_manager.emit(alert)
```

#### Practice

1. Create `monitor.py`.
2. Test the full pipeline:
   ```
   python -c "
   from ddosguard.monitor import MonitorRunner
   from ddosguard.capture.base import SyntheticGenerator
   import time

   runner = MonitorRunner()
   runner._source = SyntheticGenerator(mode='attack', attack_family='syn_flood',
                                        attack_start=__import__('datetime').datetime.now(),
                                        attack_duration=15, attack_mult=30)
   runner.start()
   time.sleep(12)
   print('Status:', runner._state._lock)  # access state
   print('Stats:', runner._state.current_stats)
   print('Score:', runner._state.current_score)
   runner.stop()
   "
   ```
   This runs the monitor for 12 seconds with attack traffic, then prints the final state.

**Verify**: The monitor starts, processes packets, updates state. After stopping, state contains the last stats and score.

**Time**: 25 minutes

---

## Phase 10: CLI & Packaging (Steps 26–28)

### Step 26: The command-line interface

#### Motivation

The monitor can be controlled programmatically, but operators need a command-line interface to start the monitor, run a baseline collection, replay a pcap, simulate an attack, and test alerting. `argparse` is the standard Python library for building CLIs.

#### Concepts

**argparse basics**:

```python
import argparse

parser = argparse.ArgumentParser(description="DDoS Guard CLI")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
args = parser.parse_args()
```

`add_argument` defines a flag. `action="store_true"` means the flag is a boolean (present = True, absent = False). `parse_args()` parses `sys.argv` and returns the parsed arguments.

**Subcommands**:

```python
sub = parser.add_subparsers(dest="command")

baseline_cmd = sub.add_parser("baseline", help="Collect baseline data")
baseline_cmd.add_argument("--seconds", type=int, default=600, help="Collection duration")

monitor_cmd = sub.add_parser("monitor", help="Run the monitor")
monitor_cmd.add_argument("--config", type=str, default="config.yaml", help="Config file path")
```

Each subcommand has its own parser with its own arguments. `dest="command"` puts the chosen subcommand name in `args.command`.

**Why subcommands**:

Different operations (baseline, monitor, replay, simulate, alert) have different arguments and do different things. Subcommands organize them cleanly: `python -m ddosguard baseline --seconds 300` vs `python -m ddosguard monitor --config config.yaml`.

#### Questions you would ask

**Q: Why use argparse instead of clicking buttons in the dashboard?**
A: The dashboard is for monitoring and light control (pause/resume, whitelist). The CLI is for starting/stopping the system, running batch operations (baseline collection), and automation (scripts that start the monitor at boot). Both are useful for different purposes.

**Q: What's the difference between `--verbose` and `--config`?**
A: `--verbose` is a flag (boolean, present or not). `--config` takes a value (a string path). `action="store_true"` creates a flag. `type=str` creates a value argument.

**Q: What happens if I run the CLI with no arguments?**
A: argparse shows the help text and exits. This is the default behavior when no subcommand is given. You can also add a default command.

#### Build

Create `ddosguard/cli.py`:

```python
from __future__ import annotations
import argparse
import logging
import sys
import time
from ddosguard.monitor import MonitorRunner
from ddosguard.capture.base import SyntheticGenerator
from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config

def main():
    parser = argparse.ArgumentParser(description="DDoS Guard CLI")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    sub = parser.add_subparsers(dest="command")

    b = sub.add_parser("baseline", help="Collect baseline")
    b.add_argument("--seconds", type=int, default=600)

    m = sub.add_parser("monitor", help="Run monitor")
    m.add_argument("--config", type=str, default="config.yaml")

    r = sub.add_parser("replay", help="Replay packets")
    r.add_argument("--file", type=str, default=None)

    s = sub.add_parser("simulate", help="Simulate attack")
    s.add_argument("--family", type=str, default="syn_flood")
    s.add_argument("--seconds", type=int, default=10)

    a = sub.add_parser("alert", help="Test alerting")
    a.add_argument("--count", type=int, default=5)

    d = sub.add_parser("dashboard", help="Start dashboard")
    d.add_argument("--port", type=int, default=8787)

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(name)s: %(message)s")

    if args.command == "baseline":
        do_baseline(args)
    elif args.command == "monitor":
        do_monitor(args)
    elif args.command == "simulate":
        do_simulate(args)
    elif args.command == "alert":
        do_alert_test(args)
    elif args.command == "dashboard":
        do_dashboard(args)
    else:
        parser.print_help()

def do_baseline(args):
    config = Config.load(None)
    store = BaselineStore(config, data_dir="data")
    store.set_ready(True)
    gen = SyntheticGenerator(mode="normal", base_rate=100)
    agg = __import__('ddosguard.metrics.window', fromlist=['WindowAggregator']).WindowAggregator(1.0)
    start = time.time()
    while time.time() - start < args.seconds:
        for pkt in gen.iter_packets(1.0):
            agg.add(pkt)
            if agg.is_complete(pkt.ts):
                stats = agg.finalize()
                store.observe(stats, pkt.ts)
                agg.reset()
    store.save()
    print(f"Baseline saved: {len(store.all())} buckets")

def do_monitor(args):
    config = Config.load(args.config)
    runner = MonitorRunner(config)
    runner.start()
    print("Monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        runner.stop()
        print("Monitor stopped")

def do_simulate(args):
    from datetime import datetime
    gen = SyntheticGenerator(mode="attack", attack_family=args.family,
                             attack_start=datetime.now(), attack_duration=args.seconds, attack_mult=50)
    count = 0
    for pkt in gen.iter_packets(args.seconds):
        count += 1
    print(f"Generated {count} attack packets")

def do_alert_test(args):
    from ddosguard.core import Alert, Severity
    from ddosguard.alert.manager import AlertManager
    import uuid
    am = AlertManager(console=True, output_file="data/alerts.jsonl")
    for i in range(args.count):
        am.emit(Alert(id=str(uuid.uuid4()), severity=Severity.CRITICAL if i==0 else Severity.HIGH,
                      title=f"Test alert {i}", summary=f"Test message {i}", stage=1))
    print(f"Emitted {args.count} alerts")

def do_dashboard(args):
    from uvicorn import Config
    from ddosguard.dashboard.app import app
    config = Config(app=app, host="127.0.0.1", port=args.port, log_level="info")
    config.run()
```

#### Practice

1. Create `cli.py`.
2. Test the help: `python -m ddosguard --help`. Should show the available subcommands.
3. Test simulate: `python -m ddosguard simulate --family syn_flood --seconds 2`. Should print a packet count.
4. Test alert: `python -m ddosguard alert --count 3`. Should print 3 alert messages.

**Verify**: CLI responds to `--help`. Simulate and alert commands work.

**Time**: 25 minutes

---

### Step 27: Making `python -m ddosguard` work

#### Motivation

`python -m ddosguard` runs the package as a module. For this to work, the package needs a `__main__.py` file. This file is executed when the package is run with `-m`.

#### Concepts

**What `__main__.py` does**:

When you run `python -m ddosguard`, Python looks for `ddosguard/__main__.py` and executes it. The conventional content is just to import and call the CLI's `main()` function:

```python
from ddosguard.cli import main
main()
```

This delegates to the CLI, which parses arguments and dispatches to the appropriate command.

**Why not put the CLI code in `__main__.py` directly**:

Separating `__main__.py` (entry point) from `cli.py` (CLI logic) is cleaner. `__main__.py` is the entry point — it should be minimal. `cli.py` contains the argument parsing and command dispatch — it can be imported and tested separately.

#### Questions you would ask

**Q: What's the difference between `python ddosguard/cli.py` and `python -m ddosguard`?**
A: `python ddosguard/cli.py` runs the file directly — the `__package__` variable is not set, and relative imports might not work. `python -m ddosguard` runs the package as a module — `__package__` is set to `"ddosguard"`, and all imports work correctly. The `-m` form is the correct way to run a package.

**Q: Can I have other entry points?**
A: Yes. You could add `console_scripts` in `pyproject.toml` to create a `ddosguard` command that works from anywhere (after `pip install`). That's a later enhancement — for now, `python -m ddosguard` is sufficient.

#### Build

Create `ddosguard/__main__.py`:

```python
from ddosguard.cli import main
main()
```

#### Practice

1. Create `__main__.py`.
2. Run `python -m ddosguard --help`. Should show the CLI help.
3. Run `python -m ddosguard simulate --seconds 1`. Should generate packets.

**Verify**: `python -m ddosguard` works and shows help.

**Time**: 5 minutes

---

### Step 28: Configuration file

#### Motivation

Hard-coded values (base_rate=50, window_seconds=10, weights, thresholds) should be configurable without changing code. A YAML config file drives all behavior.

#### Concepts

**YAML format**:

```yaml
capture:
  mode: normal
  base_rate: 100

baseline:
  data_dir: data

detection:
  weights:
    volume: 0.30
    protocol: 0.20
    source: 0.20
    port: 0.15
    syn: 0.15
  confirmation_damping: 0.8

mitigation:
  default_rate: 100
  default_burst: 200

alerting:
  cooldown_seconds: 60
  max_alerts_per_minute: 10
  console: true
  output_file: data/alerts.jsonl

dashboard:
  port: 8787
```

YAML is human-readable and supports nested structures (dictionaries and lists). PyYAML parses it into Python dicts and lists.

**Config class**:

```python
class Config:
    def __init__(self, data):
        self._data = data or {}

    @property
    def capture(self):
        return self._data.get("capture", {})

    @property
    def detection(self):
        return self._data.get("detection", {})

    ...
```

The Config class wraps the parsed YAML dict and provides property access. Code that needs config values reads them through the Config object, not directly from the dict.

**Loading**:

```python
@classmethod
def load(cls, path=None):
    if path is None:
        path = "config.yaml"
    if os.path.exists(path):
        with open(path) as f:
            return cls(yaml.safe_load(f))
    return cls({})
```

If the config file doesn't exist, returns an empty config (all defaults). This is graceful — the system works without a config file, just with defaults.

#### Questions you would ask

**Q: Why YAML and not JSON?**
A: YAML is more readable for configuration (no quotes needed for strings, supports comments). JSON is more strict and portable. For configuration files that humans edit, YAML is preferred. For data files that programs generate (like baseline.json), JSON is preferred.

**Q: What if the config file has an error?**
A: `yaml.safe_load()` raises an exception. In this project, the exception propagates — the user sees the error and fixes the file. In a more robust version, you'd catch the error and fall back to defaults with a warning.

**Q: Can I use environment variables instead?**
A: You could. Environment variables are common for deployment (secrets, endpoints). For this project, a YAML file is simpler for learning. In production, you'd combine both: YAML for general config, environment variables for secrets.

#### Build

Create `config.yaml`:

```yaml
capture:
  mode: normal
  base_rate: 100

baseline:
  data_dir: data

detection:
  weights:
    volume: 0.30
    protocol: 0.20
    source: 0.20
    port: 0.15
    syn: 0.15
  confirmation_damping: 0.8

mitigation:
  default_rate: 100
  default_burst: 200

alerting:
  cooldown_seconds: 60
  max_alerts_per_minute: 10
  console: true
  output_file: data/alerts.jsonl

dashboard:
  port: 8787
```

Add `Config` to `ddosguard/config.py`:

```python
from __future__ import annotations
import os
import yaml
from typing import Any, Dict

class Config:
    def __init__(self, data: Dict[str, Any] = None):
        self._data = data or {}

    @classmethod
    def load(cls, path: str = None) -> "Config":
        if path is None:
            path = "config.yaml"
        if os.path.exists(path):
            with open(path) as f:
                return cls(yaml.safe_load(f) or {})
        return cls({})

    @property
    def capture(self) -> Dict:
        return self._data.get("capture", {})

    @property
    def baseline(self) -> Dict:
        return self._data.get("baseline", {})

    @property
    def detection(self) -> Dict:
        return self._data.get("detection", {})

    @property
    def mitigation(self) -> Dict:
        return self._data.get("mitigation", {})

    @property
    def alerting(self) -> Dict:
        return self._data.get("alerting", {})

    @property
    def dashboard(self) -> Dict:
        return self._data.get("dashboard", {})
```

#### Practice

1. Create `config.py` and `config.yaml`.
2. Test loading: `python -c "from ddosguard.config import Config; c = Config.load(); print('capture mode:', c.capture.get('mode'))"`.
3. Test with missing file: rename `config.yaml` to `config.yaml.bak`, reload. Should get empty config (no error).

**Verify**: Config loads from YAML. Missing file gives empty config without error.

**Time**: 15 minutes

---

## Phase 11: Testing & Polish (Steps 29–31)

### Step 29: Testing detection

#### Motivation

Detection is the core of the system. Each signal and the composite scorer need tests that verify they produce the right scores for known inputs. These tests use pre-built `TrafficStats` objects so they don't depend on the packet generator or windowing — pure detection logic.

#### Concepts

**Testing signals in isolation**:

For each signal, create a `TrafficStats` with known values, a `BaselineStore` with known baseline values, call the signal function, and check the score.

```python
def test_volume_signal_high_traffic():
    baseline = BaselineStore.__new__(BaselineStore)
    baseline.buckets["weekday-14:packet_rate"] = BaselineStats(mean=100, stdev=10)
    baseline._ready = True

    stats = TrafficStats(
        window=TrafficWindow(start=datetime.now(), end=datetime.now()),
        per_proto={6: 100},
        syn_ratio=0.1,
        byte_rate=50000,
    )
    stats.window.packet_count = 1000

    result = volume_signal(stats, baseline)
    assert result.score > 0.5   # 10x traffic should be high
```

**Testing the composite scorer**:

Create a baseline, train it with normal traffic, then score normal traffic (should be low) and attack traffic (should be high).

#### Build

Create `tests/test_detection.py`:

```python
import pytest
from datetime import datetime, timedelta
from ddosguard.core import TrafficStats, TrafficWindow, BaselineStats, Severity
from ddosguard.baseline.store import BaselineStore
from ddosguard.detect.signals import volume_signal, syn_signal, protocol_signal, source_signal, port_signal
from ddosguard.detect.scorer import CompositeScorer

def make_stats(packet_count=500, byte_count=250000, syn_count=0, protocol_counts=None):
    now = datetime.now()
    w = TrafficWindow(start=now - timedelta(seconds=10), end=now)
    w.packet_count = packet_count
    w.byte_count = byte_count
    w.syn_count = syn_count
    if protocol_counts:
        w.protocol_counts = protocol_counts
    return w.finalize()

class TestVolumeSignal:
    def test_normal_traffic_low_score(self):
        baseline = BaselineStore.__new__(BaselineStore)
        baseline._ready = True
        baseline.buckets["weekday-14:packet_rate"] = BaselineStats(mean=100, stdev=10)
        stats = make_stats(packet_count=100, byte_count=50000)
        stats.window.start = datetime.now()
        result = volume_signal(stats, baseline)
        assert result.score < 0.3

    def test_high_traffic_high_score(self):
        baseline = BaselineStore.__new__(BaselineStore)
        baseline._ready = True
        baseline.buckets["weekday-14:packet_rate"] = BaselineStats(mean=100, stdev=10)
        stats = make_stats(packet_count=500, byte_count=250000)
        stats.window.start = datetime.now()
        result = volume_signal(stats, baseline)
        assert result.score > 0.5

class TestSynSignal:
    def test_low_syn_ratio_zero_score(self):
        baseline = BaselineStore.__new__(BaselineStore)
        baseline._ready = True
        stats = make_stats(packet_count=1000, syn_count=100)
        stats.syn_ratio = 0.1
        result = syn_signal(stats, baseline)
        assert result.score == 0.0

    def test_high_syn_ratio_high_score(self):
        baseline = BaselineStore.__new__(BaselineStore)
        baseline._ready = True
        stats = make_stats(packet_count=1000, syn_count=900)
        stats.syn_ratio = 0.9
        result = syn_signal(stats, baseline)
        assert result.score > 0.5

class TestCompositeScorer:
    def test_normal_traffic_low_score(self):
        config = type('Config', (), {'detection': {}})()
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        scorer = CompositeScorer(config)
        now = datetime.now()
        for i in range(20):
            w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
            w.packet_count = 500
            w.byte_count = 250000
            baseline.observe(w.finalize(), now)
        stats = make_stats(packet_count=550, byte_count=275000)
        stats.window.start = datetime.now()
        score = scorer.score(stats, baseline)
        assert score.total < 0.3
        assert score.severity == Severity.INFO

    def test_attack_traffic_high_score(self):
        config = type('Config', (), {'detection': {}})()
        baseline = BaselineStore(config, data_dir="data")
        baseline.set_ready(True)
        scorer = CompositeScorer(config)
        now = datetime.now()
        for i in range(20):
            w = TrafficWindow(start=now-timedelta(seconds=10), end=now)
            w.packet_count = 500
            w.byte_count = 250000
            baseline.observe(w.finalize(), now)
        stats = make_stats(packet_count=5000, byte_count=2500000, syn_count=4500)
        stats.window.start = datetime.now()
        stats.window.protocol_counts = {6: 5000}
        stats.syn_ratio = 0.9
        score = scorer.score(stats, baseline)
        assert score.total > 0.5
```

#### Practice

1. Create `tests/test_detection.py` and run: `python -m pytest tests/test_detection.py -v`.
2. Write your own test: test that the protocol signal returns 0 for balanced traffic (e.g., 60% TCP, 40% UDP — both below 80%).
3. Break it: change the SYN threshold in `signals.py` from 0.3 to 0.1. Run `test_high_syn_ratio_high_score` — it should still pass (0.9 > 0.1). Run `test_low_syn_ratio_zero_score` — it should fail (0.1 is not below 0.1). Fix the threshold back to 0.3.

**Verify**: All tests pass. You wrote at least one test yourself.

**Time**: 30 minutes

---

### Step 30: Testing alerts and firewall

#### Motivation

Alerting and firewall generation have their own logic that needs verification. Alert tests verify dedup, cooldown, and rate limiting. Firewall tests verify rule generation for each stage.

#### Build

Create `tests/test_firewall.py`:

```python
import pytest
from ddosguard.mitigate.firewall import FirewallManager

class TestFirewallManager:
    def test_stage_zero_no_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=0, severity="HIGH")
        assert len(rules) == 0

    def test_stage_one_rate_limit_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=1, severity="MEDIUM")
        assert any("limit" in r for r in rules)

    def test_stage_two_recent_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=2, severity="HIGH")
        assert any("recent" in r for r in rules)

    def test_stage_four_drop_rules(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=4, severity="CRITICAL")
        assert any("DROP" in r for r in rules)

    def test_whitelist_first(self):
        fw = FirewallManager(dry_run=True)
        rules = fw.generate_rules(stage=2, severity="HIGH", whitelist=["10.0.0.1"])
        whitelist_rule = next((r for r in rules if "10.0.0.1" in r), None)
        drop_rules = [r for r in rules if "DROP" in r]
        if whitelist_rule and drop_rules:
            assert rules.index(whitelist_rule) < rules.index(drop_rules[0])
```

#### Practice

1. Create `tests/test_firewall.py` and run alongside the other tests: `python -m pytest tests/ -v`.
2. Verify all tests across all test files pass.

**Verify**: All tests in `tests/` pass.

**Time**: 20 minutes

---

### Step 31: Full verification

#### Motivation

Run the complete test suite and verify the CLI works end-to-end.

#### Build

Run the full suite:

```
python -m pytest tests/ -v
```

Expected: all tests pass (19+ tests across test_metrics.py, test_baseline.py, test_ratelimit.py, test_alert.py, test_detection.py, test_firewall.py).

Verify CLI:

```
python -m ddosguard --help
python -m ddosguard simulate --seconds 1
python -m ddosguard alert --count 2
```

**Verify**: All tests pass. CLI commands work.

**Time**: 15 minutes

---

## Roadmap Summary

| Phase | Steps | What you build |
|---|---|---|
| 1. Foundations | 1–3 | Project structure, dependencies, git |
| 2. Data & Traffic | 4–6 | Dataclasses, packets, synthetic generator |
| 3. Windowing & Metrics | 7–9 | Window aggregator, rolling window, tests |
| 4. Baseline System | 10–12 | Diurnal buckets, baseline store, tests |
| 5. Anomaly Detection | 13–15 | 5 signals, composite scorer, tests |
| 6. Rate Limiting | 16–18 | Token bucket, rate limiter, tests |
| 7. Firewall | 19 | iptables-style rule generation |
| 8. Alerting | 20–22 | AlertManager, AlertDirector, tests |
| 9. Dashboard | 23–25 | FastAPI, HTML/JS, MonitorRunner |
| 10. CLI & Packaging | 26–28 | argparse, `__main__.py`, config |
| 11. Testing & Polish | 29–31 | Detection/alert/firewall tests, full suite |

---

## What You'll Know After Completing This

### Python
- Multi-module packages with `__init__.py` exports
- Dataclasses, enums, properties, type hints, `field(default_factory=...)`
- ABCs for defining interfaces
- Generators (`yield`, `yield from`)
- `collections.deque` for ring buffers
- `argparse` with subparsers
- `threading` with `Event` and `Lock`
- `logging`
- JSON/JSONL persistence
- Pydantic `BaseModel` for validation
- PyYAML for config files

### Networking
- IP packet structure (IP header, TCP/UDP headers, flags, payload)
- TCP handshake (SYN → SYN-ACK → ACK)
- TCP flags (SYN, ACK, RST, FIN, PSH)
- Three DDoS types: volumetric, protocol, application layer
- Protocol numbers (ICMP=1, TCP=6, UDP=17)
- Port numbers and their common services

### Statistics
- Mean, standard deviation
- Z-score and how to interpret it
- Percentiles (p5, p25, p50, p75, p95, p99)
- Diurnal patterns and why time matters
- Baseline training and warm-up periods

### Rate Limiting
- Token bucket algorithm (rate, burst, analytical refill)
- Per-source limiting
- Whitelisting

### Firewall
- iptables rule structure (chain, match, action)
- Rate limit module (`-m limit`)
- Recent module (`-m recent`)
- Whitelist ordering (must come before DROP)
- Dry-run safety

### Alerting
- Signature-based deduplication
- Cooldown periods
- Rate limiting notifications
- Multi-channel delivery (console, file, desktop, Slack, email)

### Engineering
- Unit testing with pytest
- "No network, no permissions" test design
- Test-driven understanding
- Configuration-driven behavior
- Version control (git init, add, commit, push)
- Thread-safe shared state
- Separation of concerns

---

*This guide teaches by making you read, think, write, and break code. Every step has questions you should answer before moving on. The code in `ddosguard/` is the reference implementation — use it to compare, not to copy. The learning happens in the Practice sections.*
