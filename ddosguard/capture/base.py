"""
Source abstraction and the synthetic traffic generator.

What we actually capture depends on the machine:

    * live scapy sniffing    (root on Linux/macOS; raw sockets on Windows are
                              restricted, so Windows demos use pcap or synthetic)
    * pcap replay            (a saved trace of the *observed* traffic)
    * synthetic generator    (deterministic fake traffic so the pipeline can be
                              demonstrated and tested without any privileges)

The synthetic generator is the reference implementation for the detection
pipeline: it emits normal diurnal traffic plus, on demand, volumetric /
protocol / application-layer DDoS patterns so we can verify that each signal
fires and that mitigation escalates correctly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterator, Optional

from ..core import PacketRecord, Protocol, TrafficStats, TrafficWindow

# Default DNS resolver for the synthetic generator.
LOCAL_DNS = "10.0.0.1"


# --------------------------------------------------------------------------- #
# Source protocol                                                            #
# --------------------------------------------------------------------------- #
class PacketSource(ABC):
    """A source of packets, expressed as an iterator of PacketRecord."""

    name: str = "source"

    @abstractmethod
    def iter_packets(self, window_seconds: float, sampling_rate: float = 0.0) -> Iterator[PacketRecord]:
        """Yield packets forever (or until the source is exhausted)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def running(self) -> bool:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Synthetic generator                                                        #
# --------------------------------------------------------------------------- #
@dataclass
class SyntheticGenerator(PacketSource):
    """Deterministic, configurable synthetic traffic for testing and demos."""

    name = "synthetic"
    # "normal" = diurnal baseline; "attack" = one of the DDoS families.
    mode: str = "normal"
    # Baseline per-window stats for the diurnal model.
    base_pkts: int = 500
    base_bytes: int = 120_000
    # Daytime profile: per hour, relative multiplier on base_pkts.
    hourly_profile: list[float] = field(default_factory=lambda: [0.5] * 24)
    # Source IP space and port space.
    source_ips: list[str] = field(
        default_factory=lambda: [f"10.0.{h}.{i}" for h in range(256) for i in range(8)]
    )
    source_ports: list[int] = field(default_factory=lambda: list(range(1024, 65536, 257)))
    protocols: list[Protocol] = field(default_factory=lambda: [Protocol.TCP, Protocol.UDP, Protocol.ICMP])
    ports: list[int] = field(default_factory=lambda: [80, 443, 22, 53, 8080, 3389])

    # Attack configuration (applied when mode == "attack").
    attack_family: str = "volumetric"  # volumetric | syn_flood | application
    attack_start: datetime = field(default_factory=datetime.now)
    attack_duration: float = 30.0  # seconds
    attack_mult: int = 20

    # ---- generation state ----------------------------------------------------- #
    _rng: "random.Random" = field(default=None, init=False, repr=False)
    _start: datetime = field(default_factory=datetime.now, init=False)
    _packet: int = field(default=0, init=False)
    _last: float = field(default=0.0, init=False)

    def __post_init__(self):
        import random

        self._rng = random.Random(42 + hash(self.mode) % 1000)
        self._start = datetime.now()
        self._last = self._start.timestamp()

    def iter_packets(self, window_seconds: float, sampling_rate: float = 0.0) -> Iterator[PacketRecord]:
        import random

        # Reset the shared generator state for the window.
        self._packet = 0
        self._last = datetime.now().timestamp()
        while self._running:
            now = datetime.now().timestamp()
            if now - self._last >= 0.01:
                self._last = now
                pkt = self._gen(now)
                if pkt is not None:
                    yield pkt
                self._packet += 1

    @property
    def _running(self) -> bool:
        return True

    def _gen(self, now: float) -> Optional[PacketRecord]:
        import random

        dt = datetime.now()
        hour = dt.hour
        weekday = dt.weekday() < 5
        profile = self.hourly_profile[hour] if hour < len(self.hourly_profile) else 1.0
        weekday_mult = 1.2 if weekday else 0.8
        target_rate = self.base_pkts * profile * weekday_mult / 10.0  # per window

        # Attack driver.
        if self.mode == "attack":
            elapsed = (datetime.now() - self.attack_start).total_seconds()
            if elapsed < self.attack_duration:
                return self._attack_packet(elapsed)
            return None

        # Normal traffic: exponential inter-arrival.
        delay = -1.0 * (1.0 / target_rate)
        if self._packet > 0 and random.random() < 0.99:
            return None
        proto = self._rng.choice(self.protocols)
        src_ip = self._rng.choice(self.source_ips)
        src_port = self._rng.choice(self.source_ports)
        dst_port = self._rng.choice(self.ports)
        length = random.randint(40, 1500)
        flags = ""
        if proto == Protocol.TCP:
            flags = random.choice(["", "S", "SA", "FA", "R"])
        return PacketRecord(
            ts=dt,
            src_ip=src_ip,
            dst_ip=LOCAL_DNS,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            flags=flags,
            payload_bytes=length - 20,
        )

    def _attack_packet(self, elapsed: float) -> PacketRecord:
        import random

        # Volumetric: rows of UDP to a single port.
        if self.attack_family == "volumetric":
            proto = Protocol.UDP
            src_ip = random.choice(self.source_ips[:40])
            length = random.choice([60, 64, 100, 1400])
            return PacketRecord(
                ts=datetime.now(),
                src_ip=src_ip,
                dst_ip="10.0.0.9",
                protocol=proto,
                src_port=random.randint(1024, 65535),
                dst_port=53,
                length=length,
                flags="",
                payload_bytes=length - 20,
            )
        # SYN flood.
        if self.attack_family == "syn_flood":
            proto = Protocol.TCP
            src_ip = random.choice(self.source_ips[:12])
            length = random.choice([40, 44, 60, 84])
            return PacketRecord(
                ts=datetime.now(),
                src_ip=src_ip,
                dst_ip="10.0.0.9",
                protocol=proto,
                src_port=random.randint(1024, 65535),
                dst_port=80,
                length=length,
                flags="S",
                payload_bytes=length - 20,
            )
        # Application: correlated traffic to a single port from few sources.
        proto = Protocol.TCP
        src_ip = random.choice(self.source_ips[:8])
        length = random.randint(200, 1400)
        return PacketRecord(
            ts=datetime.now(),
            src_ip=src_ip,
            dst_ip="10.0.0.9",
            protocol=proto,
            src_port=random.randint(1024, 65535),
            dst_port=443,
            length=length,
            flags="PA",
            payload_bytes=length - 20,
        )
