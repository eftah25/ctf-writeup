"""
Data model shared across the toolkit.

Everything that flows through the pipeline is expressed as plain dataclasses so
it can be unit-tested without touching the network or spawning threads:

    PacketRecord     - one parsed packet (timestamped, decrypted back to fields)
    TrafficWindow    - statistics for one fixed-length time window
    TrafficStats     - window statistics + per-source/port breakdowns
    BaselineStats    - mean / stdev / percentiles for one metric bucket
    BaselineStore    - dict[str, BaselineStats] keyed by diurnal bucket
    SignalResult     - one anomaly indicator (name, score 0..1, detail)
    CompositeScore   - weighted combination of signals + severity + classification
    Alert            - notification payload (severity, indicators, mitigation)
    MitigationAction - one firewall/mitigation rule planned or applied
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Dict, List, Optional



class Protocol(IntEnum):
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
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @staticmethod
    def from_str(name: str) -> "Severity":
        return Severity[name.upper()]


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class PacketRecord:
    """A decrypted representation of a packet as seen by the monitor."""

    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: Protocol = Protocol.OTHER
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ""
    payload_bytes: int = 0

    @property
    def is_tcp(self) -> bool:
        return self.protocol == Protocol.TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == Protocol.UDP

    @property
    def is_icmp(self) -> bool:
        return self.protocol == Protocol.ICMP

    @property
    def is_syn(self) -> bool:
        return "S" in self.flags

    @property
    def is_rst(self) -> bool:
        return "R" in self.flags


@dataclass
class TopTalkers:
    """Top N source IPs and destination ports with counts in a window."""

    src_ips: List[tuple[str, int]] = field(default_factory=list)  # (ip, count)
    dst_ports: List[tuple[int, int]] = field(default_factory=list)  # (port, count)
    src_unique: int = 0
    dst_unique: int = 0

    @classmethod
    def empty(cls) -> "TopTalkers":
        return cls()

    def merge(self, other: "TopTalkers") -> None:
        self.src_ips.extend(other.src_ips)
        self.dst_ports.extend(other.dst_ports)
        self.src_unique += other.src_unique
        self.dst_unique += other.dst_unique


@dataclass
class TrafficWindow:
    """Aggregated statistics for one fixed-length time window."""

    start: datetime
    end: datetime
    windows: List["TrafficWindow"] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0
    protocol_counts: Dict[Protocol, int] = field(default_factory=dict)
    syn_count: int = 0
    rst_count: int = 0
    src_ports: Dict[int, int] = field(default_factory=dict)
    dst_ports: Dict[int, int] = field(default_factory=dict)
    top_talkers: TopTalkers = field(default_factory=TopTalkers)
    top_srcs: List[tuple[str, int]] = field(default_factory=list)

    def clone(self) -> "TrafficWindow":
        import copy

        return copy.deepcopy(self)

    def reset(self) -> None:
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts = {}
        self.syn_count = 0
        self.rst_count = 0
        self.src_ports = {}
        self.dst_ports = {}
        self.top_talkers = TopTalkers.empty()
        self.top_srcs = []

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
        self.top_talkers.src_ips.append((pkt.src_ip, 1))
        self.top_talkers.dst_ports.append((pkt.dst_port, 1))
        self.top_talkers.src_unique += 1
        self.top_talkers.dst_unique += 1
        if not self.top_srcs or self.top_srcs[0][0] != pkt.src_ip:
            self.top_srcs.append((pkt.src_ip, 1))
        else:
            self.top_srcs[0] = (self.top_srcs[0][0], self.top_srcs[0][1] + 1)

    def finalize(self) -> "TrafficStats":
        return TrafficStats(
            window=self,
            per_proto={k.value: v for k, v in self.protocol_counts.items()},
            unique_sources=self.top_talkers.src_unique,
            unique_dests=self.top_talkers.dst_unique,
            top_srcs=self.top_talkers.src_ips[:10],
            top_ports=self.top_talkers.dst_ports[:10],
            src_port_dist=self.src_ports,
            dst_port_dist=self.dst_ports,
            syn_ratio=(self.syn_count / self.packet_count) if self.packet_count else 0.0,
            byte_rate=(self.byte_count / self._seconds) if self._seconds else 0.0,
        )

    @property
    def _seconds(self) -> float:
        return max(0.001, (self.end.timestamp() - self.start.timestamp()))


@dataclass
class TrafficStats:
    """Finalized statistics for one window (the unit detection reasons over)."""

    window: TrafficWindow
    per_proto: Dict[int, int] = field(default_factory=dict)
    unique_sources: int = 0
    unique_dests: int = 0
    top_srcs: List[tuple[str, int]] = field(default_factory=list)
    top_ports: List[tuple[int, int]] = field(default_factory=list)
    src_port_dist: Dict[int, int] = field(default_factory=dict)
    dst_port_dist: Dict[int, int] = field(default_factory=dict)
    syn_ratio: float = 0.0
    byte_rate: float = 0.0

    @property
    def packet_rate(self) -> float:
        return self.window.packet_count / self.window._seconds


@dataclass
class BaselineStats:
    """Statistics for one metric bucket (e.g. hour 14 on weekdays)."""

    mean: float = 0.0
    stdev: float = 0.0
    count: int = 0
    p5: float = 0.0
    p25: float = 0.0
    p75: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    samples: List[float] = field(default_factory=list)  # bounded reservoir

    @property
    def cv(self) -> float:
        return self.stdev / self.mean if self.mean else 0.0

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
    """One anomaly indicator reported by a detection signal."""

    name: str
    score: float = 0.0  # 0..1
    detail: Dict[str, object] = field(default_factory=dict)
    affected: List[str] = field(default_factory=list)  # IPs/ports/countries
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "detail": self.detail,
            "affected": self.affected,
            "recommended_action": self.recommended_action,
        }


@dataclass
class CompositeScore:
    signal_names: List[str] = field(default_factory=list)
    signal_scores: Dict[str, float] = field(default_factory=dict)
    total: float = 0.0  # 0..1
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
            "window": self.window.to_dict() if self.window else None,
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
    ip: str
    reason: str = ""
    added_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, object]:
        return {"ip": self.ip, "reason": self.reason, "added_at": self.added_at.isoformat()}


@dataclass
class MitigationAction:
    """One firewall/mitigation rule planned or applied."""

    id: str
    rule_type: str  # "rate_limit" | "block" | "redirect"
    target: str  # ip or port
    action: str  # "allow" | "deny"
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
