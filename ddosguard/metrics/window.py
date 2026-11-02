"""
Rolling window aggregator.

The monitor runs at line rate on busy links; this module is deliberately
incremental:

* Aggregators keep running counters, never replay the packet stream.
* `RollingAggregator` keeps a fixed-size ring of completed windows so memory
  use is O(number of windows), not O(total packets).
* A window only materialises a `TrafficStats` when it rolls over.

Packets arrive one at a time through `add(pkt)`; the caller is responsible for
throttling with `window_seconds` and for applying sampling.  Each call to
`add` is O(1) plus the cost of updating a bounded top-talker counter.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ..core import (
    PacketRecord,
    TrafficStats,
    TrafficWindow,
    TopTalkers,
)

TOP_SOURCES_LIMIT = 200


@dataclass
class WindowAggregator:
    """Accumulates one time window of packet statistics."""

    window_seconds: float
    start: datetime = field(default_factory=datetime.now)
    end: datetime = field(default_factory=datetime.now)
    _counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _bytes: int = 0
    _syns: int = 0
    _rcps: int = 0
    _src_ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _dst_ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    _srcips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _dstips: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    _last_ts: float = 0.0

    def is_rolled(self) -> bool:
        return (self.end - self.start).total_seconds() >= self.window_seconds

    def advance(self, new_start: datetime, new_end: datetime) -> None:
        self.start = new_start
        self.end = new_end

    def add(self, pkt: PacketRecord) -> None:
        self._counts[pkt.protocol] += 1
        self._bytes += pkt.length
        if pkt.is_syn:
            self._syns += 1
        if pkt.is_rst:
            self._rcps += 1
        self._src_ports[pkt.src_port] += 1
        self._dst_ports[pkt.dst_port] += 1
        self._srcips[pkt.src_ip] += 1
        self._dstips[pkt.dst_ip] += 1
        self._last_ts = max(self._last_ts, pkt.ts.timestamp())

    def _elapsed(self) -> float:
        """Time span covered by the accumulated packets (based on their timestamps)."""
        if self._total() == 0:
            return 0.0
        return max(0.001, self._last_ts - self.start.timestamp())

    def finalize(self) -> TrafficStats:
        # end = last packet timestamp so windows with non-contiguous data still
        # report a meaningful span.
        end = datetime.fromtimestamp(self._last_ts) if self._last_ts else self.end
        return TrafficStats(
            window=TrafficWindow(
                start=self.start,
                end=end,
                packet_count=self._total(),
                byte_count=self._bytes,
                protocol_counts={k: v for k, v in self._counts.items()},
                syn_count=self._syns,
                rst_count=self._rcps,
                src_ports=dict(self._src_ports),
                dst_ports=dict(self._dst_ports),
                top_talkers=TopTalkers(
                    src_ips=self._top_ips(self._srcips, TOP_SOURCES_LIMIT),
                    dst_ports=self._top_ports(self._dst_ports, TOP_SOURCES_LIMIT),
                    src_unique=len(self._srcips),
                    dst_unique=len(self._dstips),
                ),
                top_srcs=self._top_ips(self._srcips, TOP_SOURCES_LIMIT),
            ),
            per_proto={k: v for k, v in self._counts.items()},
            unique_sources=len(self._srcips),
            unique_dests=len(self._dstips),
            top_srcs=self._top_ips(self._srcips, TOP_SOURCES_LIMIT),
            top_ports=self._top_ports(self._dst_ports, TOP_SOURCES_LIMIT),
            src_port_dist=dict(self._src_ports),
            dst_port_dist=dict(self._dst_ports),
            syn_ratio=(self._syns / self._total()) if self._total() else 0.0,
            byte_rate=(self._bytes / self._elapsed()),
        )

    def _total(self) -> int:
        return sum(self._counts.values())

    @staticmethod
    def _top_ips(counter: Dict[str, int], limit: int) -> List[tuple[str, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]

    @staticmethod
    def _top_ports(counter: Dict[int, int], limit: int) -> List[tuple[int, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


@dataclass
class RollingAggregator:
    """Ring of pre-materialised windows plus a live window."""

    window_seconds: float
    capacity: int
    windows: List[TrafficStats] = field(default_factory=list)
    _index: int = 0
    _live: WindowAggregator = field(default_factory=lambda: WindowAggregator(10.0, start=datetime.now(), end=datetime.now()))
    _sample_rate: float = 0.0

    @property
    def current(self) -> TrafficStats:
        return self._live.finalize()

    @property
    def sample_rate(self) -> float:
        return self._sample_rate

    @sample_rate.setter
    def sample_rate(self, value: float) -> None:
        self._sample_rate = max(0.0, min(1.0, value))

    def add(self, pkt: PacketRecord) -> None:
        if self._sample_rate and (hash(pkt.ts) % 1000) >= self._sample_rate * 1000:
            return
        # The live window starts at the first packet's timestamp so tests and
        # replayed traces with arbitrary timestamps behave correctly.
        if (pkt.ts - self._live.start).total_seconds() < 0:
            self._live = WindowAggregator(
                self.window_seconds, start=pkt.ts, end=pkt.ts
            )
        self._live.add(pkt)
        if (pkt.ts - self._live.start).total_seconds() >= self.window_seconds:
            self._commit()

    def _commit(self) -> None:
        stats = self._live.finalize()
        self.windows.append(stats)
        if len(self.windows) > self.capacity:
            self.windows.pop(0)
        # Roll the live window forward: its start is the timestamp of the last
        # packet in the completed window (the window's end).
        self._live = WindowAggregator(
            self.window_seconds,
            start=stats.window.end,
            end=stats.window.end,
        )

    def get(self, index: int) -> Optional[TrafficStats]:
        if 0 <= index < len(self.windows):
            return self.windows[index]
        return None

    @property
    def total_packets(self) -> int:
        return sum(w.packet_rate for w in self.windows)

    @property
    def total_bytes(self) -> int:
        return sum(round(w.window.byte_count) for w in self.windows)
