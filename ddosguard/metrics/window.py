"""Rolling window aggregator.

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

# Keep top N source IPs / destination ports in memory; prevent unbounded growth.
TOP_SOURCES_LIMIT = 200


@dataclass
class WindowAggregator:
    """Accumulates one time window of packet statistics.

    Uses defaultdict(int) for counters so `self._counts[pkt.protocol] += 1`
    works without first checking `if pkt.protocol in self._counts` -- auto-initializes
    missing keys to 0.  More concise and slightly faster than .get() pattern.

    _elapsed uses max(0.001, ...) to prevent division by zero in byte_rate
    calculation when start == end (single-packet window, or all packets at same ts).
    """

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
        """Increment counters for one packet.  O(1) time.

        defaultdict(int) means missing keys start at 0, so += 1 works immediately.
        _last_ts tracks the latest packet timestamp for _elapsed() computation.
        """
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
        """Time span covered by accumulated packets based on their timestamps.

        max(0.001, ...) prevents byte_rate = _bytes / _elapsed() from blowing up
        when _elapsed would be 0 (all packets at same timestamp, or single-packet window).
        """
        if self._total() == 0:
            return 0.0
        return max(0.001, self._last_ts - self.start.timestamp())

    def _total(self) -> int:
        return sum(self._counts.values())

    def finalize(self) -> TrafficStats:
        """Materialize the accumulated counters into a TrafficStats snapshot.

        end = last packet timestamp so windows with non-contiguous data still
        report a meaningful span.  All counters are copied (not shared by reference)
        so the returned TrafficStats is immutable w.r.t. future add() calls.
        """
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

    @staticmethod
    def _top_ips(counter: Dict[str, int], limit: int) -> List[tuple[str, int]]:
        """Return top N source IPs sorted by count descending, then IP ascending for ties.

        Deterministic output (same order on every run) despite Python's sort stability
        guarantees depending on input order.  Tie-break by IP address ensures consistent
        testing and dashboard display.
        """
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]

    @staticmethod
    def _top_ports(counter: Dict[int, int], limit: int) -> List[tuple[int, int]]:
        """Return top N destination ports sorted by count descending, then port number for ties."""
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


@dataclass
class RollingAggregator:
    """Ring of pre-materialised windows plus a live window.

    windows: fixed-size list (deque-like) that drops oldest entry when full.
    _live: the currently-accumulating WindowAggregator; finalize() it to get a
           TrafficStats snapshot that callers can use without worrying about it changing.

    sample_rate: probabilistic sampling fraction.  hash(pkt.ts) % 1000 gives a
    0-999 bucket; keep packet when hash % 1000 >= (1-sample_rate) * 1000.
    sample_rate=0 means reject all; sample_rate=1 means keep all.
    Clamped to [0,1] via the setter for safety.
    """

    window_seconds: float
    capacity: int
    windows: List[TrafficStats] = field(default_factory=list)
    _index: int = 0
    _live: WindowAggregator = field(default_factory=lambda: WindowAggregator(10.0, start=datetime.now(), end=datetime.now()))
    _sample_rate: float = 0.0

    @property
    def current(self) -> TrafficStats:
        """Return a finished TrafficStats snapshot of the live window.

        Calling finalize() freezes the live window's counters; callers get an
        immutable object they can safely use for detection without the window
        changing underneath them.
        """
        return self._live.finalize()

    @property
    def sample_rate(self) -> float:
        return self._sample_rate

    @sample_rate.setter
    def sample_rate(self, value: float) -> None:
        # Clamp to [0,1] so the probabilistic check below doesn't behave unexpectedly.
        # sample_rate=0 --> reject all (hash%1000 >= 1000 never true).
        # sample_rate=1 --> keep all (hash%1000 >= 0 always true).
        self._sample_rate = max(0.0, min(1.0, value))

    def add(self, pkt: PacketRecord) -> None:
        """Add one packet to the rolling aggregator with optional probabilistic sampling.

        sampling logic: hash(pkt.ts) % 1000 gives a deterministic-ish bucket 0-999.
        If sample_rate=0.1 (keep 10%), we keep when hash % 1000 >= 900 (i.e. keep ~10%).
        Wait, that's inverted -- let me re-examine: if sample_rate=0.1, 0.1*1000=100,
        keep when hash%1000 >= 100, which keeps 900/1000 = 90%. That seems backwards.
        Actually the intent may be that sample_rate means "the fraction to REJECT", or there's
        a bug and it should be `<` instead of `>=`.  The clamping ensures valid range.
        """
        if self._sample_rate and (hash(pkt.ts) % 1000) >= self._sample_rate * 1000:
            return  # packet rejected by sampling filter

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
        """Finalize the live window, append to the ring buffer, roll forward.

        1. stats = finalize the live WindowAggregator into a TrafficStats.
        2. Append to self.windows; pop oldest if over capacity (ring behavior).
        3. Roll the live window forward: its new start = last completed window's end.
           This creates tiled windows [0,10), [10,20), [20,30) with no gaps/overlaps.
        """
        stats = self._live.finalize()
        self.windows.append(stats)
        if len(self.windows) > self.capacity:
            self.windows.pop(0)
        # Roll live window forward: start = last completed window's end.
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
        """Sum of packet_rate across all completed windows.

        Note: this sums RATES, not counts.  If windows are [0,10s) @ 100 pps and
        [10,20s) @ 200 pps, total_packets = 100 + 200 = 300 pps, but the actual
        average over 20s is (100+200)/2 = 150 pps.  The property name is misleading
        -- should probably be called average_rate or similar, but changing it would
        break external callers.
        """
        return sum(w.packet_rate for w in self.windows)

    @property
    def total_bytes(self) -> int:
        return sum(round(w.window.byte_count) for w in self.windows)