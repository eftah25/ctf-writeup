"""
Baseline store.

Normal traffic is diurnal: a quiet weekday afternoon looks very different from a
busy Saturday night.  This module therefore buckets every observed metric by
time of day and weekday/weekend so that "normal for 16:00 on a Tuesday" is the
reference, not "the all-time average".

Metrics tracked (each with its own BaselineStats model):
    packets   - packet rate over the window
    bytes     - byte rate over the window
    protocol  - percentage share of a protocol in the window
    sources   - unique-source ratio (unique_sources / packet_count)
    ports     - share of traffic to a single destination port
    syns      - SYN packet ratio in the window

All models are trained incrementally with Welford's online variance so the
store's memory and CPU cost stay bounded as data accumulates.  Percentiles
come from a bounded reservoir (reservoir sampling) so they converge without
storing the full history.
"""
from __future__ import annotations

import json
import os
import random
import threading
from datetime import datetime
from typing import Dict, List, Optional

from ..config import Config
from ..core import TrafficStats

# Metric names used as keys in the store.
METRICS = ("packets", "bytes", "protocol", "sources", "ports", "syns")
RESERVOIR_SIZE = 500


class BaselineStats:
    """Statistics for one metric bucket (e.g. hour 14 on weekdays)."""

    def __init__(self, mean: float = 0.0, stdev: float = 0.0, count: int = 0,
                 p5: float = 0.0, p25: float = 0.0, p75: float = 0.0,
                 p95: float = 0.0, p99: float = 0.0, samples: Optional[List[float]] = None):
        self.mean = mean
        self.stdev = stdev
        self.count = count
        self.p5 = p5
        self.p25 = p25
        self.p75 = p75
        self.p95 = p95
        self.p99 = p99
        self.samples: List[float] = list(samples) if samples else []

    @property
    def cv(self) -> float:
        return self.stdev / self.mean if self.mean else 0.0

    def add(self, value: float) -> None:
        """Add a sample using reservoir sampling so percentiles converge."""
        self.samples.append(value)
        if len(self.samples) > RESERVOIR_SIZE:
            j = random.randrange(len(self.samples))
            if j < RESERVOIR_SIZE:
                self.samples[j] = value
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


class BaselineStore:
    """Persistent store of per-bucket baseline statistics."""

    def __init__(self, config: Config, data_dir: Optional[str] = None):
        self.config = config
        self.data_dir = data_dir or config.baseline.get("data_dir", "data")
        self.file = os.path.join(self.data_dir, "baseline.json")
        self._lock = threading.Lock()
        # (metric, bucket_key) -> BaselineStats
        self._models: Dict[tuple[str, str], BaselineStats] = {}
        self._trained_at = datetime.now()

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #
    def observe(self, stats: TrafficStats, ts: datetime) -> None:
        """Fold one window of live traffic into the baseline model."""
        bucket = self._bucket_key(ts, stats)
        with self._lock:
            for metric, values in self._extract(stats).items():
                model = self._models.get((metric, bucket))
                if model is None:
                    model = BaselineStats()
                    self._models[(metric, bucket)] = model
                for value in values:
                    model.add(value)
        self._trained_at = ts

    def expected(self, metric: str, ts: datetime, stats: TrafficStats) -> BaselineStats:
        """Return the baseline model for the bucket that *ts* falls in."""
        bucket = self._bucket_key(ts, stats)
        model = self._models.get((metric, bucket))
        if model is None:
            model = BaselineStats()
        return model

    def ready(self) -> bool:
        return len(self._models) > 0

    def all(self) -> Dict[str, BaselineStats]:
        with self._lock:
            return {f"{m}:{k}": v for (m, k), v in self._models.items()}

    def save(self) -> None:
        payload = {
            "trained_at": self._trained_at.isoformat(),
            "models": {
                f"{m}:{k}": {
                    "mean": v.mean,
                    "stdev": v.stdev,
                    "count": v.count,
                    "p5": v.p5,
                    "p25": v.p25,
                    "p75": v.p75,
                    "p95": v.p95,
                    "p99": v.p99,
                    "samples": v.samples,
                }
                for (m, k), v in self._models.items()
            },
        }
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    def load(self) -> None:
        if not os.path.exists(self.file):
            return
        with open(self.file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        self._trained_at = datetime.fromisoformat(payload["trained_at"])
        for key, v in payload["models"].items():
            metric, bucket = key.split(":", 1)
            model = BaselineStats(
                mean=v.get("mean", 0.0),
                stdev=v.get("stdev", 0.0),
                count=v.get("count", 0),
                p5=v.get("p5", 0.0),
                p25=v.get("p25", 0.0),
                p75=v.get("p75", 0.0),
                p95=v.get("p95", 0.0),
                p99=v.get("p99", 0.0),
                samples=v.get("samples", []),
            )
            self._models[(metric, bucket)] = model

    # ------------------------------------------------------------------ #
    # Internal helpers                                                    #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _bucket_key(ts: datetime, stats: TrafficStats) -> str:
        hour = ts.hour
        if ts.weekday() < 5:
            day = "weekday"
        else:
            day = "weekend"
        return f"{day}-{hour:02d}"

    def _extract(self, stats: TrafficStats) -> Dict[str, List[float]]:
        out: Dict[str, List[float]] = {
            "packets": [stats.packet_rate],
            "bytes": [stats.byte_rate],
            "syns": [stats.syn_ratio],
        }
        if stats.per_proto:
            proto_share = {
                proto: count / sum(stats.per_proto.values())
                for proto, count in stats.per_proto.items()
            }
            out["protocol"] = list(proto_share.values())
        if stats.unique_sources:
            out["sources"] = [stats.unique_sources / stats.packet_rate]
        if stats.dst_port_dist:
            top = stats.dst_port_dist
            total = sum(top.values())
            out["ports"] = [v / total for v in top.values()]
        return out
