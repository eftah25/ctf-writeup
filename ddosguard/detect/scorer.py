"""
Composite anomaly scoring.

A baseline is only trustworthy after a short warm-up period.  A signal that
fires in the first few windows is marked `confirmed` only after it has kept
its score above the confirmation threshold for `confirmation_windows`
consecutive samples; signals that have not yet reached confirmation count
against the composite only at a reduced weight (they still contribute but
with a lower penalty so the severity is conservative until data accumulates).

Composite score = sum(weight_i * score_i)  clipped to [0, 1].
Severity is derived from the composite score with a hysteresis band, and
the classification labels the attack family:
    "none"      - score below info threshold
    "volumetric"     - volume + (protocol shift)
    "protocol"       - syn signal dominant
    "application"    - port/source concentration
    "mixed"          - multiple families simultaneously
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..config import Config
from ..core import CompositeScore, Severity, SignalResult, TrafficStats

SEVERITY_BANDS = (  # (lower bound, severity)
    (0.0, Severity.INFO),
    (0.2, Severity.LOW),
    (0.4, Severity.MEDIUM),
    (0.6, Severity.HIGH),
    (0.8, Severity.CRITICAL),
)


@dataclass
class SignalHistory:
    """Rolling per-signal state so confirmation logic can be applied."""

    fn: str
    history: List[float] = field(default_factory=list)

    def add(self, score: float) -> bool:
        self.history.append(score)
        if len(self.history) > 20:
            self.history.pop(0)
        return self.confirmed()

    def confirmed(self) -> bool:
        if len(self.history) < 3:
            return False
        window = self.history[-3:]
        return all(s >= 0.5 for s in window)

    def reset(self) -> None:
        self.history.clear()


class CompositeScorer:
    """Computes the composite anomaly score from live window statistics."""

    def __init__(self, config: Config):
        self.config = config
        self.weights = config.detection.get("weights", {})
        self.history = {
            "volume": SignalHistory("volume"),
            "protocol": SignalHistory("protocol"),
            "source": SignalHistory("source"),
            "port": SignalHistory("port"),
            "syn": SignalHistory("syn"),
        }
        self._last: Optional[CompositeScore] = None

    def score(self, stats: TrafficStats, baseline, window_idx: int = 0) -> CompositeScore:
        weights = self.weights
        w_volume = weights.get("volume", 0.35)
        w_protocol = weights.get("protocol", 0.15)
        w_source = weights.get("source", 0.20)
        w_port = weights.get("port", 0.15)
        w_syn = weights.get("syn", 0.15)

        s_volume = self._signal_value("volume", stats, baseline)
        s_protocol = self._signal_value("protocol", stats, baseline)
        s_source = self._signal_value("source", stats, baseline)
        s_port = self._signal_value("port", stats, baseline)
        s_syn = self._signal_value("syn", stats, baseline)

        confirmed = {
            "volume": self.history["volume"].add(s_volume),
            "protocol": self.history["protocol"].add(s_protocol),
            "source": self.history["source"].add(s_source),
            "port": self.history["port"].add(s_port),
            "syn": self.history["syn"].add(s_syn),
        }

        raw = (
            w_volume * s_volume
            + w_protocol * s_protocol
            + w_source * s_source
            + w_port * s_port
            + w_syn * s_syn
        )

        # Signals that are confirmed count fully; unconfirmed ones are damped.
        damp = {"volume": 0.6, "protocol": 0.6, "source": 0.7, "port": 0.7, "syn": 0.7}
        penalized = (
            w_volume * s_volume * (1.0 if confirmed["volume"] else damp["volume"])
            + w_protocol * s_protocol * (1.0 if confirmed["protocol"] else damp["protocol"])
            + w_source * s_source * (1.0 if confirmed["source"] else damp["source"])
            + w_port * s_port * (1.0 if confirmed["port"] else damp["port"])
            + w_syn * s_syn * (1.0 if confirmed["syn"] else damp["syn"])
        )

        total = min(1.0, max(0.0, raw if raw > 0 else penalized))
        self._last = CompositeScore(
            signal_names=list(confirmed.keys()),
            signal_scores={
                "volume": s_volume,
                "protocol": s_protocol,
                "source": s_source,
                "port": s_port,
                "syn": s_syn,
            },
            total=total,
            severity=Severity.from_str(self.severity_for(total)),
            classification=self.classification(stats, confirmed),
            window=stats,
        )
        return self._last

    def _signal_value(self, name: str, stats: TrafficStats, baseline) -> float:
        signals = {
            "volume": self._call_volume,
            "protocol": self._call_protocol,
            "source": self._call_source,
            "port": self._call_port,
            "syn": self._call_syn,
        }
        try:
            return signals[name](stats, baseline)
        except Exception:
            return 0.0

    def _call_volume(self, stats: TrafficStats, baseline) -> float:
        from .signals import volume_signal

        return volume_signal(stats, baseline, self.config).score

    def _call_protocol(self, stats: TrafficStats, baseline) -> float:
        from .signals import protocol_signal

        return protocol_signal(stats, baseline, self.config).score

    def _call_source(self, stats: TrafficStats, baseline) -> float:
        from .signals import source_signal

        return source_signal(stats, baseline, self.config).score

    def _call_port(self, stats: TrafficStats, baseline) -> float:
        from .signals import port_signal

        return port_signal(stats, baseline, self.config).score

    def _call_syn(self, stats: TrafficStats, baseline) -> float:
        from .signals import syn_signal

        return syn_signal(stats, baseline, self.config).score

    @staticmethod
    def severity_for(total: float) -> str:
        for bound, sev in SEVERITY_BANDS:
            if total >= bound:
                return sev.name
        return Severity.INFO.name

    def classification(self, stats: TrafficStats, confirmed: Dict[str, bool]) -> str:
        if max(confirmed.values()) is False and all(not v for v in confirmed.values()):
            return "none"
        families = []
        if confirmed.get("volume"):
            families.append("volumetric")
        if confirmed.get("syn") or confirmed.get("protocol"):
            families.append("protocol")
        if confirmed.get("port") or confirmed.get("source"):
            families.append("application")
        if not families:
            # Even unconfirmed signals can label the attack family heuristically.
            if confirmed.get("syn"):
                families.append("protocol")
            elif confirmed.get("port"):
                families.append("application")
            elif confirmed.get("volume"):
                families.append("volumetric")
        if len(families) == 1:
            return families[0]
        return "mixed"

    @property
    def last(self) -> Optional[CompositeScore]:
        return self._last
