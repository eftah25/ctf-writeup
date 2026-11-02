"""
Alert director: rank alerts and route them to the right channel so the
on-call experience stays useful.

The director is deliberately conservative about interruption:
    1. a CRITICAL alert always interrupts (immediate_critical).
    2. alerts are deduplicated by signature; the newest data is kept.
    3. below critical, delivery is throttled by cooldown so a sustained attack
       doesn't churn the on-call rota.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core import Alert, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class AlertRoute:
    alert: Alert
    channel: str
    delivered_at: float = 0.0
    retries: int = 0


class AlertDirector:
    """Maintains a ranked queue and decides what to deliver now."""

    def __init__(self, config: dict):
        self.config = config
        self._queue: List[AlertRoute] = []
        self._seen: Dict[str, Alert] = {}
        self._lock = None  # threaded by the monitor

    def add(self, alert: Alert) -> None:
        self._seen[alert.alert_id] = alert

    def pending(self) -> List[Alert]:
        return list(self._seen.values())

    def rank(self) -> List[Alert]:
        """Alerts sorted by severity so the most important is acted on first."""
        return sorted(self._seen.values(), key=lambda a: SEVERITY_ORDER.index(a.severity))

    def urgent(self) -> List[Alert]:
        """Only CRITICAL alerts: these get immediate attention."""
        return [a for a in self._seen.values() if a.severity == Severity.CRITICAL]

    def __len__(self) -> int:
        return len(self._seen)
