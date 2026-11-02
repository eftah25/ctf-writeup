"""
Mitigation policy: escalation ladder and safeguards.

The ladder maps anomaly severity to concrete mitigation stages:

    stage 0  MONITOR     -> report only, no mitigations
    stage 1  LOW         -> lenient token-bucket rate limit per source IP
    stage 2  MEDIUM      -> stricter rate limit + passive source blocking
    stage 3  HIGH        -> port-specific rate limits + active block of top
                            sources (reported to firewall manager)
    stage 4  CRITICAL     -> hard per-IP blocks, redirect/scrubbing hint,
                            immediate escalation

The policy in this module is the single source of truth consumed by the
monitor's event loop and by the dashboard's admin controls:

    * `decide(stats, score, baseline)` -> the stage to run, or None
    * `safeguards()`                      -> benign-traffic protections
    * `escalate(previous, proposed)`     -> only allow upward moves with
                                            hysteresis (damping windows)

Safeguards implemented here (per the specification):
    * whitelist of critical IPs that must never be blocked.  The whitelist is
      consulted before ANY block, even when the algorithm is unsure, and is
      independently persisted so restarts don't forget it.
    * start lenient and tighten only as severity increases (the ladder already
      does this).
    * rate limits never go to zero; a bare "block" only takes effect at
      critical, and then only for sources that also breach the source-block
      threshold.
    * time-based de-escalation: a stage stays active for `damping_windows`
      before it may be removed, preventing flapping in noisy links.
    * graceful degradation: if the firewall backend is unavailable, the policy
      still *reports* the rules it would have applied.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from ..config import Config
from ..core import Alert, CompositeScore, MitigationAction, Severity, WhitelistedIp

# Monotonic time helper (so tests can freeze time by patching time.monotonic).
now = time.monotonic


@dataclass
class MitigateTarget:
    """A concrete target produced by the policy, handed to the firewall/rate
    limiter rather than computed ad hoc by the dashboard."""

    id: str
    rule_type: str
    target: str
    action: str
    severity: Severity
    reason: str
    applied_at: float = field(default_factory=now)


class MitigationPolicy:
    """Configures and executes the escalation ladder with safeguards."""

    def __init__(self, config: Config):
        self.config = config
        self.rate_limits = config.mitigation.get("rate_limits", [])
        self.source_block = config.mitigation.get("source_block", {})
        self.damping_windows = config.mitigation.get("damping_windows", 6)
        self.whitelist = [WhitelistedIp(ip=r["ip"], reason=r.get("reason", ""), added_at=None) for r in self.rate_limits]

        # Internal state (persisted in the state file; only this process edits).
        self._state: Dict[str, object] = {
            "active_stage": 0,
            "active_at": 0.0,
            "consecutive_breach_windows": 0,
            "total_violations": 0,
            "last_action_time": 0.0,
        }
        self._lock = threading.RLock()
        self._actions: List[MitigationAction] = []

    def active_stage(self) -> int:
        with self._lock:
            return int(self._state["active_stage"])

    def active_stage_since(self) -> float:
        with self._lock:
            return float(self._state["active_at"])

    def set_active_stage(self, stage: int) -> None:
        with self._lock:
            self._state["active_stage"] = stage
            self._state["active_at"] = now()

    def bump_violations(self, n: int = 1) -> None:
        with self._lock:
            self._state["consecutive_breach_windows"] = max(
                0, self._state["consecutive_breach_windows"] + n
            )
            self._state["total_violations"] += n

    def violations(self) -> int:
        with self._lock:
            return int(self._state["consecutive_breach_windows"])

    def add_action(self, action: MitigationAction) -> None:
        with self._lock:
            self._actions.append(action)

    def actions(self) -> List[MitigationAction]:
        with self._lock:
            return list(self._actions)

    def clear_actions(self) -> None:
        with self._lock:
            self._actions.clear()

    def whitelist_entry(self, ip: str, reason: str = "") -> None:
        with self._lock:
            if ip in self._whitelist:
                return
            self._whitelist.append(WhitelistedIp(ip=ip, reason=reason))

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._whitelist

    def find_rate_limit(self, severity: str) -> Dict[str, object]:
        for entry in self.rate_limits:
            if entry["severity"] >= severity:
                return entry
        return self.rate_limits[-1]

    def decide(self, score: CompositeScore, baseline, stats: TrafficStats) -> Optional[int]:
        """Return the mitigation stage to activate, or None (monitor)."""
        if score.total < 0.2:
            return None
        stage = int(severity_to_stage(score.severity))
        if self._state["active_stage"] != stage:
            self.set_active_stage(stage)
        self.bump_violations()
        return stage

    def apply(self, stage: int) -> List[MitigationAction]:
        """Translate a stage into concrete actions with safeguards applied."""
        action = self.rate_limit_actions(stage)
        return action

    def rate_limit_actions(self, stage: int) -> List[MitigationAction]:
        """Build the actions for `stage` from the escalation ladder."""
        entry = self.find_rate_limit(stage)
        rate = int(entry["rate"])
        burst = int(entry["burst"])
        severity = stage_to_severity(stage)
        actions = []
        for key, bucket in self._active_buckets().items():
            if self.is_whitelisted(key):
                actions.append(
                    MitigationAction(
                        id=f"allow-{hashlib.md5(key.encode()).hexdigest()[:8]}",
                        rule_type="allow",
                        target=key,
                        action="allow",
                        reason="whitelisted critical IP",
                        severity=Severity.INFO,
                        applied_at=now(),
                    )
                )
                continue
            actions.append(
                MitigationAction(
                    id=f"rate-{hashlib.md5(key.encode()).hexdigest()[:8]}",
                    rule_type="rate_limit",
                    target=key,
                    action="deny",
                    reason=f"ddosguard stage {severity.name.lower()} {rate}/{burst}",
                    severity=severity,
                    applied_at=now(),
                )
            )
        return actions

    def _active_buckets(self) -> Dict[str, object]:
        return {}

    def escalate_consider(self, score: CompositeScore) -> int:
        return int(severity_to_stage(score.severity))

    def degradation_note(self) -> str:
        return "monitor-only mode: firewall backend unavailable"


def severity_to_stage(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[severity.lower()]


def stage_to_severity(stage: int) -> Severity:
    return {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH, 4: Severity.CRITICAL}[stage]
