"""
The monitor: the orchestration loop that ties the pipeline together.

Run model:
    * the monitor runs in a thread inside your server process (dev or prod)
    * an in-memory `MonitorState` expose the pipeline outputs to the dashboard
    * a `MonitorRunner` schedules the loop and feeds it the packet source

Each iteration:
    1. collect `n` windows of traffic (or the configured window width)
    2. fold each window into the baseline model
    3. compute detection score on the latest window
    4. decide mitigation stage (with safeguards) and apply it
    5. publish alert + state to the dashboard

Everything is deterministic given a packet sequence: you can replay a pcap
and the same alerts fire, which is what makes this testable.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .alert import AlertManager
from .core import Alert
from .baseline import BaselineStore
from .config import Config
from .core import (
    Alert as CoreAlert,
    CompositeScore,
    MitigationAction,
    PacketRecord,
    Severity,
    TrafficStats,
)
from .detect import CompositeScorer
from .dashboard import app, state as dashboard_state
from .mitigate import firewall, policy as mit_policy

logger = logging.getLogger("ddosguard")


class MonitorState:
    """Thread-safe read-only view of the pipeline exposed to the dashboard."""

    def __init__(self):
        self._lock = threading.RLock()
        self.stats: Optional[TrafficStats] = None
        self.overall: Optional[CompositeScore] = None
        self.baseline = None
        self.alerts: AlertManager = AlertManager(Config(), "data")
        self.mitigations = mit_policy.MitigationPolicy(Config())
        self.whitelist: WhitelistStore = WhitelistStore()
        self._paused = False
        self._history: List[Dict] = []

    def update(self, stats: TrafficStats, score: CompositeScore) -> None:
        with self._lock:
            self.stats = stats
            self.overall = score
            self._history.append({"ts": datetime.now().isoformat(), "stats": stats, "score": score})
            if len(self._history) > 1000:
                self._history.pop(0)

    def snapshot(self) -> Dict:
        with self._lock:
            return {
                "ts": datetime.now().isoformat(),
                "overall": self.overall.to_dict() if self.overall else None,
                "stats": self.stats.to_dict() if self.stats else None,
                "baseline_ready": self.baseline.ready() if self.baseline else False,
                "baseline_warmup_seconds": self.baseline.warmup_seconds() if self.baseline else 0,
                "alerts": self.alerts.get_timeline(50),
                "mitigations": [a.to_dict() for a in self.mitigations.actions()],
                "whitelist": self.whitelist.list(),
                "paused": self._paused,
            }

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False


class WhitelistStore:
    def __init__(self, path: str | None = None):
        self.path = path or "data/whitelist.json"
        self._lock = threading.RLock()
        self._ips: Dict[str, WhitelistedIp] = {}

    def add(self, ip: str, reason: str = "") -> WhitelistedIp:
        with self._lock:
            entry = WhitelistedIp(ip=ip, reason=reason)
            self._ips[ip] = entry
            self._persist()
            return entry

    def remove(self, ip: str) -> bool:
        with self._lock:
            if ip in self._ips:
                del self._ips[ip]
                self._persist()
                return True
            return False

    def list(self) -> List[dict]:
        with self._lock:
            return [e.to_dict() for e in self._ips.values()]

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def _persist(self) -> None:
        import os

        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in self._ips.values()], fh, indent=2)


class MonitorRunner:
    """
    Drives the pipeline against a packet source.

    `interval` is how often the loop wakes (seconds).  `window_seconds` is the
    length of a statistics window; for a reactive monitor the loop typically
    consumes exactly one window per iteration.
    """

    def __init__(
        self,
        config: Config,
        source,
        *,
        baseline: Optional[BaselineStore] = None,
        alert_mgr: Optional[AlertManager] = None,
        rate_limiter=None,
        firewall_mgr: Optional[firewall.FirewallManager] = None,
        state: Optional[MonitorState] = None,
    ):
        self.config = config
        self.source = source
        self.baseline = baseline or BaselineStore(config)
        self.alert_mgr = alert_mgr or AlertManager(config, config.baseline.get("data_dir", "data"))
        self._rate_limiter = rate_limiter
        self.firewall_mgr = firewall_mgr or firewall.FirewallManager(config)
        self.state = state or MonitorState()
        self.scorer = CompositeScorer(config)
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._window_seconds = config.capture.get("window_seconds", 10)

    # ---- lifecycle --------------------------------------------------------- #
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ddosguard-monitor")
        self._thread.start()
        logger.info("ddosguard monitor started (source=%s, window=%ss)", self.source.name, self._window_seconds)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)

    def is_running(self) -> bool:
        return self._running

    # ---- the loop ---------------------------------------------------------- #
    def _loop(self) -> None:
        epoch = time.monotonic()
        while self._running:
            if self.state._paused:
                time.sleep(0.5)
                continue
            stats = self.source.capture(self._window_seconds, self.config.capture.get("sampling_rate", 0.0))
            if stats is None:
                time.sleep(0.1)
                continue
            with self._lock:
                stats = stats
                ts = datetime.now()
                self.baseline.observe(stats, ts)
                self.state.baseline = self.baseline
                self.state.whitelist = self.state.mitigations.whitelist  # placeholder
                score = self.scorer.score(stats, self.baseline)
                self.state.update(stats, score)

                # Mitigation decision + apply.
                stage = self.state.mitigations.decide(score, self.baseline, stats)
                actions = []
                if stage and stage > 0:
                    rate = self.state.mitigations.find_rate_limit(score.severity)
                    actions = self.state.mitigations.apply(stage)
                    try:
                        self.firewall_mgr.apply(stage, score.severity, rate["rate"], rate["burst"])
                    except Exception as exc:
                        logger.warning("firewall apply failed: %s", exc)

                # Alerting.
                if score.severity >= Severity.LOW:
                    self.alert_mgr.generate(score, stats, self.baseline, stage)
                    self.state.alerts = self.alert_mgr
                    if self.config.alerting.get("email", {}).get("enabled", False):
                        self._deliver_email(score, stats, stage)

                dashboard_state.update(stats, score)
                with self._lock:
                    self.state = self.state
            time.sleep(0.05)

    def _deliver_email(self, score, stats, stage) -> None:
        try:
            alert = Alert(
                alert_id="mail-" + score.severity.name.lower(),
                severity=score.severity,
                title=self.alert_mgr._title(score.severity, score),
                summary=self.alert_mgr._summary(score.severity, stats, score),
                attack_indicators=self.alert_mgr._indicators(stats, score, self.baseline),
                current_mitigation={"stage": stage},
                occurred_at=datetime.now(),
            )
            self.alert_mgr.deliver(alert)
        except Exception as exc:
            logger.warning("email alert failed: %s", exc)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
