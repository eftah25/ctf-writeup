"""
Configuration: defaults, schema validation and YAML loading.

Configuration is split into sections mirroring the pipeline stages so
administrators can tune detection thresholds, mitigation escalation and
alerting without touching code.  All numeric thresholds are documented in
their sections; see docs/DEPLOYMENT.md for guidance on choosing values.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    # --------------------------------------------------------------------------
    # Traffic capture
    # --------------------------------------------------------------------------
    "capture": {
        # Source of packets.  Options: "scapy" (live), "pcap" (replay file),
        # "synthetic" (demo generator).  Synthetic is the only option that
        # works without root/default gateway permissions.
        "source": "synthetic",
        "interface": "0.0.0.0",
        "bpf": None,
        # Window in seconds used for per-window statistics.  Small windows give
        # fast detection, larger windows are more stable.
        "window_seconds": 10,
        # Number of recent windows kept for trend display (no analytics).
        "history_size": 120,
        # When capturing at line rate, analysis can bottleneck.  Randomly drop
        # packets so the monitor keeps up; 0 = process everything.
        "sampling_rate": 0.0,
        "pcap_file": "data/live.pcap",
    },

    # --------------------------------------------------------------------------
    # Baseline
    # --------------------------------------------------------------------------
    "baseline": {
        # Days of history required before the store is "ready" for detection.
        # During warmup detections run but are flagged as uncalibrated.
        "min_days": 1,
        # How many values per metric we keep in the percentile reservoir.
        "reservoir_size": 500,
        # Minute-level resolution for bandwidth trend history.  Set to null to
        # disable trend history (saves disk).
        "trend_resolution_seconds": 60,
        "trend_window_seconds": 24 * 3600,
        # Directory for persistent baseline/bandwidth/alert files.
        "data_dir": "data",
        # Threshold for "stable" metric during baseline training: the metric's
        # coefficient of variation must stay below this.
        "stability_cv": 0.35,
    },

    # --------------------------------------------------------------------------
    # Detection
    # --------------------------------------------------------------------------
    "detection": {
        # Window counts over which signals are evaluated.  A signal is only
        # "warmed up" after this many windows; otherwise severity is downgraded.
        "minimum_samples": 3,
        # Volatility of the volume signal before it is trusted: z-score
        # threshold.  5 sigma is the classic "obvious DDoS" rule of thumb.
        "volume_sigma": 5.0,
        "volume_sigma_warn": 3.0,
        # How many windows a signal must stay above its threshold before the
        # composite score counts it.  Prevents single-window glitches.
        "confirmation_windows": 3,
        # Threshold above which a protocol share shift is suspicious.
        "protocol_shift_eps": 0.15,
        # Share of traffic from a single source IP that is suspicious.
        "source_concentration_threshold": 0.4,
        # Minimum percentage of packets that must be UDP for a UDP flood.
        "udp_flood_share": 0.6,
        # Syn (SYN|ACK) ratio anomaly window size in packets.
        "syn_window_size": 200,
        # Number of destinations that must be targeted for application-layer.
        "app_targeting_min": 3,
        # Weights used by CompositeScorer for the final score.
        "weights": {
            "volume": 0.35,
            "protocol": 0.15,
            "source": 0.20,
            "port": 0.15,
            "syn": 0.15,
        },
    },

    # --------------------------------------------------------------------------
    # Mitigation
    # --------------------------------------------------------------------------
    "mitigation": {
        # Minimum severity that triggers automatic mitigation.
        "min_severity": "medium",
        # Escalation ladder: severity -> (rate, burst) in packets/sec per IP.
        "rate_limits": [
            {"severity": "low", "rate": 10000, "burst": 2000},
            {"severity": "medium", "rate": 2000, "burst": 500},
            {"severity": "high", "rate": 500, "burst": 100},
            {"severity": "critical", "rate": 100, "burst": 50},
        ],
        # Latch that blocks sources of worst traffic.  Shared by all stages.
        "source_block": {"min_severity": "medium", "max_sources": 50},
        # How many windows a mitigation must stay active before it is removed
        # (damping prevents flapping).
        "damping_windows": 6,
        # IPs that are never blocked, ever.
        "whitelist": [],
        # Local proxy endpoint to rate-limit: "<host>:<port>" (token bucket
        # applied at the proxy, not at the packet level).
        "proxy_endpoint": None,
        # When true, writing firewall rules prints a diff instead of applying.
        "dry_run": True,
        # Firewall backend.  Options: "iptables", "nftables", "none" (generate
        # only).  Relying on these requires root + a Linux host.  The generated
        # rules are offline-agnostic.
        "firewall_backend": "iptables",
    },

    # --------------------------------------------------------------------------
    # Alerting
    # --------------------------------------------------------------------------
    "alerting": {
        "enabled": True,
        # Channel availability (set to true to wire up that channel).
        "slack_webhook": "",
        "email": {
            "enabled": False,
            "smtp_host": "localhost",
            "smtp_port": 25,
            "from": "ddosguard@example.com",
            "to": ["admin@example.com"],
            "tls": False,
            "username": "",
            "password": "",
        },
        # Maximum alerts of the same signature per minute before we throttle.
        "max_per_minute": 5,
        # Minimum seconds between two notifications about the same signature.
        "cooldown_seconds": 120,
        # Critical alerts are always sent immediately; others are batched in
        # the alert file and sent by the runner.
        "immediate_critical": True,
        # Desktop notification backend: "auto", "win", "linux", "mac".
        "desktop": "auto",
    },

    # --------------------------------------------------------------------------
    # Dashboard
    # --------------------------------------------------------------------------
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8080,
        "title": "DDoS Mitigation Dashboard",
    },
}

SECTIONS = tuple(DEFAULT_CONFIG.keys())


@dataclass(frozen=True)
class Config:
    capture: Dict[str, Any] = field(default_factory=dict)
    baseline: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    mitigation: Dict[str, Any] = field(default_factory=dict)
    alerting: Dict[str, Any] = field(default_factory=dict)
    dashboard: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        cfg = cls()
        data: Dict[str, Any] = {}
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            data = {}
        for section in SECTIONS:
            setattr(cfg, section, data.get(section, DEFAULT_CONFIG[section]))
        return cfg

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(self.to_dict(), fh, default_flow_style=False, sort_keys=False)

    def to_dict(self) -> Dict[str, Any]:
        return {s: getattr(self, s) for s in SECTIONS}

    def find_rate_limit(self, severity: str) -> Dict[str, Any]:
        for entry in self.mitigation["rate_limits"]:
            if entry["severity"] >= severity:
                return entry
        return self.mitigation["rate_limits"][-1]

    def is_enabled(self, channel: str) -> bool:
        if channel == "slack":
            return bool(self.alerting.get("slack_webhook"))
        if channel == "email":
            return self.alerting.get("email", {}).get("enabled", False)
        return self.alerting.get("enabled", True)
