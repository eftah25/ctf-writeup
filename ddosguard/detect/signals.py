"""Root-cause anomaly signals.

Each signal takes the current window's statistics plus the corresponding
baseline model and produces a single SignalResult in [0, 1].  Signals are
deliberately independent: one of them fires on a volumetric flood, another on
a SYN storm, another on a targeted application-layer attack, and they all
work on a small, bounded dataset (per-window counters) so analysis never
becomes a bottleneck.

Scoring conventions:
    * higher = more anomalous
    * scores are clipped to [0, 1] for the composite
    * every signal supplies `affected` (IPs / ports / countries) for the
      alert payload
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Dict, List, Optional

from ..baseline.store import BaselineStore
from ..config import Config
from ..core import Protocol, SignalResult, TrafficStats

SIG_NAME = "signal"


def _zscore(current: float, baseline: BaselineStore, metric: str, ts: datetime) -> float:
    """Compute (current - mean) / stdev for a metric against baseline.

    Returns 0.0 if fewer than 2 observations or stdev == 0, rather than raising,
    so signals can safely return score=0.0 when baseline is not yet warmed up.
    """
    model = baseline.expected(metric, ts, None)
    if model.count < 2 or model.stdev == 0:
        return 0.0
    return (current - model.mean) / model.stdev


def _bucket_ts(stats: TrafficStats) -> datetime:
    """Use the window's start time as the bucket time so the signals and the
    baseline model agree (tests can fix the window time deterministically)."""
    return stats.window.start


def volume_signal(stats: TrafficStats, baseline: BaselineStore, config: Config) -> SignalResult:
    """A sudden spike in packet/byte rate versus the diurnal baseline.

    Uses 1.0 - exp(-z/sigma) instead of raw z/sigma for the score because:
    * It is bounded in [0, 1] without needing arbitrary threshold choices
    * score -> 0 as z -> 0 (no anomaly)
    * score -> 1 as z -> infinity (extreme anomaly)
    * Smooth, no edge cases where score > 1 or < 0
    * sigma (config.detection["volume_sigma"]) controls steepness, not a hard cutoff
    """
    ts = _bucket_ts(stats)
    model = baseline.expected("packets", ts, stats)
    if model.count < 2:
        return SignalResult(name="volume", score=0.0, detail={"n": model.count})
    z = _zscore(stats.packet_rate, baseline, "packets", ts)
    score = 1.0 - math.exp(-max(0.0, z) / max(1.0, config.detection["volume_sigma"]))
    return SignalResult(
        name="volume",
        score=min(1.0, score),
        detail={
            "current_pkts": round(stats.packet_rate, 1),
            "baseline_mean": round(model.mean, 1),
            "baseline_p95": round(model.p95, 1),
            "z": round(z, 2),
            "overflow": "+++" if z >= 10 else "++" if z >= 5 else "+",
        },
        affected=[f"{stats.top_srcs[0][0]}" if stats.top_srcs else "unknown"],
        recommended_action="start_rate_limit",
    )


def protocol_signal(stats: TrafficStats, baseline: BaselineStore, config: Config) -> SignalResult:
    """Protocol distribution shifted away from normal (e.g. 80% TCP -> 20% UDP).

    Computes two independent measures and takes max(share, udp_score):
    * `share` = Euclidean distance between current and baseline protocol proportions
      captures overall distribution shift (e.g. 90% TCP vs baseline 70/30)
    * `udp_z` = z-score for UDP specifically captures UDP flood attacks
    Taking max means: "if either the overall shifted unusually OR UDP is unusually
    dominant, fire the signal." Either condition alone justifies flagging.
    """
    if not stats.per_proto or len(stats.per_proto) < 2:
        return SignalResult(name="protocol", score=0.0)
    total = sum(stats.per_proto.values())
    current = {Protocol(k).name: v / total for k, v in stats.per_proto.items()}
    ts = _bucket_ts(stats)
    model = baseline.expected("protocol", ts, stats)
    if model.count < 2:
        return SignalResult(name="protocol", score=0.0, detail={"n": model.count})
    # Compare each current protocol share against the baseline mean.
    keys = sorted(set(current.keys()))
    dist = 0.0
    for k in keys:
        d = current.get(k, 0.0) - model.mean
        dist += d * d
    share = min(1.0, math.sqrt(dist) / 0.5)  # 0.5 is the scale normalization
    udp_now = current.get("UDP", 0.0)
    udp_p95 = max(0.0, model.p95) if model.p95 else 0.0
    udp_z = (udp_now - udp_p95) / max(udp_p95 * 0.5, 0.01)
    udp_score = min(1.0, max(0.0, udp_z / 5.0))
    score = max(share, udp_score)  # fire if either condition indicates anomaly
    affected = [p for p, c in stats.dst_port_dist.items()][:5]
    return SignalResult(
        name="protocol",
        score=min(1.0, score),
        detail={
            "current": {k: round(v, 3) for k, v in sorted(current.items(), key=lambda kv: -kv[1])},
            "shift": round(share, 3),
            "udp_share": round(udp_now, 3),
        },
        affected=affected,
        recommended_action="check_protocol",
    )


def source_signal(stats: TrafficStats, baseline: BaselineStore, config: Config) -> SignalResult:
    """Source-IP concentration: a few IPs carrying a huge share of traffic.

    Uses top_srcs[0][1] / packet_rate (the #1 source's share), NOT unique source IP count.
    Unique IP count would miss the volume concentration aspect: a DDoS could use
    1000 IPs each at low rate (distributed) or 1 IP at very high rate (concentrated).
    This signal detects the latter: "are a few sources sending most of the traffic?"
    """
    if stats.unique_sources < 2:
        return SignalResult(name="source", score=0.0)
    srcs = stats.top_srcs
    share = srcs[0][1] / stats.packet_rate if stats.packet_rate else 0.0
    # Divide by config threshold (default ~concentration level) to scale score
    score = min(1.0, share / max(config.detection["source_concentration_threshold"], 0.01))
    if len(srcs) > 1:
        new_share = sum(c for _, c in srcs[1:]) / stats.packet_rate if stats.packet_rate else 0.0
    else:
        new_share = 0.0
    detail = {"top_share": round(share, 3), "unique": stats.unique_sources, "new_share": round(new_share, 3)}
    return SignalResult(
        name="source",
        score=min(1.0, score),
        detail=detail,
        affected=[s[0] for s in srcs[:10]],
        recommended_action="block_source_ips" if score > 0.6 else "verify_sources",
    )


def port_signal(stats: TrafficStats, baseline: BaselineStore, config: Config) -> SignalResult:
    """Traffic concentrated on a few destination ports (application-layer attack).

    Measures top port's share of total traffic. Similar concentration logic to
    source_signal: a few ports getting most traffic indicates an application-layer
    flood targeting a specific service (e.g., HTTP flood on port 8080).
    """
    if not stats.dst_port_dist or len(stats.dst_port_dist) < 2:
        return SignalResult(name="port", score=0.0)
    top = stats.dst_port_dist
    total = sum(top.values())
    shares = {p: c / total for p, c in top.items()}
    top_port = sorted(shares.items(), key=lambda kv: -kv[1])[0]
    # Same concentration threshold as source_signal for cross-signal consistency
    score = min(1.0, top_port[1] / max(config.detection["source_concentration_threshold"], 0.01))
    affected = [p for p, c in top.items()][:5]
    return SignalResult(
        name="port",
        score=min(1.0, score),
        detail={"top_port": top_port[0], "share": round(top_port[1], 3)},
        affected=affected,
        recommended_action="mitigate_port" if score > 0.5 else "monitor",
    )


def syn_signal(stats: TrafficStats, baseline: BaselineStore, config: Config) -> SignalResult:
    """SYN (or SYN|ACK) ratio anomaly typical of a protocol/SYN flood.

    Same stdev guard as _zscore: with <2 baseline observations, stdev is 0/undefined,
    z-score is meaningless, so signal correctly returns score=0.0 (no detection yet).
    The z / max(3.0, volume_sigma) divisor ensures the SYN signal isn't as sensitive
    as volume when volume_sigma is set very low, preventing false positives from normal variation.
    """
    if stats.unique_sources < 2:
        return SignalResult(name="syn", score=0.0)
    syn_ratio = stats.syn_ratio
    ts = _bucket_ts(stats)
    model = baseline.expected("syns", ts, stats)
    if model.count < 2:
        return SignalResult(name="syn", score=0.0, detail={"n": model.count})
    z = _zscore(syn_ratio, baseline, "syns", ts)
    score = min(1.0, max(0.0, z / max(3.0, config.detection["volume_sigma"])))
    affected = [src for src, _ in stats.top_srcs[:5]] if stats.top_srcs else []
    return SignalResult(
        name="syn",
        score=min(1.0, score),
        detail={"syn_ratio": round(syn_ratio, 4), "baseline_mean": round(model.mean, 4), "z": round(z, 2)},
        affected=affected,
        recommended_action="mitigate_protocol",
    )


def _severity_from_score(score: float, config: Config) -> str:
    """Map a 0..1 signal score to a severity string.

    Thresholds (0.2 width bands) are arbitrary but reasonable cutpoints:
    * <0.2  = basically normal noise
    * 0.2-0.4 = mild anomaly worth monitoring
    * 0.4-0.6 = clear anomaly, investigate
    * 0.6-0.8 = strong anomaly, prepare mitigation
    * >0.8 = crisis, immediate action required
    """
    thresholds = {
        0.0: "info",
        0.2: "low",
        0.4: "medium",
        0.6: "high",
        0.8: "critical",
    }
    for threshold, severity in sorted(thresholds.items()):
        if score >= threshold:
            return severity
    return "info"