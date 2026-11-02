"""Unit tests for the anomaly detection signals and scoring."""
import datetime

from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import CompositeScore, PacketRecord, Protocol, Severity, TrafficStats
from ddosguard.detect import CompositeScorer, signals as sig
from ddosguard.metrics.window import WindowAggregator


def _stats(packet_rate=100.0, per_proto=None, unique_sources=50, dst_port_dist=None, syn_ratio=0.0):
    if per_proto is None:
        per_proto = {6: 100, 17: 1, 1: 1}
    if dst_port_dist is None:
        dst_port_dist = {80: 400, 443: 300, 22: 100}
    win_start = datetime.datetime(2026, 1, 1, 14, 0)
    window = WindowAggregator(window_seconds=1.0, start=win_start)
    for i in range(int(packet_rate)):
        window.add(PacketRecord(ts=win_start + datetime.timedelta(seconds=i / 1000.0),
                                src_ip="10.0.0.1", dst_ip="10.0.0.9",
                                protocol=Protocol.TCP, src_port=12345, dst_port=80, length=100))
    window._last_ts = window.start.timestamp() + 1.0
    return window.finalize()


def test_volume_signal_detects_spike():
    cfg = Config(detection={"volume_sigma": 5.0})
    store = BaselineStore(cfg)
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    # Train baseline with varying 80..120 pps traffic so stdev > 0.
    for i in range(200):
        stats = _stats(packet_rate=80.0 + i * 0.2)
        store.observe(stats, ts)
    # A 200 pps spike above the 80..120 baseline gives a z-score.
    stats = _stats(packet_rate=200.0)
    result = sig.volume_signal(stats, store, cfg)
    assert result.score >= 0.0
    big = _stats(packet_rate=1000.0)
    result_big = sig.volume_signal(big, store, cfg)
    assert result_big.score > result.score


def test_protocol_signal_detects_share_shift():
    cfg = Config(detection={"source_concentration_threshold": 0.4})
    store = BaselineStore(cfg)
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    # Train baseline with 80% TCP, 20% UDP split.
    for _ in range(200):
        stats = _stats(per_proto={6: 800, 17: 200, 1: 20})
        store.observe(stats, ts)
    # 90% UDP is a protocol shift.
    stats = TrafficStats(
        window=_stats(packet_rate=10.0).window,
        per_proto={6: 100, 17: 900},
        unique_sources=20,
        unique_dests=5,
        top_srcs=[("10.0.0.1", 10)],
        top_ports=[(80, 10), (53, 900)],
        src_port_dist={80: 10, 53: 900},
        dst_port_dist={80: 10, 53: 900},
        syn_ratio=0.0,
        byte_rate=1000.0,
    )
    result = sig.protocol_signal(stats, store, cfg)
    assert result.score > 0.0


def test_source_signal_detects_concentration():
    cfg = Config(detection={"source_concentration_threshold": 0.4})
    store = BaselineStore(cfg)
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    store.observe(_stats(), ts)
    stats = TrafficStats(
        window=_stats(packet_rate=10.0).window,
        per_proto={6: 1000},
        unique_sources=2,
        unique_dests=1,
        top_srcs=[("10.0.0.1", 800), ("10.0.0.2", 200)],
        top_ports=[(80, 1000)],
        src_port_dist={80: 1000},
        dst_port_dist={80: 1000},
        syn_ratio=0.0,
        byte_rate=1000.0,
    )
    result = sig.source_signal(stats, store, cfg)
    assert result.score > 0.3


def test_composite_scorer_outputs_severity():
    cfg = Config(detection={"volume_sigma": 5.0})
    scorer = CompositeScorer(cfg)
    store = BaselineStore(Config())
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    for _ in range(200):
        stats = _stats(packet_rate=80.0 + 0.5 * _)
        store.observe(stats, ts)
    stats = _stats(packet_rate=900.0)
    score = scorer.score(stats, store)
    assert isinstance(score, CompositeScore)
    assert 0.0 <= score.total <= 1.0
    assert score.severity in Severity
    assert score.classification in ("none", "volumetric", "protocol", "application", "mixed")


def test_scorer_never_exceeds_one():
    cfg = Config(detection={"weights": {"volume": 0.35, "protocol": 0.15, "source": 0.2, "port": 0.15, "syn": 0.15}})
    scorer = CompositeScorer(cfg)
    store = BaselineStore(Config())
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    for _ in range(200):
        stats = _stats(packet_rate=80.0 + 0.5 * _)
        store.observe(stats, ts)
    stats = _stats(packet_rate=100000.0)
    score = scorer.score(stats, store)
    assert score.total <= 1.0
