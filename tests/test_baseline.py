"""Unit tests for the diurnal baseline store."""
import datetime

from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import PacketRecord, Protocol, TrafficStats
from ddosguard.metrics.window import WindowAggregator


def _pkt(ts, proto=Protocol.TCP, dport=80, length=100):
    return PacketRecord(ts=ts, src_ip="10.0.0.1", dst_ip="10.0.0.9", protocol=proto,
                        src_port=12345, dst_port=dport, length=length)


def _stats(packets=10, proto_share=None, unique_sources=50, dst_port_dist=None, syn_ratio=0.0):
    if proto_share is None:
        proto_share = {6: 1000, 17: 5, 1: 1}
    if dst_port_dist is None:
        dst_port_dist = {80: 400, 443: 300}
    win_start = datetime.datetime(2026, 1, 1, 14, 0)
    window = WindowAggregator(window_seconds=10.0, start=win_start)
    for _ in range(packets):
        window.add(_pkt(window.start))
    window._last_ts = window.start.timestamp() + 10.0
    return window.finalize()


def test_model_accumulates_samples(tmp_path):
    cfg = Config(baseline={"data_dir": str(tmp_path)})
    store = BaselineStore(cfg)
    ts = datetime.datetime(2026, 1, 1, 14, 0)
    for i in range(200):
        stats = _stats(packets=500 + i)
        store.observe(stats, ts)
    model = store.expected("packets", ts, _stats())
    assert model.count >= 1
    assert model.mean >= 50.0
    assert model.stdev > 0.0
    # p95 should be in the upper part of the observed range (50..69.9 pps).
    assert model.p95 >= 60.0


def test_percentiles_increasing(tmp_path):
    cfg = Config(baseline={"data_dir": str(tmp_path)})
    store = BaselineStore(cfg)
    ts = datetime.datetime.now()
    for packets in range(1, 101):
        stats = _stats(packets=packets)
        store.observe(stats, ts)
    model = store.expected("packets", ts, _stats())
    assert model.p25 >= 2.0
    assert model.p75 >= 7.0
    assert model.p95 >= 9.0
