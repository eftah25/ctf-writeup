"""Unit tests for the alert manager."""
import datetime

from ddosguard.baseline.store import BaselineStore
from ddosguard.config import Config
from ddosguard.core import PacketRecord, Protocol, Severity, TrafficStats
from ddosguard.metrics.window import WindowAggregator
from ddosguard.alert import AlertManager


def _stats(packet_rate=100.0):
    window = WindowAggregator(window_seconds=10.0, start=datetime.datetime(2026, 1, 1, 14, 0))
    for _ in range(int(packet_rate)):
        window.add(PacketRecord(ts=window.start, src_ip="10.0.0.1", dst_ip="10.0.0.9",
                                 protocol=Protocol.TCP, src_port=12345, dst_port=80, length=100))
    window._last_ts = window.start.timestamp() + 10.0
    stats = window.finalize()
    stats.syn_ratio = 0.0
    return stats


def test_alert_manager_generates_unique_ids():
    cfg = Config(alerting={"enabled": True, "cooldown_seconds": 120})
    manager = AlertManager(cfg)
    a1 = manager.generate(None, _stats(packet_rate=100.0), None, 0)
    a2 = manager.generate(None, _stats(packet_rate=200.0), None, 0)
    assert a1.alert_id != a2.alert_id
