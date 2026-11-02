"""Unit tests for the rolling window aggregator."""
from datetime import datetime, timedelta

import pytest

from ddosguard.core import PacketRecord, Protocol
from ddosguard.metrics.window import WindowAggregator, RollingAggregator


def _pkt(ts, src="10.0.0.1", dst="10.0.0.9", proto=Protocol.TCP, dport=80, length=100):
    return PacketRecord(ts=ts, src_ip=src, dst_ip=dst, protocol=proto, src_port=12345, dst_port=dport, length=length)


def test_window_accumulates_packets():
    # Packets span 0..10s of the window, so the elapsed span is 10s.
    start = datetime(2026, 1, 1, 12, 0, 0)
    agg = WindowAggregator(window_seconds=10.0, start=start)
    agg._last_ts = start.timestamp() + 10.0
    for i in range(5):
        agg.add(_pkt(start + timedelta(seconds=2 * i)))
    stats = agg.finalize()
    # 5 packets over a 10s window span => 0.5 pps.
    assert stats.packet_rate == pytest.approx(0.5)
    assert stats.window.packet_count == 5
    assert stats.unique_sources == 1
    assert stats.unique_dests == 1
    assert stats.top_ports == [(80, 5)]
    assert stats.syn_ratio == 0.0


def test_window_counters_protocol_split():
    start = datetime(2026, 1, 1)
    agg = WindowAggregator(window_seconds=10.0, start=start)
    agg.end = start
    agg.add(_pkt(start, proto=Protocol.TCP, dport=80, length=60))
    agg.add(_pkt(start, proto=Protocol.UDP, dport=53, length=60))
    stats = agg.finalize()
    per_proto = stats.per_proto
    assert per_proto[6] == 1
    assert per_proto[17] == 1
    assert stats.syn_ratio == 0.0


def test_rolling_aggregator_roll_over():
    agg = RollingAggregator(window_seconds=1.0, capacity=3)
    base = datetime(2026, 1, 1, 0, 0, 0)
    for i in range(4):
        t = base + timedelta(seconds=i)
        agg.add(_pkt(t))
    # Packets arrive exactly on 1s boundaries.  A commit happens when the
    # *next* packet's timestamp is >= window_seconds after the window's
    # start, so the committed windows are [0,1) = packets at 0 and 1, then
    # [1,2) = packet at 2, then [2,3) = packet at 3.  That yields 3 windows
    # with packet rates 2.0, 1.0, 1.0.
    assert len(agg.windows) == 3
    assert agg.windows[0].packet_rate == pytest.approx(2.0)
    assert agg.windows[1].packet_rate == pytest.approx(1.0)
    assert agg.windows[2].packet_rate == pytest.approx(1.0)
