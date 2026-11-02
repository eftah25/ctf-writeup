"""
Replay a saved pcap trace file through the pipeline.

Useful for offline analysis, CI and demonstrating detection on real-traffic
traces without root or a NIC.  Any pcap readable by scapy is supported.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Iterator

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP

from .base import PacketSource
from ..core import PacketRecord, Protocol, TrafficStats, TrafficWindow

logger = logging.getLogger("ddosguard.capture")


class PcapSource(PacketSource):
    """Read-only pcap replay source."""

    name = "pcap"

    def __init__(self, path: str, window_seconds: float = 10.0):
        self.path = path
        self.window_seconds = window_seconds
        self.packets: list[PacketRecord] = []
        self._idx = 0
        self._loaded = False
        self._load()

    def _load(self) -> None:
        from scapy.all import rdpcap

        scapy_pkts = rdpcap(self.path)
        self.packets = [self._to_record(p) for p in scapy_pkts]
        self._loaded = True
        logger.info("replayed %d packets from %s", len(self.packets), self.path)

    @staticmethod
    def _to_record(pkt) -> PacketRecord:
        ip = pkt.get(IP, None)
        if ip is None:
            return PacketRecord(
                ts=datetime.now(), src_ip="0.0.0.0", dst_ip="0.0.0.0", protocol=Protocol.OTHER, length=len(pkt)
            )
        proto = Protocol.from_int(getattr(ip, "proto", 0))
        src_port = getattr(pkt.get(TCP, None), "sport", 0)
        if src_port == 0:
            src_port = getattr(pkt.get(UDP, None), "sport", 0)
        dst_port = getattr(pkt.get(TCP, None), "dport", 0)
        if dst_port == 0:
            dst_port = getattr(pkt.get(UDP, None), "dport", 0)
        flags = ""
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
        return PacketRecord(
            ts=pkt.time,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            length=len(pkt),
            flags=flags,
            payload_bytes=len(pkt[IP].payload),
        )

    def iter_packets(self, window_seconds: float, sampling_rate: float = 0.0) -> Iterator[PacketRecord]:
        for p in self.packets:
            yield p

    def capture(self, window_seconds: float, sampling_rate: float = 0.0) -> TrafficStats:
        if not self._loaded:
            raise RuntimeError("pcap source not loaded")
        end = min(self._idx + int(window_seconds / 10), len(self.packets))
        window = TrafficWindow(
            start=datetime.now(), end=datetime.now(), packet_count=end - self._idx, byte_count=0, protocol_counts={}
        )
        walker = WindowWalker()
        for rec in self.packets[self._idx:end]:
            walker.add(rec)
            window.packet_count += 1
            window.byte_count += rec.length
            self._idx = end
        return walker.finalize()


class WindowWalker:
    """Incremental window summarizer shared by pcap replay."""

    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts: dict = {}
        self.top_ports: dict = {}

    def add(self, rec: PacketRecord) -> None:
        self.packet_count += 1
        self.byte_count += rec.length
        self.protocol_counts[rec.protocol] = self.protocol_counts.get(rec.protocol, 0) + 1
        self.top_ports[rec.dst_port] = self.top_ports.get(rec.dst_port, 0) + 1

    def finalize(self) -> TrafficStats:
        return TrafficStats(
            window=TrafficWindow(start=datetime.now(), end=datetime.now(), packet_count=self.packet_count, byte_count=self.byte_count, protocol_counts=self.protocol_counts),
            per_proto=self.protocol_counts,
            unique_sources=0,
            unique_dests=len(self.top_ports),
            dst_port_dist=self.top_ports,
        )
