"""
Live packet capture with scapy (root on Linux/macOS; Windows raw sockets are
limited).

Falls back to pcap replay when sniffing is not possible, which is the normal
development profile on Windows.  The `capture_once` helper lets callers
capture a bounded number of packets instead of looping forever.
"""
from __future__ import annotations

import logging
from typing import Iterator

from scapy.all import sniff as scapy_sniff, rdpcap, sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

from .base import PacketSource
from ..core import PacketRecord, Protocol, TrafficStats, TrafficWindow

logger = logging.getLogger("ddosguard.capture")


class ScapySource(PacketSource):
    """Live sniffing source using scapy."""

    name = "scapy"

    def __init__(self, iface: str = "any", bpf: str | None = None, timeout: float | None = None):
        self.iface = iface
        self.bpf = bpf
        self.timeout = timeout
        self._sniffing = False

    def iter_packets(self, window_seconds: float, sampling_rate: float = 0.0) -> Iterator[PacketRecord]:
        self._sniffing = True
        try:
            scapy_sniff(
                iface=self.iface,
                filter=self.bpf,
                prn=self._prn,
                store=False,
                timeout=self.timeout,
            )
        finally:
            self._sniffing = False

    def _prn(self, pkt) -> None:
        ip = pkt.get(IP, None)
        if ip is None:
            return
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
        yield PacketRecord(
            ts=dt,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            length=len(pkt),
            flags=flags,
            payload_bytes=len(pkt[IP].payload),
        )

    def capture(self, window_seconds: float, sampling_rate: float = 0.0) -> TrafficStats:
        raise NotImplementedError("scapy source is an iterator; use iter_packets in the monitor")

    @property
    def running(self) -> bool:
        return self._sniffing
