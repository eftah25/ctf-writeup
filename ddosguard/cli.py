"""
Command-line interface for ddosguard.

    python -m ddosguard baseline --seconds 120      # train the baseline
    python -m ddosguard monitor                    # live monitor + dashboard
    python -m ddosguard replay trace.pcap          # offline analysis
    python -m ddosguard simulate                   # attack demo
    python -m ddosguard alert --file data/alerts.jsonl
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .alert import AlertManager
from .baseline import BaselineStore
from .config import Config
from .capture import pcap_source, scapy_source
from .capture.base import SyntheticGenerator
from .detect import CompositeScorer
from .metrics.window import WindowAggregator
from .mitigate import firewall
from .mitigate.policy import MitigationPolicy
from .core import Severity, SEVERITY_ORDER

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ddosguard")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ddosguard", description="DDoS detection and mitigation toolkit")
    p.add_argument("--version", action="version", version=f"ddosguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    baseline = sub.add_parser("baseline", help="train the baseline model")
    baseline.add_argument("--seconds", type=int, default=600, help="how long to observe normal traffic")
    baseline.add_argument("--config", default="config.yaml")
    baseline.add_argument("--source", choices=["synthetic", "scapy", "pcap"], default="synthetic")
    baseline.add_argument("--pcap", default=None)
    baseline.add_argument("--interval", type=float, default=10.0)

    monitor = sub.add_parser("monitor", help="live monitor with dashboard")
    monitor.add_argument("--config", default="config.yaml")
    monitor.add_argument("--no-dashboard", action="store_true")
    monitor.add_argument("--host", default="127.0.0.1")
    monitor.add_argument("--port", type=int, default=8080)

    replay = sub.add_parser("replay", help="analyze a pcap trace offline")
    replay.add_argument("pcap", help="pcap file to replay")
    replay.add_argument("--window", type=float, default=10.0)

    simulate = sub.add_parser("simulate", help="synthetic attack demo")
    simulate.add_argument("--family", choices=["volumetric", "syn_flood", "application"], default="volumetric")
    simulate.add_argument("--duration", type=float, default=45.0)
    simulate.add_argument("--packets", type=int, default=20000)

    alert = sub.add_parser("alert", help="show/persist alerts")
    alert.add_argument("--file", default="data/alerts.jsonl")
    alert.add_argument("--limit", type=int, default=20)

    dashboard = sub.add_parser("dashboard", help="run dashboard only")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8080)
    dashboard.add_argument("--config", default="config.yaml")

    return p


def _load_config(path: str | None) -> Config:
    cfg_path = path or "config.yaml"
    return Config.load(cfg_path)


def _make_source(config: Config, source: str, pcap_file: str | None = None):
    if source == "pcap":
        return pcap_source.PcapSource(pcap_file or config.capture.get("pcap_file", "data/live.pcap"))
    if source == "scapy":
        return scapy_source.ScapySource(config.capture.get("interface", "any"))
    return SyntheticGenerator(mode="normal")


# --------------------------------------------------------------------------- #
# Subcommands                                                               #
# --------------------------------------------------------------------------- #
def cmd_baseline(args) -> int:
    config = _load_config(args.config)
    source = _make_source(config, args.source, args.pcap)
    baseline = BaselineStore(config, data_dir=config.baseline.get("data_dir", "data"))
    baseline.load()
    baseline.set_ready(True)
    logger.info("baseline loaded: %d models", len(baseline.all()))

    win_sec = config.capture.get("window_seconds", 10)
    window = WindowAggregator(win_sec)
    scorer = CompositeScorer(config)
    end = time.monotonic() + args.seconds
    samples = 0
    while time.monotonic() < end:
        for pkt in source.iter_packets(win_sec):
            window.add(pkt)
            if (pkt.ts - window.start).total_seconds() >= win_sec:
                stats = window.finalize()
                baseline.observe(stats, pkt.ts)
                samples += 1
                if samples % 10 == 0:
                    logger.info("baseline: observed %d windows", samples)
                window = WindowAggregator(win_sec)
        time.sleep(0.05)
    baseline.save()
    logger.info("baseline saved (%d models)", len(baseline.all()))
    return 0


def cmd_monitor(args) -> int:
    config = _load_config(args.config)
    source = _make_source(config, config.capture.get("source", "synthetic"))

    from .monitor import MonitorRunner

    monitor = MonitorRunner(config, source)
    monitor.state.baseline = monitor.baseline
    monitor.state.mitigations = MitigationPolicy(config)
    monitor.start()

    if not args.no_dashboard:
        import uvicorn

        from .dashboard import app

        logger.info("dashboard: http://%s:%d", args.host, args.port)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")

    monitor.stop()
    return 0


def cmd_replay(args) -> int:
    config = _load_config(None)
    source = pcap_source.PcapSource(
        args.pcap, window_seconds=config.capture.get("window_seconds", 10)
    )
    baseline = BaselineStore(config)
    scorer = CompositeScorer(config)
    win_sec = config.capture.get("window_seconds", 10)
    aggregator = WindowAggregator(win_sec)
    seq = list(source.iter_packets(win_sec, 0.0))
    stats = None
    for i in range(0, len(seq), 100):
        chunk = seq[i : i + 100]
        for pkt in chunk:
            aggregator.add(pkt)
        stats = aggregator.finalize()
        score = scorer.score(stats, baseline)
        logger.info(
            "[%04d] pps=%.1f bytes=%.0f proto=%s score=%.3f sev=%s",
            i // 100,
            stats.packet_rate,
            stats.byte_rate,
            {6: stats.per_proto.get(6, 0), 17: stats.per_proto.get(17, 0)},
            score.total,
            score.severity,
        )
    return 0


def cmd_simulate(args) -> int:
    generator = SyntheticGenerator(
        mode="attack",
        attack_family=args.family,
        attack_start=datetime.now(),
        attack_duration=args.duration,
        attack_mult=20,
    )
    logger.info("generating %s attack for %.1fs", args.family, args.duration)
    for pkt in generator.iter_packets(10.0, 0.0):
        print(pkt.src_ip, pkt.dst_ip, pkt.protocol.name, pkt.flags, end=" ")
        if pkt.length % 100 == 0:
            print()
    return 0


def cmd_alert(args) -> int:
    if not os.path.exists(args.file):
        print(f"no alerts file at {args.file}")
        return 0
    with open(args.file, encoding="utf-8") as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    rows.sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]))
    for r in rows[-args.limit:]:
        print(f"{r['severity']:8s} {r['title']}")
        print(f"         {r['summary']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return {
        "baseline": cmd_baseline,
        "monitor": cmd_monitor,
        "replay": cmd_replay,
        "simulate": cmd_simulate,
        "alert": cmd_alert,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
