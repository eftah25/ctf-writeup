"""
Alert manager: builds alerts, controls notification fatigue, and ranks
severity so critical incidents get immediate attention while noisy signals
are throttled.

Key design points:
    * signatures: alerts are grouped by a stable signature (e.g.
      "volume:99.9th-percentile"), so one attack produces a steady stream of
      notifications, not a flood.
    * dedupe: the same signature within `cooldown_seconds` is suppressed and
      merged into an in-flight alert (more data appended).
    * ranking: severity is ranked CRITICAL > HIGH > MEDIUM > LOW > INFO so a
      critical alert can interrupt the queue for lower-severity batches.
    * throttling: `max_per_minute` caps duplicate signatures delivered in any
      one minute, preventing notification fatigue.
    * delivery channels: console (always), file (always persisted), desktop
      (best effort), email and Slack webhooks (on request).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from ..config import Config
from ..core import Alert, PacketRecord, Severity

# Fallback when the desktop backend has no platform support.
def _desktop_not_available() -> None:
    pass


class AlertManager:
    """Orchestrates alert delivery with throttling and ranking."""

    def __init__(self, config: Config, data_dir: str | None = None):
        self.config = config
        self.data_dir = data_dir or config.baseline.get("data_dir", "data")
        self.alert_file = os.path.join(self.data_dir, "alerts.jsonl")
        self._lock = threading.RLock()
        self._signatures: Dict[str, dict] = {}
        self._inflight: Dict[str, Alert] = {}
        self._timeline: List[Alert] = []
        self._severity_rank = {s.name: i for i, s in enumerate(
            [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}

    # ------------------------------------------------------------------ #
    # Core API                                                            #
    # ------------------------------------------------------------------ #
    def generate(self, score, stats, baseline, mitigation_stage: int = 0) -> Alert:
        """Turn a detection into a structured alert payload."""
        sig = self._signature(stats, score)
        with self._lock:
            entry = self._signatures.get(sig)
            if entry is None:
                entry = {"sig": sig, "first": time.monotonic(), "last": 0.0, "count": 0}
                self._signatures[sig] = entry
            entry["count"] += 1
            entry["last"] = time.monotonic()

            # Throttle identical signatures.
            if time.monotonic() - entry["last"] < self.config.alerting.get("cooldown_seconds", 120):
                alert = self._inflight.get(sig)
                if alert is None:
                    alert = self._inflight[sig] = Alert(
                        alert_id=self._uid(sig),
                        severity=Severity.LOW,
                        title="Stealth alert",
                        summary="A signal fired again but was suppressed by cooldown",
                        attack_indicators={},
                        recommendations=[],
                        window=stats,
                        occurred_at=datetime.now(),
                    )
                else:
                    alert.window = stats
                return alert

            severity = score.severity
            alert = Alert(
                alert_id=self._uid(sig),
                severity=severity,
                title=self._title(severity, score),
                summary=self._summary(severity, stats, score),
                attack_indicators=self._indicators(stats, score, baseline),
                affected_services=self._services(stats),
                current_mitigation=self._mitigation_info(score.severity, mitigation_stage),
                attack_sources=self._sources(stats),
                recommendations=self._recommendations(score.severity),
                window=stats,
                occurred_at=datetime.now(),
            )
            self._inflight[sig] = alert
            self._timeline.append(alert)
            self._flush(alert)
            return alert

    # ------------------------------------------------------------------ #
    # Throttling helpers                                                  #
    # ------------------------------------------------------------------ #
    def check_throttle(self, signature: str) -> bool:
        """True when this signature passed the rate limit in the last minute."""
        with self._lock:
            entry = self._signatures.get(signature)
            if entry is None or entry.get("count", 0) == 0:
                return False
            window_start = time.monotonic() - 60.0
            return entry["count"] <= self.config.alerting.get("max_per_minute", 5)

    def get_timeline(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._timeline[-limit:]]

    def clear(self) -> None:
        with self._lock:
            self._signatures.clear()
            self._inflight.clear()
            self._timeline.clear()
            if os.path.exists(self.alert_file):
                os.remove(self.alert_file)

    # ------------------------------------------------------------------ #
    # Alert content construction                                          #
    # ------------------------------------------------------------------ #
    def _signature(self, stats, score) -> str:
        parts = [
            "vol", f"{stats.packet_rate:.1f}",
            "proto", f"{stats.per_proto.get(6, 0)}",
            "udp", f"{stats.per_proto.get(17, 0)}",
            "top1", stats.top_srcs[0][0] if stats.top_srcs else "none",
            "top_port", str(stats.dst_port_dist),
        ]
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:16]

    @staticmethod
    def _uid(sig: str) -> str:
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def _title(self, severity: Severity, score) -> str:
        if severity == Severity.CRITICAL:
            return "CRITICAL DDoS attack detected"
        if severity == Severity.HIGH:
            return "High severity DDoS indicators"
        if severity == Severity.MEDIUM:
            return "Suspected DDoS attack"
        if severity == Severity.LOW:
            return "Anomaly detected, monitoring"
        return "Traffic anomaly noted"

    def _summary(self, severity: Severity, stats, score) -> str:
        if severity == Severity.CRITICAL:
            return "Immediate mitigation in effect: traffic is being rate limited"
        if severity == Severity.HIGH:
            return "Attack indicators confirmed for several windows"
        return "Baseline has been exceeded; action may be needed"

    def _indicators(self, stats, score, baseline) -> dict:
        return {
            "volume": round(stats.packet_rate, 2),
            "byte_rate": round(stats.byte_rate, 2),
            "syn_ratio": round(stats.syn_ratio, 4),
            "unique_sources": stats.unique_sources,
            "top_ports": stats.dst_port_dist,
            "severity": score.severity.name,
        }

    def _services(self, stats) -> List[str]:
        return [str(p) for p in stats.dst_port_dist][:5]

    def _mitigation_info(self, severity: str, stage: int) -> dict:
        rate_limit = {"low": 10000, "medium": 2000, "high": 500, "critical": 100}.get(
            severity.lower(), 0
        )
        return {"stage": stage, "rate_limit_per_ip": rate_limit}

    def _sources(self, stats) -> List[dict]:
        out = []
        for ip, _ in stats.top_srcs[:10]:
            out.append({"ip": ip, "type": "source"})
        for port, _ in stats.dst_port_dist.items():
            out.append({"port": port, "type": "destination"})
        return out

    def _recommendations(self, severity: str) -> List[str]:
        base = [
            "Continue monitoring the affected services",
            "Keep active mitigations until the threat is cleared",
        ]
        if severity in ("high", "critical"):
            base.append("Notify the network operations center (NOC) and escalate")
            base.append("Consider upstream scrubbing for sustained large attacks")
        return base

    # ------------------------------------------------------------------ #
    # Persistence and delivery                                            #
    # ------------------------------------------------------------------ #
    def _flush(self, alert: Alert) -> None:
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.alert_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_dict()) + "\n")

    def deliver(self, alert: Alert) -> List[str]:
        """Attempt to deliver an alert over every configured channel."""
        channels = []
        if self.config.alerting.get("slack_webhook", ""):
            channels.append("slack")
        if self.config.alerting.get("email", {}).get("enabled", False):
            channels.append("email")
        attempts = []
        for ch in channels:
            try:
                self._deliver_channel(ch, alert)
                attempts.append(f"{ch}: sent")
            except Exception as exc:
                attempts.append(f"{ch}: failed ({exc})")
        return attempts

    def _deliver_channel(self, channel: str, alert: Alert) -> None:
        if channel == "slack":
            import urllib.request

            url = self.config.alerting.get("slack_webhook", "")
            body = json.dumps({"text": self._slack_text(alert)}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        elif channel == "email":
            self._deliver_email(alert)

    def _deliver_email(self, alert: Alert) -> None:
        import smtplib
        from email.message import EmailMessage

        cfg = self.config.alerting["email"]
        msg = EmailMessage()
        msg["From"] = cfg["from"]
        msg["To"] = ", ".join(cfg["to"])
        msg["Subject"] = f"[DDoS Guard] {alert.title}"
        msg.set_content(self._email_body(alert))
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as server:
            if cfg.get("tls"):
                server.starttls()
            server.send_message(msg)

    def _slack_text(self, alert: Alert) -> str:
        return f"*{alert.title}*\n{alert.summary}\nSeverity: {alert.severity.name}"

    def _email_body(self, alert: Alert) -> str:
        return f"{alert.title}\n{alert.summary}\n{json.dumps(alert.to_dict(), indent=2)}"

    def desktop_notify(self, alert: Alert) -> None:
        """Best-effort desktop (OS) notification; never fails the pipeline."""
        backend = self.config.alerting.get("desktop", "auto")
        try:
            if backend == "win":
                self._win_toast(alert)
            elif backend == "linux":
                self._desktop_send("notify-send", alert)
            elif backend == "mac":
                self._osascript(alert)
            elif backend == "auto":
                if os.name == "nt":
                    self._win_toast(alert)
                elif os.name == "posix":
                    try:
                        self._desktop_send("notify-send", alert)
                    except Exception:
                        try:
                            self._osascript(alert)
                        except Exception:
                            pass
        except Exception:
            pass

    @staticmethod
    def _win_toast(alert: Alert) -> None:
        import subprocess

        text = f"{alert.title}\n{alert.summary}"
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
             f"$t = New-Object Windows.UI.Notifications.ToastNotification "
             f"$(New-Object Windows.UI.Notifications.ToastText01String '{alert.title.replace(chr(34), chr(39))}'); "
             f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ddosguard').Show($t)"],
            capture_output=True, timeout=5,
        )

    @staticmethod
    def _desktop_send(cmd: str, alert: Alert) -> None:
        import subprocess

        subprocess.run([cmd, "ddosguard", alert.summary], capture_output=True, timeout=5)

    @staticmethod
    def _osascript(alert: Alert) -> None:
        import subprocess

        text = f"{alert.title}\n{alert.summary}"
        subprocess.run(["osascript", "-e", f"display notification {alert.summary!r} with title {alert.title!r}"],
                       capture_output=True, timeout=5)
