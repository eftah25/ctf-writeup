"""
ddosguard - DDoS detection and automated mitigation toolkit.

Public API (stable):
- ddosguard.metrics.TrafficWindow / Aggregator
- ddosguard.baseline.BaselineStore
- ddosguard.detect.signals / CompositeScorer
- ddosguard.mitigate.ratelimit / firewall
- ddosguard.alert.AlertManager
- ddosguard.dashboard.app
"""
from __future__ import annotations

__version__ = "1.0.0"
