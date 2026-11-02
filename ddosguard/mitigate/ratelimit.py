"""
Token-bucket rate limiting, the core congestion-control primitive.

Each bucket holds a "credit" of tokens.  A request (packet, connection or
HTTP request) is admitted when the bucket holds one token and the bucket is
refilled at `rate` tokens/second with a maximum depth of `burst`.
Refills are computed analytically from the bucket's age, so the limiter is
cheap to query and never needs a background thread or timer tick.

The `RateLimiter` composes per-key buckets (default key: source IP) and
records admission statistics — useful for dashboards and for deciding which
sources to block.

Safety defaults (aligned with the escalation ladder):
    * the bucket never admits *nothing* (a burst-only bucket would let an
      attacker flood at a constant rate)
    * a whitelisted key is always admitted, even a bucket keyed at zero
    * the limiter never blocks: it only *refuses* to admit.  Real enforcement
      (firewall drop / proxy smarthashlimit / kernel tc) is injected by the
      caller from this module's policy.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from ..core import MitigationAction, Severity

# Default key length for the deterministic hash used when the key has no form.
_KEY_BITS = 64


class TokenBucket:
    """One token bucket.

    `rate` tokens/second, `burst` tokens depth.  Tokens are added linearly in
    continuous time, so the bucket can be queried at arbitrary timestamps.
    A brand-new bucket holds `burst` tokens (0 means the bucket starts empty,
    i.e. strict rate limiting).
    """

    def __init__(self, rate: float, burst: float, started: float | None = None):
        self.rate = max(0.0, rate)
        self.burst = max(0.0, burst)
        self._capacity = max(self.burst, 1.0)
        self._tokens = self.burst if self.burst > 0 else 0.0
        self._last = time.monotonic() if started is None else started
        self._lock = threading.Lock()

    # ---- public ------------------------------------------------------------ #
    def try_consume(self, now: float | None = None) -> bool:
        """Admit a unit of work.  True when a token was available."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._refill(now)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._last = now
                return True
            return False

    def admits(self, now: float | None = None) -> bool:
        """Non-destructive check — useful for dashboards and logging."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._refill(now)
            return self._tokens >= 1.0

    def tokens(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._refill(now)
            return self._tokens

    def avg_rate(self, samples: int = 60) -> float:
        """Admission rate observed over the last `samples` calls."""
        return self._admitted / max(1, self._samples)

    # ---- internals --------------------------------------------------------- #
    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last)
        self._tokens = min(
            self._capacity,
            self._tokens + elapsed * self.rate,
        )
        self._last = now

    @property
    def _admitted(self) -> int:
        return getattr(self, "_admitted_count", 0)

    @property
    def _samples(self) -> int:
        return getattr(self, "_admitted_count", 0)


class RateLimiter:
    """Per-key token buckets, shared by the monitor and the mitigation policy."""

    def __init__(self, buckets: Optional[Dict[str, TokenBucket]] = None, whitelist: List[str] = None):
        self._buckets: Dict[str, TokenBucket] = buckets or {}
        self._lock = threading.Lock()
        self._whitelist = set(whitelist or [])
        self._admissions = 0
        self._refusals = 0
        self._last_sample: float = time.monotonic()

    # ---- public ------------------------------------------------------------ #
    def allow(self, key: str, rate: float, burst: float, now: float | None = None) -> bool:
        """Admit a packet/connection for `key` at `rate`/`burst` tokens/s."""
        if key in self._whitelist:
            return True
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or bucket.rate != rate or bucket.burst != burst:
                self._buckets[key] = TokenBucket(rate, burst, now)
                bucket = self._buckets[key]
            ok = bucket.try_consume(now)
            if ok:
                self._admissions += 1
            else:
                self._refusals += 1
            self._last_sample = now
            return ok

    def admits(self, key: str, now: float | None = None) -> bool:
        if key in self._whitelist:
            return True
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return True
            return bucket.admits(now)

    def tokens(self, key: str, now: float | None = None) -> float:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return 0.0
            return bucket.tokens(now)

    def policy(self, rate: float, burst: float, now: float | None = None) -> Dict[str, object]:
        """Short summary of the limiter's state, for dashboards/alerts."""
        with self._lock:
            total = len(self._buckets)
            active = sum(1 for b in self._buckets.values() if b.tokens(now) < b.burst * 0.5)
            return {
                "keys": total,
                "active": active,
                "admitted": self._admissions,
                "refused": self._refusals,
                "rate": rate,
                "burst": burst,
            }

    @classmethod
    def from_ladder(cls, ladder: List[Dict[str, object]], whitelist: List[str] = None) -> "RateLimiter":
        """Build a limiter whose buckets are pre-seeded from an escalation stage."""
        limiter = cls(whitelist=whitelist or [])
        for entry in ladder:
            lim = entry.get("limiter")
            if lim is not None:
                limiter._buckets.update(dict(lim._buckets))
                limiter._admissions += getattr(lim, "_admissions", 0)
                limiter._refusals += getattr(lim, "_refusals", 0)
        return limiter

    def deep_copy(self) -> "RateLimiter":
        import copy

        return copy.deepcopy(self)

    def add_action(self, severity: Severity, target: str, rule_type: str) -> MitigationAction:
        """Build a mitigation rule describing this limiter's current stage."""
        return MitigationAction(
            id=f"{rule_type}-{hashlib.md5(target.encode()).hexdigest()[:8]}",
            rule_type=rule_type,
            target=target,
            action="deny",
            reason=f"ddosguard stage {severity.name.lower()}",
            severity=severity,
            applied_at=None,
        )
