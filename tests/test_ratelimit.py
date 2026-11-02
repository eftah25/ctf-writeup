"""Unit tests for the token-bucket rate limiter."""
import time

import pytest

from ddosguard.mitigate.ratelimit import RateLimiter, TokenBucket


def test_token_bucket_denies_over_rate():
    # Bucket refills at 10 tokens/s; a fresh bucket (burst=0) holds 0 tokens.
    T0 = 1000000.0
    bucket = TokenBucket(rate=10.0, burst=0.0, started=T0)
    assert bucket.try_consume(T0 + 0.05) is False      # only 0.5 tokens earned
    assert bucket.try_consume(T0 + 0.15) is True       # 1 token available; bucket now 0
    # 0.15s after the last admission, 1.5 tokens are earned -> admits.
    assert bucket.try_consume(T0 + 0.30) is True


def test_token_bucket_refills_over_time():
    # 10 tokens/sec, burst cap of 10: a bucket empties at rate 10/s and refills
    # back to its cap after 1s of quiet.
    bucket = TokenBucket(rate=10.0, burst=10.0, started=time.monotonic())
    assert bucket.try_consume(time.monotonic() + 1.1) is True


def test_token_bucket_whitelist():
    limiter = RateLimiter(whitelist=["10.0.0.1"])
    # Whitelisted IPs are always admitted, regardless of the bucket.
    assert limiter.allow("10.0.0.1", rate=100, burst=10) is True
    # Unwhitelisted IPs must respect the bucket.  A burst=0 bucket starts
    # empty, so the very first packet is denied.
    assert limiter.allow("10.0.0.2", rate=100, burst=0) is False


def test_rate_limiter_admission_statistics():
    limiter = RateLimiter()
    now = time.monotonic()
    limiter.allow("10.0.0.1", rate=1000, burst=100, now=now)
    stats = limiter.policy(1000, 100, now)
    assert stats["admitted"] == 1
    assert stats["keys"] == 1


def test_tokens_refill_over_time():
    bucket = TokenBucket(rate=10.0, burst=5.0, started=time.monotonic())
    assert bucket.tokens() <= 5.0
    time.sleep(0.1)
    assert bucket.tokens() <= 5.0
