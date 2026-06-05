import pytest
import time
from micropki.ratelimit import TokenBucket


def test_token_bucket_init():
    """Test token bucket initialization."""
    bucket = TokenBucket(rate=10, burst=5)
    assert bucket.rate == 10
    assert bucket.burst == 5


def test_token_bucket_allow():
    """Test token bucket allows requests within limit."""
    bucket = TokenBucket(rate=10, burst=5)

    # First request should be allowed
    allowed, retry = bucket.allow('127.0.0.1')
    assert allowed is True
    assert retry == 0


def test_token_bucket_rate_limit_disabled():
    """Test token bucket with rate limit disabled."""
    bucket = TokenBucket(rate=0, burst=10)

    # All requests should be allowed when rate=0
    for _ in range(100):
        allowed, retry = bucket.allow('127.0.0.1')
        assert allowed is True
        assert retry == 0


def test_token_bucket_rate_limit_exceeded():
    """Test token bucket rejects requests after limit exceeded."""
    bucket = TokenBucket(rate=1, burst=2)

    # First 2 requests should be allowed (burst)
    for _ in range(2):
        allowed, retry = bucket.allow('127.0.0.1')
        assert allowed is True

    # 3rd request should be rejected
    allowed, retry = bucket.allow('127.0.0.1')
    assert allowed is False
    assert retry > 0


def test_token_bucket_multiple_ips():
    """Test token bucket handles multiple IPs independently."""
    bucket = TokenBucket(rate=10, burst=5)  # Increase rate to avoid depletion

    # Different IPs should have separate buckets
    for i in range(3):
        allowed1, _ = bucket.allow('192.168.1.1')
        allowed2, _ = bucket.allow('192.168.1.2')
        allowed3, _ = bucket.allow('192.168.1.3')
        assert allowed1 is True
        assert allowed2 is True
        assert allowed3 is True


def test_token_bucket_refill():
    """Test token bucket refills over time."""
    bucket = TokenBucket(rate=10, burst=2)

    # Exhaust bucket
    for _ in range(2):
        bucket.allow('127.0.0.1')

    # Should be rejected
    allowed, _ = bucket.allow('127.0.0.1')
    assert allowed is False

    # Wait for refill
    time.sleep(0.2)

    # Should be allowed again
    allowed, _ = bucket.allow('127.0.0.1')
    assert allowed is True