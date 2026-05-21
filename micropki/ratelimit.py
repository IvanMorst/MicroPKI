import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple


class TokenBucket:
    """Simple token bucket rate limiter per client IP."""

    def __init__(self, rate: float, burst: int):
        """
        rate: tokens per second
        burst: maximum tokens (bucket size)
        """
        self.rate = rate
        self.burst = burst
        self.buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_update)
        self.lock = Lock()

    def allow(self, ip: str) -> Tuple[bool, int]:
        """
        Check if request from IP is allowed.
        Returns (allowed, retry_after_seconds).
        """
        if self.rate <= 0:
            return True, 0

        now = time.time()
        with self.lock:
            tokens, last = self.buckets.get(ip, (self.burst, now))

            # Add new tokens based on time elapsed
            elapsed = now - last
            tokens = min(self.burst, tokens + elapsed * self.rate)

            if tokens >= 1:
                tokens -= 1
                self.buckets[ip] = (tokens, now)
                return True, 0
            else:
                # Calculate retry after
                retry_after = int((1 - tokens) / self.rate) + 1
                return False, retry_after