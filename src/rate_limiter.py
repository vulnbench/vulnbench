"""Simple sliding-window rate limiter."""

import time
from collections import deque


class RateLimiter:
    """Sliding window rate limiter.

    Args:
        max_requests: Maximum requests allowed in the window.
        window_seconds: Window duration in seconds.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    def acquire(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()

        # Purge expired timestamps
        while self._timestamps and self._timestamps[0] < now - self.window_seconds:
            self._timestamps.popleft()

        if len(self._timestamps) >= self.max_requests:
            sleep_time = self._timestamps[0] + self.window_seconds - now
            if sleep_time > 0:
                time.sleep(sleep_time)

        self._timestamps.append(time.monotonic())


# Pre-configured limiters
gh_limiter = RateLimiter(max_requests=4500, window_seconds=3600)  # GitHub: 5000/hr with margin
nvd_limiter = RateLimiter(max_requests=4, window_seconds=30)       # NVD public: 5/30s with margin
registry_limiter = RateLimiter(max_requests=80, window_seconds=60)  # Package registries
benchmark_limiter = RateLimiter(max_requests=3000, window_seconds=3600)  # Conservative bulk diff fetching
