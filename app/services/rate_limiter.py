from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock


class RateLimiter:
    """Simple in-memory sliding window rate limiter keyed by source IP."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._events: dict[str, deque[datetime]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, source_ip: str) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - self.window_seconds
        with self._lock:
            window = self._events[source_ip]
            while window and window[0].timestamp() < cutoff:
                window.popleft()
            if len(window) >= self.max_requests:
                return False
            window.append(now)
            return True
