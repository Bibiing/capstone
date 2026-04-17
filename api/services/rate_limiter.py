"""Simple in-memory rate limiter for auth-sensitive endpoints."""

from collections import defaultdict, deque
from threading import Lock
from time import time


class InMemoryRateLimiter:
    """Token bucket-like limiter using timestamp windows."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        """Return True if current request is allowed, else False."""
        now = time()
        cutoff = now - window_seconds

        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()

            if len(events) >= limit:
                return False

            events.append(now)
            return True

    def retry_after_seconds(self, key: str, window_seconds: int) -> int:
        """Return remaining seconds until next slot opens for a key."""
        now = time()
        cutoff = now - window_seconds

        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()

            if not events:
                return 0

            # Oldest event defines when the window frees one slot.
            remaining = int(window_seconds - (now - events[0]))
            return max(remaining, 0)

    def clear(self, key: str | None = None) -> None:
        """Clear one key or all tracked events (useful for tests)."""
        with self._lock:
            if key is None:
                self._events.clear()
                return
            self._events.pop(key, None)
