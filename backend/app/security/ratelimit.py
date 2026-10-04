"""Sliding-window limiter: anti-probing (mule herders) and per-institution influence caps."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_s: float, clock=time.time):
        self.max_events, self.window_s, self._clock = max_events, window_s, clock
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            q = self._events[key]
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= self.max_events:
                return False
            q.append(now)
            return True
