"""I/O velocity detector — sliding-window event rate.

rate(t) = |{ e : t - W < e.ts <= t }| / W

A deque holds event timestamps; old ones are evicted from the left on
every update, so each event costs amortized O(1).
"""

from __future__ import annotations

import time
from collections import deque


class VelocityDetector:
    def __init__(self, threshold: float = 50.0, window: float = 1.0) -> None:
        if threshold <= 0 or window <= 0:
            raise ValueError("threshold and window must be > 0")
        self.threshold = threshold
        self.window = window
        self._stamps: deque[float] = deque()

    def _evict(self, now: float) -> None:
        cutoff = now - self.window
        while self._stamps and self._stamps[0] <= cutoff:
            self._stamps.popleft()

    def record(self, ts: float | None = None) -> float:
        """Register one file event and return the current rate (events/s)."""
        now = time.monotonic() if ts is None else ts
        self._stamps.append(now)
        self._evict(now)
        return self.rate(now)

    def rate(self, now: float | None = None) -> float:
        self._evict(time.monotonic() if now is None else now)
        return len(self._stamps) / self.window

    def triggered(self, now: float | None = None) -> bool:
        return self.rate(now) > self.threshold

    def reset(self) -> None:
        self._stamps.clear()
