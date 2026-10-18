"""Shannon entropy detector.

H(X) = -sum_{i=0}^{255} p_i * log2(p_i),  0 <= H <= 8 bits/byte

Plain text sits around 4-5 bits/byte; compressed or encrypted data
approaches 8. One high-entropy file proves little (a JPEG or ZIP is
already compressed), so the signal fires only after ``min_files``
distinct high-entropy writes inside ``window`` seconds.
"""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def sample_file(path: Path, sample_bytes: int = 4096) -> bytes | None:
    """Read up to ``sample_bytes`` from the middle of the file.

    The middle skips format headers (magic numbers, ZIP local headers)
    that would skew a small sample. Returns ``None`` if the file is
    gone or locked — normal while a process is still writing it.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, (size - sample_bytes) // 2))
            return fh.read(sample_bytes)
    except OSError:
        return None


class EntropyDetector:
    # Below this many bytes the estimate is too noisy to trust:
    # with n samples, H can never exceed log2(n).
    MIN_SAMPLE = 512

    def __init__(
        self,
        threshold: float = 7.5,
        sample_bytes: int = 4096,
        min_files: int = 3,
        window: float = 5.0,
    ) -> None:
        self.threshold = threshold
        self.sample_bytes = sample_bytes
        self.min_files = min_files
        self.window = window
        self._hits: deque[tuple[float, Path]] = deque()

    def measure(self, path: Path) -> float | None:
        data = sample_file(path, self.sample_bytes)
        if data is None or len(data) < self.MIN_SAMPLE:
            return None
        return shannon_entropy(data)

    def observe(self, path: Path, ts: float | None = None) -> float | None:
        """Measure ``path``; record it as a hit if above threshold."""
        h = self.measure(path)
        if h is not None and h > self.threshold:
            now = time.monotonic() if ts is None else ts
            self._hits.append((now, path))
            self._evict(now)
        return h

    def _evict(self, now: float) -> None:
        cutoff = now - self.window
        while self._hits and self._hits[0][0] <= cutoff:
            self._hits.popleft()

    def hit_count(self, now: float | None = None) -> int:
        self._evict(time.monotonic() if now is None else now)
        return len({p for _, p in self._hits})

    def triggered(self, now: float | None = None) -> bool:
        return self.hit_count(now) >= self.min_files

    def reset(self) -> None:
        self._hits.clear()
