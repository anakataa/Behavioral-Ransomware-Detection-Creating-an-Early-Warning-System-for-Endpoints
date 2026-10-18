"""Process attribution — answering "who is writing?" from user space.

watchdog reports *what* changed, not *who*. Without a kernel driver
(minifilter / fanotify / ETW) we infer the culprit from per-process
write counters (``psutil.Process.io_counters().write_bytes``):

1. A background sampler records every process's cumulative write
   counter once per ``interval``. When the agent sees a first signal it
   calls ``boost()``: sampling switches to ``BOOST_INTERVAL`` for a few
   seconds, so "writes since the burst began" has a tight baseline.
2. Volume consistency: the culprit wrote at least the bytes seen
   changing in watched dirs, and not wildly more. Candidates outside
   MIN_RATIO..MAX_RATIO are dropped; the rest rank by closeness to 1.
   (A browser streaming 50 MB to its cache is a heavy writer, not a
   plausible author of 2 MB of encrypted documents.)
3. An open handle inside a watched directory outranks everything.
4. Two equally plausible candidates -> ambiguous.

No candidate, or ambiguity -> the agent alerts but doesn't kill.

Rejected alternative (measured, kept for the thesis): Pearson
correlation of per-100 ms write increments vs. file-change increments.
A ransomware writing at a steady rate yields a near-constant series, so
r is noise (observed -0.10..0.69 for the same mock across runs).
This is the documented weak point of a user-space design and is
evaluated explicitly in the thesis (Chapter V).
"""

from __future__ import annotations

import logging
import math
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

import psutil

log = logging.getLogger(__name__)

# Never treat these as suspects: killing them crashes the OS or the session.
PROTECTED_NAMES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "fontdrvhost.exe", "dwm.exe", "memcompression",
    "systemd", "init", "kthreadd", "launchd", "kernel_task",
}

# Observed bytes are a lower bound on what the culprit wrote (it also writes
# notes, temp files, may overwrite originals); the small slack below 1 covers
# event-vs-sample timing jitter. Far above means an unrelated heavy writer.
MIN_RATIO = 0.9
MAX_RATIO = 4.0
# Two candidates whose ratios are within this factor of each other are
# equally plausible: attribution is ambiguous and nothing gets killed.
AMBIGUITY_FACTOR = 1.5
BOOST_INTERVAL = 0.1     # seconds between samples while a burst is suspected
BOOST_DURATION = 5.0


@dataclass
class Suspect:
    pid: int
    name: str
    exe: str | None
    bytes_written: int
    touches_watched: bool
    ratio: float | None = None   # bytes_written / bytes observed changing in watched dirs

    def __str__(self) -> str:
        flag = " [open handle in watched dir]" if self.touches_watched else ""
        ratio = f", x{self.ratio:.2f} of observed" if self.ratio is not None else ""
        return f"{self.name} (pid {self.pid}, {self.bytes_written / 1024:.0f} KiB written{ratio}){flag}"


def ambiguous(suspects: Sequence[Suspect]) -> bool:
    """True if the two best volume-matched suspects are equally plausible."""
    if len(suspects) < 2 or suspects[0].touches_watched != suspects[1].touches_watched:
        return False
    a, b = suspects[0].ratio, suspects[1].ratio
    if a is None or b is None:
        return False
    return abs(math.log(b)) - abs(math.log(a)) < math.log(AMBIGUITY_FACTOR)


if sys.platform == "win32":
    import ctypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def can_terminate(pid: int) -> bool:
        """Can this agent open ``pid`` with terminate rights at all?

        Processes it cannot open (higher integrity, protected, other
        users) are useless suspects — they couldn't be stopped anyway —
        and psutil's fallback path for them costs a full system
        snapshot per call. Checking once up front keeps sampling cheap.
        """
        h = _kernel32.OpenProcess(_PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return False
        _kernel32.CloseHandle(h)
        return True
else:
    def can_terminate(pid: int) -> bool:
        return True  # AccessDenied from psutil is cheap on POSIX


def is_protected(pid: int, name: str | None) -> bool:
    if pid in (0, 4) or pid == os.getpid():
        return True
    if pid == 1 and os.name != "nt":
        return True
    return (name or "").lower() in PROTECTED_NAMES


class IoTracker:
    def __init__(self, watch_paths: list[Path], interval: float = 1.0, window: float = 10.0) -> None:
        self.watch_paths = [Path(p).resolve() for p in watch_paths]
        self.interval = interval
        self.window = window
        self._history: dict[int, deque[tuple[float, int]]] = {}
        self._names: dict[int, str] = {}
        self._swept = False
        self._denied: set[int] = set()
        self._boost_start = 0.0
        self._boost_until = 0.0
        self._lock = threading.Lock()
        self._sample_lock = threading.Lock()  # background thread and suspects() both sample
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- sampling ----------------------------------------------------------
    def sample(self) -> None:
        with self._sample_lock:
            self._sample()

    def _sample(self) -> None:
        now = time.monotonic()
        seen = set()
        alive = set()
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            alive.add(pid)
            if pid in self._denied:
                continue
            if pid not in self._history and not can_terminate(pid):
                self._denied.add(pid)
                continue
            try:
                io = proc.io_counters()
                # Linux write_bytes only counts storage writeback (delayed by the
                # page cache); write_chars counts write() syscalls as they happen.
                written = getattr(io, "write_chars", None) or io.write_bytes
            except psutil.AccessDenied:
                # Other users' / system processes: won't change, and the
                # exception path is expensive on Windows — remember it.
                self._denied.add(pid)
                continue
            except (psutil.Error, AttributeError, OSError):
                continue
            seen.add(pid)
            with self._lock:
                hist = self._history.get(pid)
                if hist is None:
                    hist = self._history[pid] = deque()
                    if self._swept:
                        # Born after the previous sweep: it had written 0 bytes at birth.
                        hist.append((self._birth(proc, now), 0))
                hist.append((now, written))
                while len(hist) > 1 and now - hist[0][0] > self.window:
                    hist.popleft()
                self._names[pid] = proc.info["name"] or "?"
        with self._lock:
            for pid in list(self._history):
                if pid not in seen:
                    del self._history[pid]
                    self._names.pop(pid, None)
            self._denied &= alive  # forget dead pids (pid reuse)
            self._swept = True

    @staticmethod
    def _birth(proc: psutil.Process, now: float) -> float:
        """Process creation time on the monotonic clock (clamped to ``now``)."""
        try:
            age = time.time() - proc.create_time()
        except (psutil.Error, OSError):
            return now
        return now - max(0.0, age)

    def boost(self) -> None:
        """Sample at BOOST_INTERVAL for the next BOOST_DURATION seconds."""
        now = time.monotonic()
        if now >= self._boost_until:
            self._boost_start = now
        self._boost_until = now + BOOST_DURATION

    @property
    def boosted_since(self) -> float | None:
        return self._boost_start if time.monotonic() < self._boost_until else None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except Exception:  # never let the sampler die silently
                log.exception("io sampler failed")
            boosted = time.monotonic() < self._boost_until
            self._stop.wait(BOOST_INTERVAL if boosted else self.interval)

    def start(self) -> None:
        self.sample()
        self._thread = threading.Thread(target=self._run, name="io-tracker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 2)

    # -- scoring -----------------------------------------------------------
    def _touches_watched(self, pid: int) -> bool:
        try:
            files = psutil.Process(pid).open_files()
        except (psutil.Error, OSError):
            return False
        for f in files:
            p = Path(f.path)
            if any(w == p or w in p.parents for w in self.watch_paths):
                return True
        return False

    @staticmethod
    def _delta_since(hist: Sequence[tuple[float, int]], since: float | None) -> int:
        """Bytes written after the last sample at or before ``since``."""
        base = hist[0][1]
        if since is not None:
            for ts, written in hist:
                if ts > since:
                    break
                base = written
        return hist[-1][1] - base

    def suspects(
        self,
        top: int = 5,
        since: float | None = None,
        expected_bytes: int = 0,
    ) -> list[Suspect]:
        """Rank processes by how well they explain the observed burst.

        ``since``: monotonic start of the burst.
        ``expected_bytes``: bytes seen changing in watched dirs. When
        given, only processes whose writes since the burst started are
        MIN_RATIO..MAX_RATIO of it remain, closest first. Without it,
        processes are simply ranked by write volume (diagnostics, tests).
        """
        self.sample()
        with self._lock:
            history = {pid: list(h) for pid, h in self._history.items() if len(h) >= 2}
            names = dict(self._names)
        deltas = [(pid, self._delta_since(h, since)) for pid, h in history.items()]
        deltas = [(pid, d) for pid, d in deltas if d > 0 and not is_protected(pid, names.get(pid))]

        deltas.sort(key=lambda x: x[1], reverse=True)
        if expected_bytes > 0:
            for pid, d in deltas[:5]:
                log.debug("writer %s[%d]: %d B (x%.2f of observed %d B)",
                          names.get(pid), pid, d, d / expected_bytes, expected_bytes)
            lo, hi = MIN_RATIO * expected_bytes, MAX_RATIO * expected_bytes
            deltas = [(pid, d) for pid, d in deltas if lo <= d <= hi]
            deltas.sort(key=lambda x: abs(math.log(x[1] / expected_bytes)))

        result = []
        for pid, delta in deltas[:top]:
            try:
                exe = psutil.Process(pid).exe()
            except (psutil.Error, OSError):
                exe = None
            ratio = delta / expected_bytes if expected_bytes > 0 else None
            result.append(Suspect(pid, names.get(pid, "?"), exe, delta, self._touches_watched(pid), ratio))
        # stable sort: an open handle in a watched dir outranks everything else
        result.sort(key=lambda s: s.touches_watched, reverse=True)
        return result
