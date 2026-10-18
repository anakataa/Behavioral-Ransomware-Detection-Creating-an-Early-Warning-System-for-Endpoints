"""Agent — wires listener, detectors, decision engine, mitigation, audit.

Threads:
  watchdog observer  -> pushes FileEvents onto a queue (never blocks)
  analyzer           -> consumes the queue, runs detectors, decides
  io-tracker         -> samples per-process write counters for attribution
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

import psutil

from .attribution import IoTracker, Suspect, ambiguous
from .audit import AuditLog
from .canary import CanaryManager
from .config import Config
from .decision import DecisionEngine, Signal, SignalKind, Verdict, Whitelist
from .entropy import EntropyDetector
from .event_listener import EventKind, EventListener, FileEvent
from .mitigation import MitigationResult, Mitigator
from .velocity import VelocityDetector

log = logging.getLogger(__name__)

CANARY_VERIFY_INTERVAL = 5.0   # seconds between integrity sweeps of the bait files
ENTROPY_RESAMPLE_GAP = 0.25    # don't re-read the same file more often than this
CANARY_REARM_QUIET = 1.0       # ignore vault events right after we rewrite it ourselves
ATTRIBUTION_SETTLE = 0.3       # boosted sampling before the first attribution window closes
CONFIRM_WINDOW = 0.6           # second, independent window the culprit must match again
METRICS_INTERVAL = 0.25        # seconds between telemetry rows for the dashboard


class Agent:
    def __init__(
        self,
        cfg: Config,
        audit: AuditLog | None = None,
        kill_filter: Callable[[int], bool] | None = None,
    ) -> None:
        """``kill_filter``: optional extra gate on termination. When given, a
        correctly attributed culprit is only killed if ``kill_filter(pid)`` is
        true; otherwise the verdict stays alert-only. ``sentinel demo`` uses it
        to restrict kills to the simulator the dashboard launched."""
        self.cfg = cfg
        self.kill_filter = kill_filter
        d = cfg.detection
        self.audit = audit or AuditLog(cfg.audit_db)
        db = Path(self.audit.db_path).resolve()
        self.listener = EventListener(
            cfg.watch_paths,
            ignore_paths=[db, db.with_name(db.name + "-journal"), db.with_name(db.name + "-wal")],
        )
        self.velocity = VelocityDetector(d.velocity_threshold, d.velocity_window)
        self.entropy = EntropyDetector(d.entropy_threshold, d.entropy_sample_bytes,
                                       d.entropy_min_files, d.entropy_window)
        self.canary = CanaryManager(cfg.watch_paths, cfg.canary.count, cfg.canary.vault_dirname)
        self.engine = DecisionEngine(d.confirmation_signals, d.correlation_window)
        self.whitelist = Whitelist(cfg.mitigation.whitelist)
        self.mitigator = Mitigator(cfg.mitigation.enabled, cfg.mitigation.kill_grace_period)
        self.io = IoTracker(cfg.watch_paths)

        self.on_verdict: list[Callable[[Verdict, Suspect | None, MitigationResult | None], None]] = []
        self._last_sampled: dict[Path, float] = {}
        self._observed: deque[tuple[float, Path, int]] = deque()  # (ts, path, size) of changed files
        self._canary_quiet_until = 0.0
        self._handled_until = 0.0  # events stamped before the last response belong to that burst
        self._tick_events = 0              # telemetry accumulators, reset every METRICS_INTERVAL
        self._tick_entropy: float | None = None
        self._self_proc = psutil.Process()
        self._cpus = psutil.cpu_count() or 1
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self.cfg.canary.enabled and self.cfg.canary.count:
            self.canary.deploy()
        self.io.start()
        self.listener.start()
        self._thread = threading.Thread(target=self._loop, name="analyzer", daemon=True)
        self._thread.start()
        self.audit.write("INFO", "system", "agent started", details={
            "watch_paths": [str(p) for p in self.cfg.watch_paths],
            "canaries": len(self.canary.files),
            "mitigation": self.cfg.mitigation.enabled,
        })

    def stop(self) -> None:
        self._stop.set()
        self.listener.stop()
        self.io.stop()
        if self._thread:
            self._thread.join(timeout=5)
        self.audit.write("INFO", "system", "agent stopped")

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:
            log.info("interrupted")
        finally:
            self.stop()

    # -- analysis loop -------------------------------------------------------
    def _loop(self) -> None:
        next_verify = time.monotonic() + CANARY_VERIFY_INTERVAL
        next_metrics = time.monotonic()
        self._self_proc.cpu_percent(None)  # prime: first call always returns 0
        while not self._stop.is_set():
            event = self.listener.get(timeout=0.1)
            if event is not None:
                try:
                    self.handle(event)
                except Exception:
                    log.exception("failed to handle %s", event)
            now = time.monotonic()
            if self.canary.files and now >= next_verify:
                next_verify = now + CANARY_VERIFY_INTERVAL
                for path in self.canary.verify():
                    self._fire(Signal(SignalKind.CANARY, 1.0, now, path, {"source": "integrity-sweep"}))
            if now >= next_metrics:
                next_metrics = now + METRICS_INTERVAL
                try:
                    self._write_metrics(now)
                except Exception:
                    log.exception("failed to write metrics")

    def _write_metrics(self, now: float) -> None:
        tampered = set(self.canary.verify()) if self.canary.files else set()
        self.audit.write_metrics(
            velocity=self.velocity.rate(now),
            entropy=self._tick_entropy,
            events=self._tick_events,
            cpu=self._self_proc.cpu_percent(None) / self._cpus,
            canary_state="".join("0" if f in tampered else "1" for f in self.canary.files),
            active_signals=[k.value for k in self.engine.active(now)],
        )
        self._tick_events = 0
        self._tick_entropy = None

    def handle(self, event: FileEvent) -> None:
        ts = event.timestamp
        self._tick_events += 1
        if ts < self._handled_until:
            return  # backlog of a burst we already responded to
        touched = [p for p in (event.path, event.dest_path) if p is not None]
        is_canary = any(self.canary.is_canary(p) for p in touched)
        if is_canary and ts < self._canary_quiet_until:
            return  # our own re-arm writes

        self._record_change(event)
        rate = self.velocity.record(ts)
        if rate > self.velocity.threshold:
            self._fire(Signal(SignalKind.VELOCITY, rate, ts, event.path))

        if is_canary:
            self._fire(Signal(SignalKind.CANARY, 1.0, ts, event.path, {"event": event.kind.value}))
            return  # never entropy-sample our own bait

        if event.kind is EventKind.DELETED:
            return
        target = event.effective_path
        last = self._last_sampled.get(target)
        if last is not None and ts - last < ENTROPY_RESAMPLE_GAP:
            return
        self._last_sampled[target] = ts
        if len(self._last_sampled) > 10_000:
            self._last_sampled.clear()
        h = self.entropy.observe(target, ts)
        if h is not None:
            self._tick_entropy = h if self._tick_entropy is None else max(self._tick_entropy, h)
        if h is not None and self.entropy.triggered(ts):
            self._fire(Signal(SignalKind.ENTROPY, h, ts, target,
                              {"high_entropy_files": self.entropy.hit_count(ts)}))

    def _record_change(self, event: FileEvent) -> None:
        """Every changed file counts toward the bytes attribution must explain."""
        if event.kind is EventKind.DELETED:
            return
        try:
            size = event.effective_path.stat().st_size
        except OSError:
            return
        self._observed.append((event.timestamp, event.effective_path, size))

    def _fire(self, signal: Signal) -> None:
        if signal.kind not in self.engine.active(signal.ts):
            self.io.boost()  # start fine-grained write sampling for attribution
            level = "ALERT" if signal.kind is SignalKind.CANARY else "WARNING"
            log.warning("signal %s=%.2f at %s", signal.kind.value, signal.value, signal.path)
            self.audit.write(level, "signal", f"{signal.kind.value} signal fired",
                             path=signal.path, details={"value": signal.value, **signal.details})
        verdict = self.engine.submit(signal)
        if verdict is not None:
            self.respond(verdict)

    # -- response ------------------------------------------------------------
    def respond(self, verdict: Verdict) -> None:
        log.critical("VERDICT: ransomware behavior detected (%s)", verdict.reason)
        # Window 1: from burst start. Writes only — a freshly started culprit's
        # reads are inflated by its own startup (interpreter, DLLs, config).
        boosted = self.io.boosted_since
        if boosted is None:
            self.io.boost()
            boosted = time.monotonic()
        self._settle(boosted + ATTRIBUTION_SETTLE)
        burst_start, observed1 = self._observed_burst()
        t1 = time.monotonic()
        first = self.io.suspects(since=burst_start, expected_bytes=observed1, check_reads=False)
        # Window 2: steady state. Writes and reads must both match again.
        self._settle(t1 + CONFIRM_WINDOW)
        _, observed = self._observed_burst(after=t1)
        suspects = self.io.suspects(since=t1, expected_bytes=observed) if first else []
        target: Suspect | None = suspects[0] if suspects else None
        outcome = None
        if not first:
            outcome = f"no process accounts for the observed writes ({observed1} B)"
        elif target is None:
            outcome = f"no process consistently accounts for the writes ({observed} B in confirm window)"
        elif target.pid not in {s.pid for s in first}:
            outcome = f"best match {target.name} was not a candidate in the first window"
        elif ambiguous(suspects):
            outcome = f"ambiguous attribution between {suspects[0].name} and {suspects[1].name}"
        elif target.name in self.whitelist:
            # The burst is explained by a trusted tool; the runner-up is not the culprit.
            outcome = f"best match {target.name} is whitelisted"
        elif self.kill_filter is not None and not self.kill_filter(target.pid):
            outcome = f"{target.name} (pid {target.pid}) is outside the kill scope"
        if outcome:
            log.error("%s; alert only", outcome)

        self.audit.write("ALERT", "verdict", f"ransomware behavior: {verdict.reason}",
                         pid=target.pid if target else None,
                         process=target.name if target else None,
                         details={"signals": verdict.kinds,
                                  "observed_bytes": observed,
                                  "observed_bytes_window1": observed1,
                                  "window1_candidates": [str(s) for s in first],
                                  "suspects": [str(s) for s in suspects],
                                  "no_action_reason": outcome})
        result = None
        if outcome:
            target = None
        else:
            result = self.mitigator.neutralize(target.pid)
            self.audit.write("ACTION", "mitigation", f"{result.action}: {target.name}",
                             pid=target.pid, process=target.name,
                             details={"exe": target.exe, "children": result.children,
                                      "bytes_written": target.bytes_written,
                                      "error": result.error})

        self._handled_until = time.monotonic()
        self.velocity.reset()
        self.entropy.reset()
        self._observed.clear()
        if self.canary.files:
            self._canary_quiet_until = time.monotonic() + CANARY_REARM_QUIET
            self.canary.deploy()  # re-arm the traps

        for cb in self.on_verdict:
            cb(verdict, target, result)

    def _settle(self, deadline: float) -> None:
        """Keep collecting file changes until ``deadline`` (boosted I/O sampling runs meanwhile).

        Events that arrive meanwhile are only recorded as changes (no
        detection): the burst they belong to is the one being responded to.
        """
        while (now := time.monotonic()) < deadline:
            event = self.listener.get(timeout=min(0.05, deadline - now))
            if event is not None and event.timestamp >= self._handled_until:
                self._record_change(event)

    def _observed_burst(self, after: float | None = None) -> tuple[float | None, int]:
        """Start and total size of distinct files changed in the attribution window
        (or only after monotonic time ``after``)."""
        cutoff = time.monotonic() - self.io.window
        while self._observed and self._observed[0][0] < cutoff:
            self._observed.popleft()
        changes = [(ts, path, size) for ts, path, size in self._observed if after is None or ts > after]
        if not changes:
            return None, 0
        return changes[0][0], sum({path: size for _, path, size in changes}.values())
