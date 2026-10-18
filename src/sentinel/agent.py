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
ATTRIBUTION_SETTLE = 0.3       # boosted sampling needed before choosing whom to kill


class Agent:
    def __init__(self, cfg: Config, audit: AuditLog | None = None) -> None:
        self.cfg = cfg
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
        while not self._stop.is_set():
            event = self.listener.get(timeout=0.5)
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

    def handle(self, event: FileEvent) -> None:
        ts = event.timestamp
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
        self._settle()
        burst_start, observed = self._observed_burst()
        suspects = self.io.suspects(since=burst_start, expected_bytes=observed)
        target: Suspect | None = suspects[0] if suspects else None
        outcome = None
        if target is None:
            outcome = f"no process accounts for the observed writes ({observed} B)"
        elif ambiguous(suspects):
            outcome = f"ambiguous attribution between {suspects[0].name} and {suspects[1].name}"
        elif target.name in self.whitelist:
            # The burst is explained by a trusted tool; the runner-up is not the culprit.
            outcome = f"best match {target.name} is whitelisted"
        if outcome:
            log.error("%s; alert only", outcome)

        self.audit.write("ALERT", "verdict", f"ransomware behavior: {verdict.reason}",
                         pid=target.pid if target else None,
                         process=target.name if target else None,
                         details={"signals": verdict.kinds,
                                  "observed_bytes": observed,
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

    def _settle(self) -> None:
        """Collect enough boosted write samples for correlation to be meaningful.

        Waits up to ATTRIBUTION_SETTLE after boosting began. Events that
        arrive meanwhile are only recorded as changes (no detection): the
        burst they belong to is the one being responded to.
        """
        boosted = self.io.boosted_since
        if boosted is None:
            self.io.boost()
            boosted = time.monotonic()
        deadline = boosted + ATTRIBUTION_SETTLE
        while (now := time.monotonic()) < deadline:
            event = self.listener.get(timeout=min(0.05, deadline - now))
            if event is not None and event.timestamp >= self._handled_until:
                self._record_change(event)

    def _observed_burst(self) -> tuple[float | None, int]:
        """Burst start and total size of distinct files changed in the attribution window."""
        cutoff = time.monotonic() - self.io.window
        while self._observed and self._observed[0][0] < cutoff:
            self._observed.popleft()
        if not self._observed:
            return None, 0
        return self._observed[0][0], sum({path: size for _, path, size in self._observed}.values())
