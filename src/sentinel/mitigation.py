"""Mitigation — stop the offending process tree via psutil.

Order matters: the whole tree is *suspended* first (freezes encryption
within milliseconds, children can't respawn work), then terminated,
and anything still alive after the grace period is killed.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import psutil

from .attribution import is_protected

log = logging.getLogger(__name__)


@dataclass
class MitigationResult:
    pid: int
    name: str | None
    action: str                      # terminated | killed | monitor-only | protected | gone | failed
    children: list[int] = field(default_factory=list)
    error: str | None = None

    @property
    def stopped(self) -> bool:
        return self.action in ("terminated", "killed", "gone")


class Mitigator:
    def __init__(self, enabled: bool = True, grace_period: float = 0.5) -> None:
        self.enabled = enabled
        self.grace_period = grace_period

    def neutralize(self, pid: int) -> MitigationResult:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            return MitigationResult(pid, None, "gone")
        except psutil.Error as exc:
            return MitigationResult(pid, None, "failed", error=repr(exc))

        if is_protected(pid, name):
            log.warning("refusing to terminate protected process %s (%d)", name, pid)
            return MitigationResult(pid, name, "protected")
        if not self.enabled:
            log.warning("monitor-only mode: would terminate %s (%d)", name, pid)
            return MitigationResult(pid, name, "monitor-only")

        try:
            children = proc.children(recursive=True)
        except psutil.Error:
            children = []
        tree = [proc, *children]

        for p in tree:
            try:
                p.suspend()
            except psutil.Error:
                pass
        for p in tree:
            try:
                p.terminate()
                if os.name != "nt":
                    p.resume()  # SIGTERM stays pending while a process is SIGSTOPped
            except psutil.Error:
                pass
        _, alive = psutil.wait_procs(tree, timeout=self.grace_period)
        for p in alive:
            try:
                p.kill()
            except psutil.Error:
                pass
        _, still_alive = psutil.wait_procs(alive, timeout=self.grace_period) if alive else ([], [])

        result = MitigationResult(
            pid, name,
            "failed" if proc in still_alive else ("killed" if proc in alive else "terminated"),
            children=[c.pid for c in children],
            error="process survived SIGKILL" if proc in still_alive else None,
        )
        log.warning("mitigation: %s %s (pid %d), %d child(ren)", result.action, name, pid, len(children))
        return result
