"""Attribution windows must hold up when file events arrive late and in batches."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from sentinel import agent as agent_mod
from sentinel import config
from sentinel.agent import Agent
from sentinel.attribution import IoTracker, Suspect
from sentinel.audit import AuditLog
from sentinel.decision import Signal, SignalKind, Verdict
from sentinel.event_listener import EventKind, FileEvent


def _agent(tmp_path: Path) -> Agent:
    cfg = config.load(None)
    cfg.watch_paths = [tmp_path]
    return Agent(cfg, AuditLog(tmp_path / "audit.db"))


def _changed_at(path: Path, mono: float, size: int = 1000) -> Path:
    """Create ``path`` and backdate its mtime to monotonic time ``mono``."""
    path.write_bytes(b"x" * size)
    wall = mono + (time.time() - time.monotonic())
    os.utime(path, (wall, wall))
    return path


def test_io_delta_is_cut_at_window_end():
    hist = [(1.0, 0, 0), (2.0, 100, 10), (3.0, 300, 30), (4.0, 1000, 40)]
    assert IoTracker._delta_since(hist, since=2.5, until=3.5) == (200, 20)
    assert IoTracker._delta_since(hist, since=2.0, until=3.0) == (200, 20)
    assert IoTracker._delta_since(hist, since=None) == (1000, 40)


def test_late_events_count_in_the_window_the_file_changed_in(tmp_path):
    agent = _agent(tmp_path)
    now = time.monotonic()
    t1 = now - 1.0  # window 1 = (.., t1], window 2 = (t1, now]
    early = _changed_at(tmp_path / "early.txt", t1 - 0.5, 1000)
    late = _changed_at(tmp_path / "late.txt", t1 + 0.5, 3000)
    # Both reported in one batch, now: arrival time says nothing about the window.
    for p in (early, late):
        agent._record_change(FileEvent(EventKind.MODIFIED, p, now))
    start, w1 = agent._observed_burst(until=t1)
    assert w1 == 1000 and abs(start - (t1 - 0.5)) < 0.05
    assert agent._observed_burst(after=t1, until=now)[1] == 3000


def test_backdated_mtime_falls_back_to_arrival(tmp_path):
    agent = _agent(tmp_path)
    now = time.monotonic()
    old = _changed_at(tmp_path / "copied.txt", now - 3600)  # e.g. copy2 keeps the mtime
    assert agent._record_change(FileEvent(EventKind.MODIFIED, old, now)) == now


def test_window_waits_for_changes_reported_late(tmp_path, monkeypatch):
    agent = _agent(tmp_path)
    t = time.monotonic()
    monkeypatch.setattr(agent.io, "sample", lambda: t)
    before = _changed_at(tmp_path / "before.txt", t - 0.1, 2000)

    def deliver():  # watchdog reports the change 0.3 s late, then a later one
        time.sleep(0.3)
        agent.listener.events.put(FileEvent(EventKind.MODIFIED, before, time.monotonic()))
        after = tmp_path / "after.txt"
        after.write_bytes(b"y" * 10)
        agent.listener.events.put(FileEvent(EventKind.MODIFIED, after, time.monotonic()))

    threading.Thread(target=deliver).start()
    assert agent._close_window() == t
    elapsed = time.monotonic() - t
    assert agent._observed_burst(until=t)[1] == 2000
    assert elapsed < agent_mod.EVENT_CATCHUP, "should stop once the stream passed the window end"


def test_window_closes_after_catchup_when_nothing_more_comes(tmp_path, monkeypatch):
    agent = _agent(tmp_path)
    monkeypatch.setattr(agent_mod, "EVENT_CATCHUP", 0.2)
    monkeypatch.setattr(agent.io, "sample", time.monotonic)
    t0 = time.monotonic()
    agent._close_window()
    assert time.monotonic() - t0 < 1.0


def test_too_little_data_in_confirm_window_is_alert_only(tmp_path, monkeypatch):
    """A few KiB can be matched by any background writer: never kill on that."""
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        agent = _agent(tmp_path)
        agent.cfg.canary.enabled = False
        monkeypatch.setattr(agent_mod, "CONFIRM_MAX_WINDOW", 0.5)
        s = Suspect(sleeper.pid, "python.exe", None, 4096, False, 1.0, 4096, 1.0)
        agent.io.suspects = lambda **kw: [s]
        now = time.monotonic()
        agent.respond(Verdict((Signal(SignalKind.CANARY, 1.0, now), Signal(SignalKind.ENTROPY, 7.9, now)), now))
        assert sleeper.poll() is None
        v = agent.audit.recent(1, category="verdict")[0]
        assert "too little written" in v.details["no_action_reason"]
    finally:
        sleeper.kill()
        sleeper.wait()


def test_bystander_is_not_blamed_when_the_better_match_exited(tmp_path, monkeypatch):
    """Window 1: culprit and a background writer both match. The culprit exits;
    window 2 then only has the bystander left. It must not be killed."""
    culprit = subprocess.Popen([sys.executable, "-c", "pass"])
    culprit.wait()                                       # exited: pid no longer exists
    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        agent = _agent(tmp_path)
        agent.cfg.canary.enabled = False
        monkeypatch.setattr(agent_mod, "CONFIRM_MIN_BYTES", 0)
        gone = Suspect(culprit.pid, "python.exe", None, 100_000, False, 1.01, 0, None)
        by = Suspect(bystander.pid, "firefox.exe", None, 103_000, False, 1.03, 0, None)
        calls = iter([[gone, by], [Suspect(bystander.pid, "firefox.exe", None, 100_000, False, 1.0, 70_000, 0.7)]])
        agent.io.suspects = lambda **kw: next(calls)
        now = time.monotonic()
        agent.respond(Verdict((Signal(SignalKind.CANARY, 1.0, now), Signal(SignalKind.ENTROPY, 7.9, now)), now))
        assert bystander.poll() is None, "bystander was killed"
        v = agent.audit.recent(1, category="verdict")[0]
        assert "exited before confirmation" in v.details["no_action_reason"]
    finally:
        bystander.kill()
        bystander.wait()
