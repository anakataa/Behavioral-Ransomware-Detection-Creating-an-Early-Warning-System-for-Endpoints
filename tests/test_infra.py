import os
import subprocess
import sys
import time

import psutil
import pytest

from sentinel import config
from sentinel.attribution import IoTracker, Suspect, ambiguous, is_protected
from sentinel.audit import AuditLog
from sentinel.event_listener import EventKind, EventListener
from sentinel.mitigation import Mitigator


# -- config ------------------------------------------------------------------
def test_defaults_without_file():
    cfg = config.load(None)
    assert cfg.detection.velocity_threshold == 50.0
    assert cfg.detection.confirmation_signals == 2
    assert "7z.exe" in cfg.mitigation.whitelist


def test_load_example_config(tmp_path, monkeypatch):
    monkeypatch.setenv("USERNAME", "alice")
    root = os.path.dirname(os.path.dirname(__file__))
    cfg = config.load(os.path.join(root, "config.example.yaml"))
    assert any("alice" in str(p) for p in cfg.watch_paths)
    assert cfg.canary.count == 12


def test_invalid_config_rejected(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("detection:\n  confirmation_signals: 5\n")
    with pytest.raises(ValueError):
        config.load(f)


# -- audit -------------------------------------------------------------------
def test_audit_roundtrip(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    log.write("ALERT", "verdict", "boom", pid=42, process="evil.exe", details={"x": 1})
    log.write("INFO", "system", "started")
    recs = log.recent(10)
    assert [r.message for r in recs] == ["started", "boom"]
    assert recs[1].details == {"x": 1} and recs[1].pid == 42
    assert [r.message for r in log.recent(10, category="verdict")] == ["boom"]
    log.close()


# -- event listener ----------------------------------------------------------
def test_listener_reports_file_events(tmp_path):
    ignored = tmp_path / "ignored.db"
    lst = EventListener([tmp_path], ignore_paths=[ignored])
    lst.start()
    try:
        time.sleep(0.2)
        (tmp_path / "a.txt").write_text("hi")
        ignored.write_text("x")
        (tmp_path / "a.txt").rename(tmp_path / "a.txt.locked")
        deadline = time.monotonic() + 3
        events = []
        while time.monotonic() < deadline:
            e = lst.get(timeout=0.2)
            if e:
                events.append(e)
            if any(e.kind is EventKind.MOVED for e in events):
                break
    finally:
        lst.stop()
    assert any(e.path.name == "a.txt" for e in events)
    assert any(e.kind is EventKind.MOVED and e.dest_path.name == "a.txt.locked" for e in events)
    assert not any(e.path == ignored.resolve() for e in events)


# -- attribution & mitigation ------------------------------------------------
def test_ambiguity_rule():
    def s(ratio, handle=False):
        return Suspect(1, "x", None, 0, handle, ratio)
    assert not ambiguous([s(1.05)])
    assert not ambiguous([s(1.05), s(3.5)])          # clear winner
    assert ambiguous([s(1.3), s(1.4)])               # coin flip -> don't kill
    assert not ambiguous([s(1.3, handle=True), s(1.4)])  # open handle is decisive


def test_never_targets_self_or_system():
    assert is_protected(os.getpid(), "python")
    assert is_protected(4, "System")
    assert is_protected(1234, "lsass.exe")


WRITER = (
    "import os, sys, time\n"
    "with open(sys.argv[1], 'wb') as f:\n"
    "    for _ in range(40):\n"
    "        f.write(os.urandom(256 * 1024)); f.flush(); os.fsync(f.fileno())\n"
    "        time.sleep(0.02)\n"
    "    time.sleep(30)\n"
)


def test_tracker_finds_heavy_writer(tmp_path):
    tracker = IoTracker([tmp_path], window=10)
    tracker.sample()
    proc = subprocess.Popen([sys.executable, "-c", WRITER, str(tmp_path / "out.bin")])
    try:
        time.sleep(2.0)
        suspects = tracker.suspects()
        # venv launchers on Windows run the real interpreter as a child
        tree = {proc.pid} | {c.pid for c in psutil.Process(proc.pid).children(recursive=True)}
        assert suspects and suspects[0].pid in tree
    finally:
        proc.kill()
        proc.wait()


def test_mitigator_terminates(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        res = Mitigator(enabled=True, grace_period=1.0).neutralize(proc.pid)
        assert res.stopped
        assert proc.wait(timeout=5) is not None
    finally:
        if proc.poll() is None:
            proc.kill()


def test_mitigator_monitor_only(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        res = Mitigator(enabled=False).neutralize(proc.pid)
        assert res.action == "monitor-only"
        assert psutil.pid_exists(proc.pid) and proc.poll() is None
    finally:
        proc.kill()
        proc.wait()
