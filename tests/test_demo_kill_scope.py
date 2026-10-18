"""`sentinel demo` may only kill the simulator the dashboard launched.

With the kill filter in place nothing outside the dashboard's own attack
can be terminated, so these tests are safe to run in active mode.
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from sentinel import config
from sentinel.agent import Agent
from sentinel.attribution import Suspect
from sentinel.audit import AuditLog
from sentinel.dashboard import MOCK, AttackRunner
from sentinel.decision import Signal, SignalKind, Verdict

SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]


def _agent(tmp_path: Path, watch: Path, kill_filter) -> Agent:
    cfg = config.load(None)
    cfg.watch_paths = [watch]
    cfg.canary.enabled = False
    return Agent(cfg, AuditLog(tmp_path / "audit.db"), kill_filter=kill_filter)


def _verdict() -> Verdict:
    now = time.monotonic()
    return Verdict((Signal(SignalKind.CANARY, 1.0, now), Signal(SignalKind.ENTROPY, 7.9, now)), now)


def _blame(agent: Agent, pid: int) -> None:
    """Make attribution name ``pid`` as a clean, unambiguous culprit."""
    s = Suspect(pid, psutil.Process(pid).name(), None, 100_000, False, 1.0, 100_000, 1.0)
    agent.io.suspects = lambda **kw: [s]


@pytest.fixture
def sleepers():
    procs = [subprocess.Popen(SLEEPER) for _ in range(2)]
    yield procs
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.wait()


def test_attack_runner_owns_only_its_process_tree(tmp_path, sleepers):
    runner = AttackRunner(tmp_path / "sandbox", files=50)
    runner.ensure_sandbox()
    assert not runner.owns(os.getpid())                  # nothing launched yet
    pid = runner.launch(rate=5, stealth=False)
    try:
        tree = [pid] + [c.pid for c in psutil.Process(pid).children(recursive=True)]
        assert all(runner.owns(p) for p in tree)
        assert not runner.owns(os.getpid())
        assert not runner.owns(sleepers[0].pid)
    finally:
        runner._proc.kill()
        runner._proc.wait()
    assert not runner.owns(pid)                          # finished attack is out of scope


def test_kill_filter_blocks_out_of_scope_culprit(tmp_path, sleepers):
    outsider, insider = sleepers
    agent = _agent(tmp_path, tmp_path, kill_filter=lambda pid: pid == insider.pid)

    _blame(agent, outsider.pid)
    agent.respond(_verdict())
    assert outsider.poll() is None, "out-of-scope process must survive"
    v = agent.audit.recent(1, category="verdict")[0]
    assert "outside the kill scope" in v.details["no_action_reason"]
    assert not agent.audit.recent(5, category="mitigation")

    _blame(agent, insider.pid)
    agent.respond(_verdict())
    assert insider.wait(timeout=5) is not None, "in-scope culprit must be killed"
    assert agent.audit.recent(1, category="mitigation")[0].pid == insider.pid


def test_demo_kills_dashboard_attack(tmp_path):
    """Full demo wiring, active mode: the Launch-attack simulator gets killed."""
    sandbox = tmp_path / "sandbox"
    runner = AttackRunner(sandbox, files=300)
    runner.ensure_sandbox()
    agent = _agent(tmp_path, sandbox, kill_filter=runner.owns)
    agent.cfg.canary.enabled = True
    killed = threading.Event()
    agent.on_verdict.append(lambda v, target, result: result and result.stopped and killed.set())
    agent.start()
    try:
        time.sleep(1.0)
        runner.launch(rate=0, stealth=False)
        deadline = time.time() + 60
        while runner.running() and time.time() < deadline:
            time.sleep(0.2)
    finally:
        agent.stop()
    state = runner.state()
    assert killed.is_set(), [vars(r) for r in agent.audit.recent(20)]
    assert state["attack"]["returncode"] != 0
    assert state["attack"]["encrypted_by_attack"] < 300
    print(f"\ndemo attack killed after {state['attack']['encrypted_by_attack']}/300 files")


def test_demo_does_not_kill_attack_launched_elsewhere(tmp_path):
    """The same simulator started outside the dashboard is alert-only."""
    sandbox = tmp_path / "sandbox"
    runner = AttackRunner(sandbox, files=150)
    runner.ensure_sandbox()                              # dashboard idle: owns nothing
    agent = _agent(tmp_path, sandbox, kill_filter=runner.owns)
    agent.cfg.canary.enabled = True
    agent.start()
    try:
        time.sleep(1.0)
        proc = subprocess.run([sys.executable, str(MOCK), "encrypt", "--target", str(sandbox)],
                              capture_output=True, text=True, timeout=60)
        time.sleep(1.5)                                  # let a pending verdict finish
    finally:
        agent.stop()
    assert proc.returncode == 0, "simulator outside the kill scope must run to completion"
    verdicts = agent.audit.recent(20, category="verdict")
    assert verdicts, "attack must still be detected and alerted"
    assert not agent.audit.recent(20, category="mitigation")
    assert any("outside the kill scope" in (v.details.get("no_action_reason") or "") for v in verdicts)
