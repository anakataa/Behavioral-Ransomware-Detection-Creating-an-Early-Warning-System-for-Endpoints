"""End-to-end: real agent vs. the mock ransomware in a subprocess."""

import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from sentinel import config
from sentinel.agent import Agent
from sentinel.audit import AuditLog

MOCK = Path(__file__).resolve().parents[1] / "scripts" / "mock_ransomware.py"
FILES = 400


def _mock(*args):
    return [sys.executable, str(MOCK), *args]


def _make_agent(sandbox: Path, tmp_path: Path, mitigate: bool) -> tuple[Agent, threading.Event]:
    cfg = config.load(None)
    cfg.watch_paths = [sandbox]
    cfg.mitigation.enabled = mitigate
    agent = Agent(cfg, AuditLog(tmp_path / "audit.db"))
    fired = threading.Event()
    agent.on_verdict.append(lambda *a: fired.set())
    return agent, fired


def test_agent_detects_and_kills_mock_ransomware(tmp_path):
    sandbox = tmp_path / "sandbox"
    subprocess.run(_mock("setup", "--target", str(sandbox), "--files", str(FILES)), check=True)

    agent, fired = _make_agent(sandbox, tmp_path, mitigate=True)
    agent.start()
    try:
        time.sleep(1.0)  # let watchdog + io sampler settle
        proc = subprocess.Popen(_mock("encrypt", "--target", str(sandbox)),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        proc.wait(timeout=60)
        assert fired.wait(5), "no verdict issued"
    finally:
        agent.stop()

    out = proc.stdout.read()
    assert "Sentinel did NOT stop this run" not in out, out
    assert proc.returncode != 0

    # The mock reports its own pid; on Windows venvs `proc.pid` is only a launcher.
    worker_pid = int(re.search(r"\[pid (\d+)\]", out).group(1))
    actions = agent.audit.recent(50, category="mitigation")
    assert actions and actions[0].pid == worker_pid, [vars(a) for a in actions]

    remaining = [p for p in sandbox.rglob("*.txt") if ".sentinel_canary" not in p.parts]
    assert remaining, "every file was encrypted before the kill"
    print(f"\nkilled after {FILES - len(remaining)}/{FILES} files encrypted")


def test_monitor_only_alerts_without_killing(tmp_path):
    sandbox = tmp_path / "sandbox"
    subprocess.run(_mock("setup", "--target", str(sandbox), "--files", "150"), check=True)

    agent, fired = _make_agent(sandbox, tmp_path, mitigate=False)
    agent.start()
    try:
        time.sleep(1.0)
        proc = subprocess.run(_mock("encrypt", "--target", str(sandbox)),
                              capture_output=True, text=True, timeout=60)
        assert fired.wait(5), "no verdict issued"
    finally:
        agent.stop()

    assert proc.returncode == 0
    assert agent.audit.recent(10, category="verdict")
    assert agent.audit.recent(10, category="mitigation")[0].message.startswith("monitor-only")


def test_normal_editing_does_not_trigger(tmp_path):
    work = tmp_path / "docs"
    work.mkdir()
    agent, fired = _make_agent(work, tmp_path, mitigate=False)
    agent.start()
    try:
        for i in range(20):  # a user saving documents: slow, low entropy
            (work / f"note{i % 5}.txt").write_text(f"meeting notes revision {i}\n" * 200)
            time.sleep(0.1)
        time.sleep(1.0)
    finally:
        agent.stop()
    assert not fired.is_set()
    assert not agent.audit.recent(10, category="verdict")
