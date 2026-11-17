"""Smoke test of the built executable: demo server + attack + kill, no Python needed by the exe.

    python scripts/vm/smoke_exe.py dist/sentinel.exe

Starts `sentinel demo` on a temporary sandbox, launches the bundled simulator
through the dashboard API, and checks the audit log for a termination.
Exit code 0 = the executable detected and stopped the simulator.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import psutil

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"


def request(path: str, data: dict | None = None) -> dict | str:
    req = urllib.request.Request(BASE + path)
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Sentinel-Demo", "1")
        req.method = "POST"
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body


def main() -> int:
    exe = Path(sys.argv[1]).resolve()
    work = Path(tempfile.mkdtemp(prefix="sentinel-smoke-"))
    db = work / "audit.db"
    print(subprocess.run([str(exe), "--version"], capture_output=True, text=True, check=True).stdout.strip())
    demo = subprocess.Popen([str(exe), "demo", "--no-browser", "--port", str(PORT),
                             "--sandbox", str(work / "sandbox"), "--db", str(db)], cwd=work)
    try:
        for _ in range(60):  # onefile builds unpack themselves first
            try:
                request("/")
                break
            except OSError:
                time.sleep(1)
        else:
            print("dashboard never came up")
            return 1
        time.sleep(2)
        print("attack:", request("/api/attack", {"rate": 100}))
        for _ in range(60):
            state = request("/api/state")
            if not state["attack"]["running"]:
                break
            time.sleep(1)
        time.sleep(2)
        print("final attack state:", state["attack"])
    finally:
        try:
            for p in [psutil.Process(demo.pid), *psutil.Process(demo.pid).children(recursive=True)]:
                p.kill()
        except psutil.Error:
            pass
    audit = subprocess.run([str(exe), "audit", "--db", str(db), "-n", "20"],
                           capture_output=True, text=True, cwd=work).stdout
    print(audit)
    if "mitigation" in audit and ("terminated:" in audit or "killed:" in audit):
        print("SMOKE TEST PASSED: simulator detected and stopped by the executable")
        return 0
    print("SMOKE TEST FAILED: no termination in the audit log")
    return 1


if __name__ == "__main__":
    sys.exit(main())
