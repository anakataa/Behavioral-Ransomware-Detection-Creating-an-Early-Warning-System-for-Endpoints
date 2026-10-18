"""Local dashboard server — the HTML dashboard on top of the live audit DB.

The agent and the dashboard share nothing but the SQLite file: the agent
writes ``audit_log`` and ``metrics``; this server reads them read-only
and serves ``dashboard/sentinel_dashboard.html`` plus a small JSON API:

    GET  /api/state?since=<id>   new audit events, recent metrics, attack + sandbox state
    POST /api/attack             launch scripts/mock_ransomware.py against the sandbox
    POST /api/reset              regenerate the sandbox's synthetic documents

Binds to 127.0.0.1 only. POSTs require an ``X-Sentinel-Demo`` header: a
custom header forces a CORS preflight, which this server never grants,
so other web pages can't trigger the simulator. The Host header is
checked against localhost to defeat DNS rebinding.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import psutil

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HTML = REPO_ROOT / "dashboard" / "sentinel_dashboard.html"
MOCK = REPO_ROOT / "scripts" / "mock_ransomware.py"
METRICS_WINDOW = 60.0      # seconds of telemetry returned on the first poll
MAX_EVENTS = 200


class AttackRunner:
    """Owns at most one mock-ransomware process against the sandbox."""

    def __init__(self, sandbox: Path, files: int = 300) -> None:
        self.sandbox = sandbox.resolve()
        self.files = files
        self._proc: subprocess.Popen[bytes] | None = None
        self._started: float | None = None
        self._ended: float | None = None
        self._profile: str | None = None
        self._baseline = 0  # encrypted files already present when the attack started
        self._lock = threading.Lock()

    def _mock(self, *args: str) -> list[str]:
        return [sys.executable, str(MOCK), *args, "--target", str(self.sandbox)]

    def ensure_sandbox(self) -> None:
        if not (self.sandbox / ".mock_ransomware_sandbox").is_file():
            self.reset()

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def owns(self, pid: int) -> bool:
        """True if ``pid`` is the running simulator launched here, or its descendant.

        Descendants matter: a Windows venv ``python.exe`` is a launcher that
        runs the real interpreter as a child, and that child does the writing.
        ``sentinel demo`` passes this to the agent as its kill filter.
        """
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return False
        if pid == proc.pid:
            return True
        try:
            return any(p.pid == proc.pid for p in psutil.Process(pid).parents())
        except psutil.Error:
            return False

    def reset(self) -> None:
        with self._lock:
            if self.running():
                raise RuntimeError("attack in progress")
            subprocess.run(self._mock("setup") + ["--files", str(self.files)],
                           check=True, capture_output=True)
            self._proc = None
            self._started = self._ended = None

    def launch(self, rate: float, stealth: bool) -> int:
        if not MOCK.is_file():
            raise RuntimeError(f"simulator not found at {MOCK}")
        with self._lock:
            if self.running():
                raise RuntimeError("attack already running")
            args = self._mock("encrypt") + ["--rate", str(rate)]
            if stealth:
                args.append("--skip-hidden")
            self._baseline = self._count()[1]
            self._proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._started, self._ended = time.time(), None
            self._profile = "stealth (skips canary vault)" if stealth else "standard"
            log.warning("demo attack launched: pid %d, rate %s files/s, %s", self._proc.pid, rate, self._profile)
            return self._proc.pid

    def _count(self) -> tuple[int, int]:
        """(plaintext, encrypted) documents in the sandbox, canary vault excluded."""
        plain = locked = 0
        if self.sandbox.is_dir():
            for p in self.sandbox.rglob("*"):
                if not p.is_file() or ".sentinel_canary" in p.parts:
                    continue
                if p.name.endswith(".locked"):
                    locked += 1
                elif p.suffix == ".txt" and not p.name.startswith("README_"):
                    plain += 1
        return plain, locked

    def state(self) -> dict[str, Any]:
        plain, locked = self._count()
        proc = self._proc
        code = proc.poll() if proc else None
        if proc is not None and code is not None and self._ended is None:
            self._ended = time.time()
        return {
            "sandbox": str(self.sandbox),
            "plaintext": plain,
            "encrypted": locked,
            "attack": None if proc is None else {
                "pid": proc.pid,
                "running": code is None,
                "returncode": code,
                "profile": self._profile,
                "started": self._started,
                "ended": self._ended,
                "encrypted_by_attack": max(0, locked - self._baseline),
            },
        }


def _read_db(db: Path, since_id: int, since_ts: float | None) -> dict[str, Any]:
    if not db.exists():
        return {"events": [], "metrics": [], "agent": None, "threats_blocked": 0}
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=1.0)
    try:
        conn.row_factory = sqlite3.Row
        if since_id > 0:
            rows = conn.execute("SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT ?",
                                (since_id, MAX_EVENTS)).fetchall()
        else:  # first poll: the latest events, not the oldest
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                                (MAX_EVENTS,)).fetchall()[::-1]
        events = [dict(r) for r in rows]
        for e in events:
            e["details"] = json.loads(e["details"]) if e["details"] else {}
        cutoff = since_ts if since_ts is not None else time.time() - METRICS_WINDOW
        try:
            metrics = [dict(r) for r in conn.execute(
                "SELECT * FROM metrics WHERE ts > ? ORDER BY ts", (cutoff,))]
            last = conn.execute("SELECT MAX(ts) FROM metrics").fetchone()[0]
        except sqlite3.OperationalError:  # DB written by an agent without telemetry
            metrics, last = [], None
        started = conn.execute(
            "SELECT ts, details FROM audit_log WHERE category='system' AND message='agent started'"
            " ORDER BY id DESC LIMIT 1").fetchone()
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE category='mitigation'"
            " AND (message LIKE 'terminated:%' OR message LIKE 'killed:%')"
            + (" AND ts >= ?" if started else ""), (started["ts"],) if started else ()).fetchone()[0]
    finally:
        conn.close()
    agent = None
    if started:
        details = json.loads(started["details"] or "{}")
        agent = {
            "started": started["ts"],
            "alive": last is not None and time.time() - last < 3.0,
            "mitigation": details.get("mitigation"),
            "watch_paths": details.get("watch_paths", []),
            "canaries": details.get("canaries"),
        }
    return {"events": events, "metrics": metrics, "agent": agent, "threats_blocked": blocked}


def make_handler(html: Path, db: Path, attack: AttackRunner):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SentinelDashboard/0.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("http: " + fmt, *args)

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: Any, status: int = 200) -> None:
            self._send(status, json.dumps(obj, default=str).encode(), "application/json")

        def _local_host(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            return host in ("127.0.0.1", "localhost", "::1")

        def do_GET(self) -> None:
            if not self._local_host():
                return self._json({"error": "forbidden host"}, HTTPStatus.FORBIDDEN)
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(200, html.read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/state":
                q = parse_qs(url.query)
                since_id = int(q.get("since", ["0"])[0] or 0)
                since_ts = float(q["since_ts"][0]) if q.get("since_ts") else None
                return self._json({**_read_db(db, since_id, since_ts), **attack.state(),
                                   "server_time": time.time()})
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if not self._local_host() or self.headers.get("X-Sentinel-Demo") != "1":
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                body = {}
            url = urlparse(self.path)
            try:
                if url.path == "/api/attack":
                    rate = max(0.0, min(500.0, float(body.get("rate", 20))))
                    pid = attack.launch(rate, bool(body.get("stealth")))
                    return self._json({"ok": True, "pid": pid})
                if url.path == "/api/reset":
                    attack.reset()
                    return self._json({"ok": True})
            except (RuntimeError, subprocess.CalledProcessError) as exc:
                return self._json({"ok": False, "error": str(exc)}, HTTPStatus.CONFLICT)
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    return Handler


def serve(db: Path, sandbox: Path, port: int = 8765, html: Path = DEFAULT_HTML,
          files: int = 300) -> ThreadingHTTPServer:
    """Create (not start) the dashboard server; call ``serve_forever()`` on it."""
    attack = AttackRunner(sandbox, files)
    attack.ensure_sandbox()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(html, Path(db).resolve(), attack))
    httpd.daemon_threads = True
    httpd.attack = attack  # type: ignore[attr-defined]  # `sentinel demo` needs attack.owns
    return httpd
