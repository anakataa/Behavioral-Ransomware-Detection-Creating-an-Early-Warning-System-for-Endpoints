"""Dashboard server API — no agent involved, nothing gets terminated."""

import http.client
import json
import threading
import time

import pytest

from sentinel.audit import AuditLog
from sentinel.dashboard import serve


@pytest.fixture
def server(tmp_path):
    db = tmp_path / "audit.db"
    log = AuditLog(db)
    log.write("INFO", "system", "agent started", details={"mitigation": True, "watch_paths": ["x"]})
    log.write("ALERT", "verdict", "ransomware behavior: canary + entropy", pid=42, process="evil.exe",
              details={"suspects": ["evil.exe (pid 42)"]})
    log.write("ACTION", "mitigation", "terminated: evil.exe", pid=42, process="evil.exe")
    log.write_metrics(12.0, 7.9, 30, 0.4, "1101", ["canary"])
    httpd = serve(db, tmp_path / "sandbox", port=0, files=20)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd, log, tmp_path
    httpd.shutdown()
    httpd.server_close()
    log.close()


def request(httpd, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
    conn.request(method, path, body=None if body is None else json.dumps(body),
                 headers={"Content-Type": "application/json", **(headers or {})})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def state(httpd, query=""):
    status, data = request(httpd, "GET", "/api/state" + query)
    assert status == 200
    return json.loads(data)


def test_serves_live_dashboard(server):
    httpd, *_ = server
    status, html = request(httpd, "GET", "/")
    assert status == 200 and b"/api/state" in html


def test_state_reads_audit_db(server):
    httpd, log, _ = server
    s = state(httpd)
    assert [e["category"] for e in s["events"]] == ["system", "verdict", "mitigation"]
    assert s["threats_blocked"] == 1
    assert s["agent"]["alive"] and s["agent"]["mitigation"] is True
    assert s["metrics"][-1]["canary_state"] == "1101"
    assert s["plaintext"] == 20 and s["encrypted"] == 0  # sandbox was created

    last = s["events"][-1]["id"]
    log.write("WARNING", "signal", "velocity signal fired")
    assert [e["message"] for e in state(httpd, f"?since={last}")["events"]] == ["velocity signal fired"]


def test_posts_need_demo_header(server):
    httpd, *_ = server
    assert request(httpd, "POST", "/api/reset", {})[0] == 403
    assert request(httpd, "POST", "/api/reset", {}, {"X-Sentinel-Demo": "1"})[0] == 200


def test_rejects_foreign_host_header(server):
    httpd, *_ = server
    status, _ = request(httpd, "GET", "/api/state", headers={"Host": "evil.example:8765"})
    assert status == 403


def test_attack_runs_mock_in_sandbox(server):
    httpd, *_ = server
    status, data = request(httpd, "POST", "/api/attack", {"rate": 0}, {"X-Sentinel-Demo": "1"})
    assert status == 200 and json.loads(data)["ok"]
    deadline = time.time() + 30
    while state(httpd)["attack"]["running"] and time.time() < deadline:
        time.sleep(0.2)
    s = state(httpd)
    assert s["attack"]["returncode"] == 0          # no agent here, so it runs to completion
    assert s["encrypted"] == 20 and s["attack"]["encrypted_by_attack"] == 20
    assert request(httpd, "POST", "/api/reset", {}, {"X-Sentinel-Demo": "1"})[0] == 200
    assert state(httpd)["plaintext"] == 20
