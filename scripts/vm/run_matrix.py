"""Evaluation test matrix: runs on any VM (VirtualBox, CI runner) or a bare machine.

Every scenario uses a fresh sandbox created by the safe mock simulator, so
nothing outside the sandbox is ever touched.

Scenarios
---------
attack   mock ransomware at several speeds, agent in ACTIVE mode:
         detected? killed? files encrypted before the kill, time to verdict.
evasive  same, but the mock skips hidden dirs (never touches bait files):
         detection must rely on velocity + entropy alone.
benign   legitimate workloads, agent in MONITOR-ONLY mode, counting verdicts
         (= false positives): bulk copy, in-place gzip, one zip archive,
         normal document editing.
idle     agent CPU and memory while nothing happens.

Usage
-----
    python scripts/vm/run_matrix.py                    # full matrix, 3 runs each
    python scripts/vm/run_matrix.py --runs 1 --quick   # smoke test (~1 min)
    python scripts/vm/run_matrix.py --out results/vm-win10

Writes <out>/results.csv (one row per run) and <out>/summary.md.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sentinel import __version__, config  # noqa: E402
from sentinel.agent import Agent  # noqa: E402
from sentinel.audit import AuditLog  # noqa: E402

MOCK = ROOT / "scripts" / "mock_ransomware.py"
FIELDS = ["scenario", "variant", "run", "mode", "files_total", "detected", "verdicts", "killed",
          "files_encrypted", "pct_encrypted", "time_to_signal_s", "time_to_verdict_s", "attack_duration_s",
          "no_action_reason", "cpu_pct", "rss_mb"]

BENIGN = {
    "bulk_copy": """
        import shutil, sys, pathlib
        src = pathlib.Path(sys.argv[1]) / "Documents"
        dst = pathlib.Path(sys.argv[1]) / "Copy"
        shutil.copytree(src, dst)
    """,
    "gzip_in_place": """
        import gzip, sys, pathlib, shutil
        root = pathlib.Path(sys.argv[1])
        for p in sorted(root.rglob("*.txt")):
            if any(part.startswith(".") for part in p.relative_to(root).parts):
                continue
            with open(p, "rb") as f, gzip.open(str(p) + ".gz", "wb") as g:
                shutil.copyfileobj(f, g)
            p.unlink()
    """,
    "zip_archive": """
        import zipfile, sys, pathlib
        root = pathlib.Path(sys.argv[1])
        with zipfile.ZipFile(root / "backup.zip", "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted((root / "Documents").rglob("*")):
                z.write(p, p.relative_to(root))
    """,
    "doc_editing": """
        import sys, time, pathlib
        root = pathlib.Path(sys.argv[1]) / "Documents"
        for i in range(30):
            (root / f"notes{i % 5}.txt").write_text(f"meeting notes revision {i}\\n" * 300)
            time.sleep(0.1)
    """,
}


def mock(*args: str) -> list[str]:
    return [sys.executable, str(MOCK), *args]


def setup_sandbox(base: Path, files: int) -> Path:
    sandbox = base / "sandbox"
    subprocess.run(mock("setup", "--target", str(sandbox), "--files", str(files)),
                   check=True, capture_output=True)
    return sandbox


def count_plain(sandbox: Path) -> int:
    return sum(1 for p in sandbox.rglob("*.txt") if ".sentinel_canary" not in p.parts)


def make_agent(sandbox: Path, base: Path, active: bool) -> Agent:
    cfg = config.load(None)
    cfg.watch_paths = [sandbox]
    cfg.mitigation.enabled = active
    return Agent(cfg, AuditLog(base / "audit.db"))


def verdict_rows(agent: Agent):
    return agent.audit.recent(50, category="verdict")


def run_attack(base: Path, files: int, rate: float, skip_hidden: bool) -> dict:
    sandbox = setup_sandbox(base, files)
    agent = make_agent(sandbox, base, active=True)
    agent.start()
    try:
        time.sleep(1.0)  # watchdog + io sampler settle
        args = ["encrypt", "--target", str(sandbox), "--rate", str(rate)]
        if skip_hidden:
            args.append("--skip-hidden")
        t0 = time.time()
        proc = subprocess.run(mock(*args), capture_output=True, text=True, timeout=600)
        duration = time.time() - t0
        time.sleep(2.0)  # let the agent finish its response
    finally:
        agent.stop()
    verdicts = verdict_rows(agent)
    signals = agent.audit.recent(50, category="signal")
    actions = agent.audit.recent(20, category="mitigation")
    killed = any(a.message.split(":")[0] in ("terminated", "killed") for a in actions)
    remaining = count_plain(sandbox)
    first_signal = min((s.ts for s in signals), default=None)
    first = min((v.ts for v in verdicts), default=None)
    reasons = {v.details.get("no_action_reason") for v in verdicts if v.details.get("no_action_reason")}
    return {
        "mode": "active",
        "files_total": files,
        "detected": bool(verdicts),
        "verdicts": len(verdicts),
        "killed": killed,
        "files_encrypted": files - remaining,
        "pct_encrypted": round(100 * (files - remaining) / files, 1),
        "time_to_signal_s": round(first_signal - t0, 3) if first_signal else "",
        "time_to_verdict_s": round(first - t0, 3) if first else "",
        "attack_duration_s": round(duration, 2),
        "no_action_reason": "; ".join(sorted(reasons)),
        "_stdout": proc.stdout,
    }


def run_benign(base: Path, files: int, name: str) -> dict:
    sandbox = setup_sandbox(base, files)
    script = base / f"{name}.py"
    script.write_text(textwrap.dedent(BENIGN[name]))
    agent = make_agent(sandbox, base, active=False)
    agent.start()
    try:
        time.sleep(1.0)
        t0 = time.time()
        subprocess.run([sys.executable, str(script), str(sandbox)], check=True, timeout=600)
        duration = time.time() - t0
        time.sleep(2.0)
    finally:
        agent.stop()
    verdicts = verdict_rows(agent)
    return {"mode": "monitor-only", "files_total": files, "detected": bool(verdicts),
            "verdicts": len(verdicts), "killed": False, "attack_duration_s": round(duration, 2)}


def run_idle(base: Path, files: int, seconds: float) -> dict:
    sandbox = setup_sandbox(base, files)
    agent = make_agent(sandbox, base, active=False)
    me = psutil.Process()
    agent.start()
    try:
        time.sleep(2.0)
        me.cpu_percent(None)
        time.sleep(seconds)
        cpu = me.cpu_percent(None) / (psutil.cpu_count() or 1)
        rss = me.memory_info().rss / 2**20
    finally:
        agent.stop()
    return {"mode": "monitor-only", "files_total": files, "detected": bool(verdict_rows(agent)),
            "verdicts": len(verdict_rows(agent)), "killed": False,
            "cpu_pct": round(cpu, 2), "rss_mb": round(rss, 1)}


def summarize(rows: list[dict], out: Path, info: dict) -> str:
    lines = [f"# Sentinel evaluation — {info['host']}", "",
             f"- Platform: {info['platform']}",
             f"- Python: {info['python']} · Sentinel {info['sentinel']} · CPUs: {info['cpus']}",
             f"- Date: {info['date']}", "",
             "## Attacks (agent active)", "",
             "Times are from attack start. *First signal* = first detector fired; "
             "*decision* = verdict logged after the two attribution windows.", "",
             "| Variant | Runs | Detected | Killed | Files encrypted (mean) | % (mean) | First signal, s | Decision, s | Attack duration, s |",
             "|---|---|---|---|---|---|---|---|---|"]
    def mean(vals):
        vals = [float(v) for v in vals if v not in ("", None)]
        return f"{statistics.mean(vals):.2f}" if vals else "—"
    def speed(variant: str) -> float:
        head = variant.split()[0]
        return float("inf") if head == "max" else float(head)

    for scen in ("attack", "evasive"):
        for variant in sorted(dict.fromkeys(r["variant"] for r in rows if r["scenario"] == scen), key=speed):
            rs = [r for r in rows if r["scenario"] == scen and r["variant"] == variant]
            lines.append(f"| {scen} {variant} | {len(rs)} | {sum(r['detected'] for r in rs)}/{len(rs)} | "
                         f"{sum(r['killed'] for r in rs)}/{len(rs)} | {mean(r['files_encrypted'] for r in rs)} | "
                         f"{mean(r['pct_encrypted'] for r in rs)} | {mean(r['time_to_signal_s'] for r in rs)} | "
                         f"{mean(r['time_to_verdict_s'] for r in rs)} | "
                         f"{mean(r['attack_duration_s'] for r in rs)} |")
    lines += ["", "## Legitimate workloads (agent monitor-only, verdict = false positive)", "",
              "| Workload | Runs | Runs with a verdict |", "|---|---|---|"]
    for variant in dict.fromkeys(r["variant"] for r in rows if r["scenario"] == "benign"):
        rs = [r for r in rows if r["scenario"] == "benign" and r["variant"] == variant]
        lines.append(f"| {variant} | {len(rs)} | {sum(r['detected'] for r in rs)}/{len(rs)} |")
    idle = [r for r in rows if r["scenario"] == "idle"]
    if idle:
        lines += ["", "## Idle overhead", "",
                  f"- CPU: {mean(r['cpu_pct'] for r in idle)} % of the machine",
                  f"- Memory (runner process incl. agent): {mean(r['rss_mb'] for r in idle)} MB"]
    reasons = sorted({r["no_action_reason"] for r in rows if r.get("no_action_reason")})
    if reasons:
        lines += ["", "## Why no kill (when detected but not killed)", ""] + [f"- {x}" for x in reasons]
    text = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(text, encoding="utf-8")
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="results/" + platform.node().lower(), help="output directory")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--files", type=int, default=400)
    ap.add_argument("--rates", default="20,50,100,0", help="attack speeds, files/s (0 = max)")
    ap.add_argument("--quick", action="store_true", help="fewer scenarios, shorter idle")
    ap.add_argument("--scenarios", default="attack,evasive,benign,idle",
                    help="comma-separated subset of: attack, evasive, benign, idle")
    ap.add_argument("--benign", default=",".join(BENIGN), help="comma-separated benign workloads")
    ap.add_argument("--append", action="store_true",
                    help="add rows to an existing results.csv (run the matrix in several parts)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.ERROR)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rates = [float(r) for r in args.rates.split(",")]
    if args.quick:
        rates = [rates[-1]]
    wanted = set(args.scenarios.split(","))
    plan = []
    if "attack" in wanted:
        plan += [("attack", f"{'max' if r == 0 else int(r)} files/s", r) for r in rates]
    if "evasive" in wanted:
        plan.append(("evasive", "max files/s, skips bait", 0.0))
    if "benign" in wanted:
        benign = ["doc_editing", "bulk_copy"] if args.quick else [b for b in args.benign.split(",") if b in BENIGN]
        plan += [("benign", b, None) for b in benign]
    if "idle" in wanted:
        plan.append(("idle", "15 s" if not args.quick else "5 s", None))

    info = {"host": platform.node(), "platform": platform.platform(), "python": platform.python_version(),
            "sentinel": __version__, "cpus": psutil.cpu_count(), "date": time.strftime("%Y-%m-%d %H:%M")}
    rows: list[dict] = []
    csv_path = out / "results.csv"
    append = args.append and csv_path.exists()
    with open(csv_path, "a" if append else "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        if not append:
            writer.writeheader()
        for scen, variant, param in plan:
            for run in range(1, args.runs + 1):
                base = Path(tempfile.mkdtemp(prefix="sentinel-vm-"))
                try:
                    if scen == "attack":
                        r = run_attack(base, args.files, param, skip_hidden=False)
                    elif scen == "evasive":
                        r = run_attack(base, args.files, param, skip_hidden=True)
                    elif scen == "benign":
                        r = run_benign(base, args.files, variant)
                    else:
                        r = run_idle(base, args.files, 5 if args.quick else 15)
                finally:
                    shutil.rmtree(base, ignore_errors=True)
                r.update(scenario=scen, variant=variant, run=run)
                rows.append(r)
                writer.writerow(r)
                fh.flush()
                print(f"{scen:8} {variant:24} run {run}: detected={r['detected']} killed={r['killed']} "
                      f"encrypted={r.get('files_encrypted', '-')} signal@{r.get('time_to_signal_s', '-')}s "
                      f"decision@{r.get('time_to_verdict_s', '-')}s",
                      flush=True)
    print()
    print(summarize(load_rows(csv_path), out, info))
    return 0


def load_rows(csv_path: Path) -> list[dict]:
    """All rows of results.csv (including earlier --append parts), typed."""
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        for key in ("detected", "killed"):
            r[key] = r.get(key) == "True"
    return rows


if __name__ == "__main__":
    sys.exit(main())
