"""CLI entrypoint.

    python -m sentinel run   [-c config.yaml] [--watch DIR ...] [--monitor-only]
    python -m sentinel canary {deploy,verify,remove} [-c config.yaml] [--watch DIR ...]
    python -m sentinel audit [-n 20] [--category verdict]
    python -m sentinel dashboard [--port 8765] [--sandbox sandbox]
    python -m sentinel demo      [--port 8765] [--sandbox sandbox] [--monitor-only]
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__, config
from .audit import AuditLog
from .canary import CanaryManager


def _load(args: argparse.Namespace) -> config.Config:
    cfg = config.load(args.config)
    if getattr(args, "watch", None):
        cfg.watch_paths = [config.expand_path(p) for p in args.watch]
    if getattr(args, "db", None):
        cfg.audit_db = Path(args.db)
    if getattr(args, "monitor_only", False):
        cfg.mitigation.enabled = False
    if getattr(args, "no_canary", False):
        cfg.canary.enabled = False
    return cfg


def _install_shutdown_handlers() -> None:
    def _shutdown(signum, frame):
        raise KeyboardInterrupt
    for name in ("SIGTERM", "SIGBREAK"):  # service stop / Ctrl+Break on Windows
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _shutdown)


def _banner(cfg: config.Config) -> None:
    mode = "MONITOR-ONLY" if not cfg.mitigation.enabled else "ACTIVE (will terminate)"
    print(f"Sentinel {__version__} - {mode}. Ctrl+C to stop.", flush=True)
    for p in cfg.watch_paths:
        print(f"  watching {p}", flush=True)


def cmd_run(args: argparse.Namespace, cfg: config.Config) -> int:
    from .agent import Agent  # imports watchdog; keep `audit` usable without it

    if not cfg.watch_paths:
        print("error: no watch paths (set watch_paths in config or pass --watch)", file=sys.stderr)
        return 2
    agent = Agent(cfg)
    _install_shutdown_handlers()
    _banner(cfg)
    agent.run_forever()
    return 0


def cmd_dashboard(args: argparse.Namespace, cfg: config.Config) -> int:
    """Dashboard only: reads the DB of an agent started separately with `run`."""
    from .dashboard import serve

    httpd = serve(cfg.audit_db, Path(args.sandbox), args.port, files=args.files)
    _install_shutdown_handlers()
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Dashboard on {url} (audit db: {Path(cfg.audit_db).resolve()})", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def cmd_demo(args: argparse.Namespace, cfg: config.Config) -> int:
    """Agent watching the sandbox + dashboard, in one process, for live demos."""
    from .agent import Agent
    from .dashboard import serve

    sandbox = Path(args.sandbox).resolve()
    httpd = serve(cfg.audit_db, sandbox, args.port, files=args.files)  # creates the sandbox first
    cfg.watch_paths = [sandbox]  # never point the demo at real user folders
    # Only the simulator launched from the dashboard may be killed; any other
    # process the agent blames (a misattribution on a busy laptop) is alert-only.
    agent = Agent(cfg, kill_filter=httpd.attack.owns)
    print("Demo kill scope: only processes started by the dashboard's Launch attack button", flush=True)
    agent.start()
    threading.Thread(target=httpd.serve_forever, name="dashboard", daemon=True).start()
    _install_shutdown_handlers()
    _banner(cfg)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"Dashboard on {url}", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        agent.stop()
    return 0


def cmd_canary(args: argparse.Namespace, cfg: config.Config) -> int:
    mgr = CanaryManager(cfg.watch_paths, cfg.canary.count, cfg.canary.vault_dirname)
    if args.action == "remove":
        mgr.remove()
        print("canary vaults removed")
        return 0
    files = mgr.deploy()
    print(f"{len(files)} canary file(s) deployed")
    if args.action == "verify":
        tampered = mgr.verify()
        print("all intact" if not tampered else "\n".join(f"TAMPERED {p}" for p in tampered))
        return 1 if tampered else 0
    return 0


def cmd_audit(args: argparse.Namespace, cfg: config.Config) -> int:
    if not Path(cfg.audit_db).exists():
        print(f"no audit database at {cfg.audit_db}")
        return 1
    log = AuditLog(cfg.audit_db)
    for r in reversed(log.recent(args.n, args.category)):
        when = dt.datetime.fromtimestamp(r.ts).strftime("%Y-%m-%d %H:%M:%S")
        who = f" {r.process}[{r.pid}]" if r.pid else ""
        where = f" {r.path}" if r.path else ""
        print(f"{when} {r.level:<7} {r.category:<10} {r.message}{who}{where}")
    log.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default="config.yaml", help="YAML config (default: config.yaml)")
    common.add_argument("--watch", nargs="+", metavar="DIR", help="override watch_paths")
    common.add_argument("--db", help="override audit_db path")

    parser = argparse.ArgumentParser(prog="sentinel", description="Behavioral ransomware early-warning agent")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", parents=[common], help="start the agent")
    run.add_argument("--monitor-only", action="store_true", help="detect and log, never terminate")
    run.add_argument("--no-canary", action="store_true", help="don't deploy bait files")
    run.set_defaults(func=cmd_run)

    can = sub.add_parser("canary", parents=[common], help="manage bait files")
    can.add_argument("action", choices=["deploy", "verify", "remove"])
    can.set_defaults(func=cmd_canary)

    aud = sub.add_parser("audit", parents=[common], help="show the audit trail")
    aud.add_argument("-n", type=int, default=20, help="number of records")
    aud.add_argument("--category", choices=["signal", "verdict", "mitigation", "canary", "system"])
    aud.set_defaults(func=cmd_audit)

    for name, func, text in (("dashboard", cmd_dashboard, "serve the live dashboard (agent runs separately)"),
                             ("demo", cmd_demo, "agent on a sandbox + live dashboard, one command")):
        p = sub.add_parser(name, parents=[common], help=text)
        p.add_argument("--port", type=int, default=8765)
        p.add_argument("--sandbox", default="sandbox", help="mock-ransomware sandbox dir (default: ./sandbox)")
        p.add_argument("--files", type=int, default=300, help="synthetic documents in the sandbox")
        p.add_argument("--no-browser", action="store_true")
        if name == "demo":
            p.add_argument("--monitor-only", action="store_true", help="detect and log, never terminate")
        p.set_defaults(func=func)
    return parser


def _run_bundled_mock(args: list[str]) -> int:
    """Frozen builds only: run the bundled mock-ransomware simulator in this exe."""
    import runpy

    from .dashboard import MOCK

    sys.argv = [str(MOCK), *args]
    runpy.run_path(str(MOCK), run_name="__main__")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = sys.argv[1:] if argv is None else argv
    if raw and raw[0] == "_mock":  # hidden: used by `demo` in the Windows .exe build
        return _run_bundled_mock(raw[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    logging.basicConfig(level="DEBUG" if args.verbose else "INFO",
                        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    cfg = _load(args)
    if not args.verbose:
        logging.getLogger().setLevel(cfg.log_level)
    return args.func(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
