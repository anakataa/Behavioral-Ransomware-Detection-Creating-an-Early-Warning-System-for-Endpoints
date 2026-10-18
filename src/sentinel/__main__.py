"""CLI entrypoint.

    python -m sentinel run   [-c config.yaml] [--watch DIR ...] [--monitor-only]
    python -m sentinel canary {deploy,verify,remove} [-c config.yaml] [--watch DIR ...]
    python -m sentinel audit [-n 20] [--category verdict]
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import signal
import sys
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


def cmd_run(args: argparse.Namespace, cfg: config.Config) -> int:
    from .agent import Agent  # imports watchdog; keep `audit` usable without it

    if not cfg.watch_paths:
        print("error: no watch paths (set watch_paths in config or pass --watch)", file=sys.stderr)
        return 2
    agent = Agent(cfg)

    def _shutdown(signum, frame):
        raise KeyboardInterrupt
    for name in ("SIGTERM", "SIGBREAK"):  # service stop / Ctrl+Break on Windows
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _shutdown)

    mode = "MONITOR-ONLY" if not cfg.mitigation.enabled else "ACTIVE (will terminate)"
    print(f"Sentinel {__version__} - {mode}. Ctrl+C to stop.", flush=True)
    for p in cfg.watch_paths:
        print(f"  watching {p}", flush=True)
    agent.run_forever()
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
    return parser


def main(argv: list[str] | None = None) -> int:
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
