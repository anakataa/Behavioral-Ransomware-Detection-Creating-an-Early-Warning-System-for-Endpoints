#!/usr/bin/env python3
"""Mock ransomware — a SAFE behavioral simulator for testing Sentinel.

It reproduces the observable behavior of crypto-ransomware:
  * walks a directory tree (alphabetically, hidden dirs included),
  * overwrites each file with high-entropy bytes (XOR with a random
    keystream — not real crypto, there is no key to recover),
  * renames it to ``*.locked`` and drops a ransom note.

Safety rails:
  * It only ever operates inside a sandbox directory that it created
    itself, recognised by a marker file. Any other path is refused.
  * It never follows symlinks out of the sandbox.
  * Files are synthetic; ``setup`` regenerates them at any time.

Usage:
    python scripts/mock_ransomware.py setup   --target sandbox --files 200
    python scripts/mock_ransomware.py encrypt --target sandbox [--rate 0] [--skip-hidden]
    python scripts/mock_ransomware.py clean   --target sandbox
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import sys
import time
from pathlib import Path

MARKER = ".mock_ransomware_sandbox"
NOTE = "README_RESTORE_FILES.txt"
EXT = ".locked"
WORDS = ("invoice report budget meeting notes client project draft summary "
         "quarter revenue plan schedule contract review final status update").split()


def _is_sandbox(target: Path) -> bool:
    return (target / MARKER).is_file()


def _require_sandbox(target: Path) -> None:
    if not _is_sandbox(target):
        sys.exit(f"refusing: {target} is not a mock-ransomware sandbox (no {MARKER}). Run `setup` first.")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def setup(target: Path, files: int, size_kb: int, seed: int) -> None:
    if target.exists() and any(target.iterdir()) and not _is_sandbox(target):
        sys.exit(f"refusing: {target} exists, is not empty and is not a sandbox")
    if _is_sandbox(target):
        clean(target, keep=True)
    target.mkdir(parents=True, exist_ok=True)
    (target / MARKER).write_text("created by scripts/mock_ransomware.py - safe to delete\n")

    rng = random.Random(seed)
    subdirs = ["Documents", "Finance", "Projects", "Photos"]
    for d in subdirs:
        (target / d).mkdir(exist_ok=True)
    for i in range(files):
        d = target / subdirs[i % len(subdirs)]
        text, length = [], 0
        while length < size_kb * 1024:
            word = rng.choice(WORDS)
            text.append(word)
            length += len(word) + 1
        (d / f"{rng.choice(WORDS)}_{i:04d}.txt").write_text(" ".join(text))
    print(f"sandbox ready: {files} files x {size_kb} KiB in {target}")


def clean(target: Path, keep: bool = False) -> None:
    _require_sandbox(target)
    for child in target.iterdir():
        if child.name == MARKER:
            continue
        if child.name.startswith(".sentinel"):
            continue  # agent-owned canary vault: leave it to the agent
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    if not keep:
        (target / MARKER).unlink()
        try:
            target.rmdir()
        except OSError:
            pass
    print(f"sandbox {'reset' if keep else 'removed'}: {target}")


def _victims(target: Path, skip_hidden: bool):
    for root, dirs, files in os.walk(target, followlinks=False):
        dirs.sort()
        if skip_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in sorted(files):
            if name in (MARKER, NOTE) or name.endswith(EXT):
                continue
            path = Path(root) / name
            if path.is_symlink() or not _inside(path, target):
                continue
            yield path


def encrypt(target: Path, rate: float, skip_hidden: bool, delay: float) -> None:
    _require_sandbox(target)
    if delay:
        print(f"waiting {delay}s before attack...")
        time.sleep(delay)
    print(f"[pid {os.getpid()}] encrypting {target} (rate={'max' if not rate else f'{rate}/s'})", flush=True)
    start = time.perf_counter()
    count = 0
    for path in _victims(target, skip_hidden):
        try:
            data = path.read_bytes()
            key = os.urandom(len(data))
            locked = path.with_name(path.name + EXT)
            locked.write_bytes(bytes(a ^ b for a, b in zip(data, key)))
            path.unlink()
        except OSError as exc:
            print(f"  skip {path}: {exc}")
            continue
        count += 1
        if count % 25 == 0:
            print(f"  {count} files encrypted", flush=True)
        if rate:
            time.sleep(1.0 / rate)
    (target / NOTE).write_text("Your files are encrypted. (This is a Sentinel test - nothing was harmed.)\n")
    elapsed = time.perf_counter() - start
    print(f"done: {count} files in {elapsed:.2f}s - Sentinel did NOT stop this run", flush=True)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("setup", "encrypt", "clean"):
        s = sub.add_parser(name)
        s.add_argument("--target", type=Path, default=Path("sandbox"))
        if name == "setup":
            s.add_argument("--files", type=int, default=200)
            s.add_argument("--size-kb", type=int, default=16)
            s.add_argument("--seed", type=int, default=42)
        if name == "encrypt":
            s.add_argument("--rate", type=float, default=0, help="files/sec, 0 = as fast as possible")
            s.add_argument("--skip-hidden", action="store_true", help="don't enter hidden dirs (evades canaries)")
            s.add_argument("--delay", type=float, default=0, help="seconds to wait before starting")
    a = p.parse_args()
    target = a.target.resolve()
    if a.cmd == "setup":
        setup(target, a.files, a.size_kb, a.seed)
    elif a.cmd == "encrypt":
        encrypt(target, a.rate, a.skip_hidden, a.delay)
    else:
        clean(target)


if __name__ == "__main__":
    main()
