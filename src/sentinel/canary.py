"""Canary (bait) files.

A hidden vault with decoy documents is planted in every watched
directory. No legitimate process has a reason to touch them, so any
modification, deletion or rename inside the vault is a strong signal.

Names start with ``!`` / ``0`` so they sort first: many ransomware
families walk directories alphabetically and hit the bait early.

Limitation: watchdog sees writes, renames and deletes — not reads.
Pure exfiltration-by-read of a canary is invisible in user space
(fanotify on Linux / ETW on Windows would close that gap).
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)

DECOY_NAMES = [
    "!_Passwords.txt", "!_Bank_Accounts.csv", "0_Invoice_2026_Q3.txt",
    "0_Payroll_Summary.csv", "0_Contracts_Index.txt", "!_Backup_Keys.txt",
    "0_Customer_List.csv", "0_Tax_Return_2025.txt", "!_VPN_Credentials.txt",
    "0_Board_Minutes.txt", "0_Salaries.csv", "!_Recovery_Codes.txt",
]


def _decoy_content(name: str) -> bytes:
    """Deterministic, low-entropy, plausible-looking content."""
    lines = [f"{name} - internal, do not distribute"]
    lines += [f"record {i:04d}; ref {name[:8]}-{i * 37 % 1000:03d}; status ok" for i in range(64)]
    return ("\n".join(lines) + "\n").encode()


def _hide(path: Path) -> None:
    if sys.platform == "win32":
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
    # On POSIX the leading dot of the vault name already hides it.


class CanaryManager:
    def __init__(self, watch_paths: list[Path], count: int = 12,
                 vault_dirname: str = ".sentinel_canary") -> None:
        self.watch_paths = [Path(p).resolve() for p in watch_paths]
        self.count = count
        self.vault_dirname = vault_dirname
        self._digests: dict[Path, str] = {}
        self._keys: list[str] | None = None

    @property
    def vaults(self) -> list[Path]:
        return [p / self.vault_dirname for p in self.watch_paths]

    @property
    def files(self) -> list[Path]:
        return list(self._digests)

    def deploy(self) -> list[Path]:
        """(Re)create every vault. Idempotent: rewrites known content."""
        names = [DECOY_NAMES[i] if i < len(DECOY_NAMES) else f"0_Archive_{i:02d}.txt"
                 for i in range(self.count)]
        self._digests.clear()
        for vault in self.vaults:
            if not vault.parent.is_dir():
                continue
            vault.mkdir(exist_ok=True)
            _hide(vault)
            for name in names:
                path = vault / name
                content = _decoy_content(name)
                if path.exists():
                    os.chmod(path, 0o644)
                path.write_bytes(content)
                self._digests[path] = hashlib.sha256(content).hexdigest()
        log.info("deployed %d canary files in %d vault(s)", len(self._digests), len(self.vaults))
        return self.files

    def remove(self) -> None:
        for vault in self.vaults:
            if not vault.is_dir():
                continue
            for f in vault.iterdir():
                if f.is_file():
                    f.unlink()
            vault.rmdir()
        self._digests.clear()

    def is_canary(self, path: Path) -> bool:
        """True if ``path`` is a canary file or lies inside a vault.

        Called on every FS event, so it is a pure string check — no
        ``resolve()`` syscall. Listener paths are already absolute and
        rooted at the resolved watch paths.
        """
        p = os.path.normcase(str(path))
        return any(p == v or p.startswith(v + os.sep) for v in self._vault_keys)

    @property
    def _vault_keys(self) -> list[str]:
        if self._keys is None:
            self._keys = [os.path.normcase(str(v)) for v in self.vaults]
        return self._keys

    def verify(self) -> list[Path]:
        """Return canaries that are missing or whose content changed.

        Backstop for events the listener might have dropped.
        """
        tampered = []
        for path, digest in self._digests.items():
            try:
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    tampered.append(path)
            except OSError:
                tampered.append(path)
        return tampered
