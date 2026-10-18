"""Decision engine — k-of-n signal convergence + process whitelist.

Each detector emits a ``Signal`` when it fires. A signal stays "hot"
for ``correlation_window`` seconds. A ``Verdict`` (= kill decision) is
issued when at least ``k`` *distinct* signal kinds are hot at once.

Canary hits are always reported as alerts, but by default still need a
second signal before the engine authorizes termination — this keeps
the 2-of-3 rule uniform and is the knob tuned in Phase 4.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class SignalKind(str, Enum):
    VELOCITY = "velocity"
    ENTROPY = "entropy"
    CANARY = "canary"


@dataclass(frozen=True)
class Signal:
    kind: SignalKind
    value: float
    ts: float = field(default_factory=time.monotonic)
    path: Path | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Verdict:
    signals: tuple[Signal, ...]
    ts: float

    @property
    def kinds(self) -> list[str]:
        return sorted(s.kind.value for s in self.signals)

    @property
    def reason(self) -> str:
        return " + ".join(f"{s.kind.value}={s.value:.2f}" for s in self.signals)


class DecisionEngine:
    def __init__(self, required_signals: int = 2, correlation_window: float = 10.0) -> None:
        if not 1 <= required_signals <= len(SignalKind):
            raise ValueError(f"required_signals must be 1..{len(SignalKind)}")
        self.required = required_signals
        self.window = correlation_window
        self._hot: dict[SignalKind, Signal] = {}

    def submit(self, signal: Signal) -> Verdict | None:
        """Register a fired signal; return a Verdict if the quorum is met.

        The engine resets after a verdict so one attack burst produces
        one decision; if the attack continues, signals re-accumulate.
        """
        self._hot[signal.kind] = signal
        self._expire(signal.ts)
        if len(self._hot) >= self.required:
            verdict = Verdict(tuple(self._hot.values()), signal.ts)
            self._hot.clear()
            return verdict
        return None

    def active(self, now: float | None = None) -> list[SignalKind]:
        self._expire(time.monotonic() if now is None else now)
        return list(self._hot)

    def _expire(self, now: float) -> None:
        for kind, sig in list(self._hot.items()):
            if now - sig.ts > self.window:
                del self._hot[kind]

    def reset(self) -> None:
        self._hot.clear()


class Whitelist:
    """Case-insensitive process-name allow list (``7z.exe``, ``rsync``...)."""

    def __init__(self, names: Iterable[str]) -> None:
        self._names = {n.lower() for n in names}

    def __contains__(self, name: str | None) -> bool:
        return bool(name) and name.lower() in self._names

    def __len__(self) -> int:
        return len(self._names)
