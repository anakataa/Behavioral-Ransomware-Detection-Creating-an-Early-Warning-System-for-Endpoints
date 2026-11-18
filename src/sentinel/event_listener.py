"""File-system event listener (watchdog wrapper).

Watchdog picks the native backend per OS: inotify (Linux),
ReadDirectoryChangesW (Windows), FSEvents (macOS). It reports *what*
changed, never *who* changed it — process attribution is handled
separately in ``attribution.py``.

Raw watchdog events are normalized into ``FileEvent`` and pushed onto a
thread-safe queue, so the watchdog thread never blocks on analysis.
"""

from __future__ import annotations

import logging
import queue
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

log = logging.getLogger(__name__)


class EventKind(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"


@dataclass(frozen=True)
class FileEvent:
    kind: EventKind
    path: Path
    timestamp: float
    dest_path: Path | None = None   # set for MOVED

    @property
    def effective_path(self) -> Path:
        """Path that holds the file's content after the event."""
        return self.dest_path or self.path


_KIND_MAP = {
    "created": EventKind.CREATED,
    "modified": EventKind.MODIFIED,
    "deleted": EventKind.DELETED,
    "moved": EventKind.MOVED,
}


class _Handler(FileSystemEventHandler):
    def __init__(self, sink: "queue.Queue[FileEvent]", ignore: tuple[Path, ...]) -> None:
        self._sink = sink
        self._ignore = ignore

    def _ignored(self, path: Path) -> bool:
        return any(path == p or p in path.parents for p in self._ignore)

    def on_any_event(self, event: FileSystemEvent) -> None:
        kind = _KIND_MAP.get(event.event_type)
        if kind is None or event.is_directory:
            return  # opened/closed events and directory churn are noise here
        src = Path(_decode(event.src_path))
        dest = Path(_decode(event.dest_path)) if getattr(event, "dest_path", "") else None
        if self._ignored(src) and (dest is None or self._ignored(dest)):
            return
        self._sink.put(FileEvent(kind, src, time.monotonic(), dest))


def _decode(p: str | bytes) -> str:
    return p.decode(errors="replace") if isinstance(p, bytes) else p


if sys.platform == "win32":
    from watchdog.observers.read_directory_changes import WindowsApiEmitter

    class _PromptEmitter(WindowsApiEmitter):
        """Delivers ReadDirectoryChangesW results as soon as they arrive.

        watchdog >= 7 reads change buffers on a helper thread and only hands
        them over once none has arrived for ``timeout`` (1 s): while a
        process keeps writing, every event is held back until it pauses.
        Measured on Windows 10: a 2 s write burst was reported in one batch
        1 s after it ended; a 400-file mock attack, only after it finished —
        too late to attribute or stop anything. (watchdog 6, which Python
        3.10 still installs, delivers within milliseconds.)

        Here we wait for the first buffer, then take whatever is queued.
        On watchdog < 7 (no reader thread) the stock behaviour is kept.
        """

        def queue_events(self, timeout: float) -> None:
            reader = getattr(self, "_reader", None)
            buffers = getattr(reader, "_buf_queue", None)
            if not isinstance(buffers, queue.Queue):
                super().queue_events(timeout)
                return
            with buffers.not_empty:  # notified by every put(); doesn't consume
                if not buffers.queue:
                    buffers.not_empty.wait(timeout)
            super().queue_events(0)  # drain what is there, don't wait for silence

    def _observer() -> BaseObserver:
        return BaseObserver(_PromptEmitter)
else:
    def _observer() -> BaseObserver:
        return Observer()


class EventListener:
    """Watches a set of directories recursively and queues ``FileEvent``s.

    ``ignore_paths`` lets the agent exclude its own files (the audit DB,
    its journal) so it doesn't detect itself.
    """

    def __init__(
        self,
        watch_paths: Iterable[Path],
        ignore_paths: Iterable[Path] = (),
        maxsize: int = 100_000,
    ) -> None:
        self.watch_paths = [Path(p).resolve() for p in watch_paths]
        self.events: "queue.Queue[FileEvent]" = queue.Queue(maxsize=maxsize)
        ignore = tuple(Path(p).resolve() for p in ignore_paths)
        self._handler = _Handler(self.events, ignore)
        self._observer = _observer()

    def start(self) -> None:
        if not self.watch_paths:
            raise ValueError("no watch paths configured")
        for path in self.watch_paths:
            if not path.is_dir():
                log.warning("watch path %s does not exist, skipping", path)
                continue
            self._observer.schedule(self._handler, str(path), recursive=True)
            log.info("watching %s", path)
        self._observer.start()

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)

    def get(self, timeout: float | None = None) -> FileEvent | None:
        try:
            return self.events.get(timeout=timeout)
        except queue.Empty:
            return None
