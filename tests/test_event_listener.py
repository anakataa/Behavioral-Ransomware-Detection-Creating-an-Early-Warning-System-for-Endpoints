"""Event delivery latency: detection is only as fast as the events reach the agent."""

import os
import time

from sentinel.event_listener import EventListener


def test_events_arrive_while_writes_continue(tmp_path):
    """Regression: watchdog 7 on Windows held every event back until the
    writer paused for 1 s, so a running attack was invisible to the agent."""
    listener = EventListener([tmp_path])
    listener.start()
    try:
        start = time.monotonic()
        first = None
        for i in range(60):  # ~2 s of continuous writes, never pausing for long
            (tmp_path / f"f{i}.bin").write_bytes(os.urandom(4096))
            time.sleep(0.025)
            if first is None and listener.events.qsize():
                first = time.monotonic() - start
    finally:
        listener.stop()
    assert first is not None, "no event was delivered while the writes were still going on"
    assert first < 0.5, f"first event took {first:.2f}s"
