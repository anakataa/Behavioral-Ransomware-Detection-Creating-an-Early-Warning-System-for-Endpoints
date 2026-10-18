import os

import pytest

from sentinel.entropy import EntropyDetector, sample_file, shannon_entropy
from sentinel.velocity import VelocityDetector


# -- velocity ----------------------------------------------------------------
def test_velocity_rate_counts_events_in_window():
    v = VelocityDetector(threshold=5, window=1.0)
    for i in range(4):
        v.record(10.0 + i * 0.1)
    assert v.rate(10.35) == 4
    assert not v.triggered(10.35)


def test_velocity_triggers_above_threshold():
    v = VelocityDetector(threshold=50, window=1.0)
    for i in range(60):
        v.record(i / 100)  # 60 events in 0.6 s
    assert v.triggered(0.6)


def test_velocity_evicts_old_events():
    v = VelocityDetector(threshold=5, window=1.0)
    for i in range(10):
        v.record(i * 0.01)
    assert v.rate(0.1) == 10
    assert v.rate(5.0) == 0


def test_velocity_rejects_bad_params():
    with pytest.raises(ValueError):
        VelocityDetector(threshold=0)


# -- entropy -----------------------------------------------------------------
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


def test_entropy_text_vs_random():
    text = ("the quick brown fox jumps over the lazy dog " * 200).encode()
    assert shannon_entropy(text) < 5.0
    assert shannon_entropy(os.urandom(4096)) > 7.9


def test_sample_file_reads_middle(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"A" * 1000 + b"B" * 1000 + b"C" * 1000)
    assert sample_file(f, 1000) == b"B" * 1000
    assert sample_file(tmp_path / "missing", 10) is None


def test_entropy_detector_needs_min_files(tmp_path):
    det = EntropyDetector(threshold=7.5, min_files=3, window=5.0)
    for i in range(2):
        p = tmp_path / f"enc{i}"
        p.write_bytes(os.urandom(4096))
        det.observe(p, ts=1.0 + i)
    assert not det.triggered(3.0)
    p = tmp_path / "enc2"
    p.write_bytes(os.urandom(4096))
    det.observe(p, ts=3.0)
    assert det.triggered(3.0)
    assert not det.triggered(20.0)  # hits expire


def test_entropy_detector_ignores_text_and_tiny_files(tmp_path):
    det = EntropyDetector(min_files=1)
    t = tmp_path / "doc.txt"
    t.write_text("hello world " * 500)
    assert det.observe(t) < 5
    tiny = tmp_path / "tiny"
    tiny.write_bytes(os.urandom(100))
    assert det.observe(tiny) is None
    assert not det.triggered()


def test_entropy_same_file_counted_once(tmp_path):
    det = EntropyDetector(min_files=2)
    p = tmp_path / "enc"
    p.write_bytes(os.urandom(4096))
    det.observe(p, ts=1.0)
    det.observe(p, ts=1.1)
    assert det.hit_count(1.2) == 1
