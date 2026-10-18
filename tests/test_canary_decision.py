from sentinel.canary import CanaryManager
from sentinel.decision import DecisionEngine, Signal, SignalKind, Whitelist
from sentinel.entropy import shannon_entropy


# -- canary ------------------------------------------------------------------
def test_canary_deploy_and_verify(tmp_path):
    mgr = CanaryManager([tmp_path], count=12)
    files = mgr.deploy()
    assert len(files) == 12
    assert all(f.parent.name == ".sentinel_canary" for f in files)
    assert all(shannon_entropy(f.read_bytes()) < 6 for f in files)  # decoys look like text
    assert mgr.verify() == []

    files[0].write_bytes(b"encrypted!")
    files[1].unlink()
    assert set(mgr.verify()) == {files[0], files[1]}


def test_canary_deploy_is_idempotent(tmp_path):
    mgr = CanaryManager([tmp_path], count=3)
    mgr.deploy()
    mgr.deploy()
    assert len(mgr.files) == 3
    assert mgr.verify() == []


def test_canary_more_than_name_list(tmp_path):
    mgr = CanaryManager([tmp_path], count=20)
    assert len(set(mgr.deploy())) == 20


def test_is_canary(tmp_path):
    mgr = CanaryManager([tmp_path], count=2)
    files = mgr.deploy()
    assert mgr.is_canary(files[0])
    assert mgr.is_canary(files[0].with_name(files[0].name + ".locked"))  # anything in the vault
    assert not mgr.is_canary(tmp_path / "normal.txt")


def test_canary_remove(tmp_path):
    mgr = CanaryManager([tmp_path], count=2)
    mgr.deploy()
    mgr.remove()
    assert not (tmp_path / ".sentinel_canary").exists()


# -- decision ----------------------------------------------------------------
def sig(kind, ts):
    return Signal(kind, 1.0, ts)


def test_single_signal_is_not_enough():
    eng = DecisionEngine(required_signals=2)
    assert eng.submit(sig(SignalKind.VELOCITY, 1.0)) is None
    assert eng.submit(sig(SignalKind.VELOCITY, 1.5)) is None  # same kind twice ≠ two signals


def test_two_distinct_signals_converge():
    eng = DecisionEngine(required_signals=2, correlation_window=10)
    eng.submit(sig(SignalKind.VELOCITY, 1.0))
    v = eng.submit(sig(SignalKind.ENTROPY, 2.0))
    assert v is not None and v.kinds == ["entropy", "velocity"]
    assert eng.active(2.0) == []  # reset after verdict


def test_signals_expire_outside_window():
    eng = DecisionEngine(required_signals=2, correlation_window=5)
    eng.submit(sig(SignalKind.CANARY, 1.0))
    assert eng.submit(sig(SignalKind.ENTROPY, 10.0)) is None


def test_aggressive_and_conservative_modes():
    assert DecisionEngine(1).submit(sig(SignalKind.CANARY, 0)) is not None
    eng = DecisionEngine(3)
    eng.submit(sig(SignalKind.CANARY, 0))
    assert eng.submit(sig(SignalKind.ENTROPY, 0)) is None
    assert eng.submit(sig(SignalKind.VELOCITY, 0)) is not None


def test_whitelist_case_insensitive():
    wl = Whitelist(["7z.exe", "rsync"])
    assert "7Z.EXE" in wl and "rsync" in wl
    assert "evil.exe" not in wl and None not in wl
