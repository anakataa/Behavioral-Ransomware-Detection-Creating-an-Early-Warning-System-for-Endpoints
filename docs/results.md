# Evaluation results

Raw data for Chapter V of the thesis. Every number below comes from the
safe simulator `scripts/mock_ransomware.py` on 400 synthetic 16 KiB
documents, produced by `scripts/vm/run_matrix.py` (3 runs per scenario
unless stated otherwise). Reproduce with:

```bash
python scripts/vm/run_matrix.py --runs 3 --rates 20,50,100,200,400,0
```

## 1. Ubuntu 22.04 virtual machine — 17 Nov 2026

Environment: Ubuntu 22.04.5 LTS VM, 2 vCPU, 4 GB RAM, Python 3.10.12,
Sentinel 0.1.0, agent in active mode (attacks) or monitor-only (benign).
Raw rows: [`results-ubuntu-22.04.csv`](results-ubuntu-22.04.csv).

### Attacks

| Simulator speed | Detected | Stopped | Files encrypted (mean of 3) | First signal | Decision |
|---|---|---|---|---|---|
| 20 files/s | 3/3 | 3/3 | 14 / 400 (3.5 %) | 0.03 s | 1.34 s |
| 50 files/s | 3/3 | 3/3 | 31 / 400 (7.9 %) | 0.02 s | 0.92 s |
| 100 files/s | 3/3 | 3/3 | 70 / 400 (17.4 %) | 0.02 s | 0.93 s |
| 200 files/s | 3/3 | 3/3 | 133 / 400 (33.2 %) | 0.03 s | 0.93 s |
| 400 files/s | 3/3 | 3/3 | 231 / 400 (57.9 %) | 0.03 s | 0.93 s |
| maximum (≈ 850 files/s) | 3/3 | **0/3** | 399 / 400 | 0.03 s | 0.93 s |
| maximum, skipping bait files | 3/3 | **0/3** | 399 / 400 | 0.03 s | 0.93 s |

*First signal*: time from attack start to the first detector firing.
*Decision*: time to the logged verdict, after the two attribution windows.

**Finding 1 — detection is fast, response is bounded by attribution.**
Detection takes about 25 ms in every run. The verdict, however, is only
issued after process attribution: a 0.3 s first window plus a 0.6 s
confirmation window. Files lost therefore grow roughly linearly with
attack speed (≈ speed × 0.6–0.9 s). At 20 files/s the decision takes
longer (1.34 s) because the velocity threshold (50 files/s) is never
reached and the entropy detector needs several high-entropy files first.

**Finding 2 — on Linux the fastest attack finishes before attribution.**
At maximum speed the simulator encrypts all 400 files in 0.47 s (Linux
writes go to the page cache). By the time the confirmation window closes
the process has already exited, so no process can be identified and the
agent alerts without killing (`no process consistently accounts for the
writes`). On the Windows development machine the same simulator ran
much slower and was stopped (section 2). This is the main measured
limitation of the user-space design; a kernel-level PID source (fanotify
on Linux, a minifilter or ETW on Windows) or a shorter, adaptive
confirmation window are the documented future-work paths.

**Finding 3 — bait files are not required for detection.** With bait
files skipped, velocity + entropy alone reached the 2-of-3 rule in
0.03 s in every run.

### Legitimate workloads (false positives)

| Workload | Runs with a verdict |
|---|---|
| Normal document editing (30 saves) | 0/3 |
| Copying a folder of 400 documents | 0/3 |
| Creating one zip archive of the documents | 0/3 |
| Compressing every document in place with gzip | **3/3** |

**Finding 4 — in-place compression looks like ransomware.** Rewriting
every document as compressed data produces exactly the signals
Sentinel looks for: high speed and high entropy. This is the expected
false positive of behavioral detection; the mitigation is the trusted
program list (7-Zip, WinRAR, backup tools) plus watch-only mode on a
new machine. The whitelist currently matches by process name only;
matching by signature and path is planned.

### Overhead

Agent idle on a watched folder for 15 s (3 runs): **0.48 % CPU** of the
machine, **25.5 MB** resident memory (measured for the whole runner
process, so an upper bound for the agent).

### Test suite

42/42 tests pass on this VM (3 consecutive runs, ~21 s each) after the
fixes below.

### Defects found by the Linux run and fixed

| Defect | Fix |
|---|---|
| `%USERNAME%`-style paths in `config.yaml` were only expanded on Windows (`os.path.expandvars` ignores `%VAR%` on POSIX) | `config.expand_path` expands `%VAR%` explicitly on every OS |
| Kill tests used an unbounded simulator, which on Linux finishes before attribution (Finding 2), so they tested a race instead of the kill pipeline | Kill tests run the simulator at 200 files/s; the unbounded race is measured by `run_matrix.py` |
| On POSIX the tests' agent runs in the simulator's parent process, so `psutil.wait_procs` reaps the killed child and `Popen` reports exit status 0 | Tests assert on the simulator's output and the audit log instead of the exit status on POSIX |

## 2. Windows 10 development machine — Oct 2026

Not an isolated VM: the developer's own laptop with background
applications running. Python 3.14.

- Simulator at maximum speed: stopped after **21 of 400** files with
  single-window attribution, **39 of 400** after the read + write,
  two-window attribution was introduced.
- Bait + entropy signals converged **≈ 80 ms** after the first bait
  file was rewritten; termination followed **≈ 0.3 s** later.
- Monitor-only, 12 attacks at 10, 20 and maximum files/s with a busy
  machine (browser, game launcher): **0 wrong decisions in 68 verdicts**.
  One run at 10 files/s ended as alert-only (no consistent writer).
- Process scan per sampling cycle optimised from 594 ms to 10 ms.
- Rejected approach: correlating per-process write curves with file
  changes over time — for a steady attack the correlation was noise
  (r between −0.10 and 0.69).

## 3. Windows and Ubuntu CI virtual machines

`.github/workflows/ci.yml` runs the test suite on fresh Windows Server
and Ubuntu 22.04 VMs (Python 3.10 and 3.12) on every push, then the full
evaluation matrix on both. Each run's `summary.md` appears on the
workflow page and as a downloadable artifact. Copy the Windows summary
here as section 3 once the first run completes.

The release workflow additionally builds `sentinel.exe` and runs
`scripts/vm/smoke_exe.py` on a clean Windows VM: the executable starts
its demo, launches the bundled simulator and must stop it. The same
smoke test passed for the Linux build on 17 Nov 2026 (stopped after
68 of 300 files at 100 files/s).
