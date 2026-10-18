<div align="center">

# Project Sentinel

### Behavioral Ransomware Detection: Creating an Early Warning System for Endpoints

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](<https://img.shields.io/badge/Status-Phase_3_(In_Progress)-yellow>)]()
[![Platform](https://img.shields.io/badge/Platform-Windows_|_Linux_|_macOS-lightgrey)]()

_A lightweight, signature-less endpoint agent that detects ransomware by its **actions** — not its identity._

[Proposal PDF](docs/proposal.pdf) · [Architecture](#architecture) · [Dashboard Demo](#dashboard) · [Roadmap](#roadmap)

</div>

---

## The Problem

Traditional signature-based antivirus solutions **fail against zero-day ransomware**. Enterprise EDR platforms (CrowdStrike, SentinelOne) solve this but cost thousands of dollars and consume heavy system resources — leaving **small and medium businesses unprotected**.

Sentinel fills this gap: a **free, open-source, behavioral detection agent** that monitors file system activity in real time and terminates malicious processes before encryption completes.

## How It Works

Instead of scanning files for known virus signatures, Sentinel monitors **how processes behave**:

| Detection Method         | What It Catches                                                             |
| ------------------------ | --------------------------------------------------------------------------- |
| **I/O Velocity**         | Mass file modifications (>50 files/sec) impossible for normal user activity |
| **Shannon Entropy**      | Encrypted output approaches maximum randomness (~8.0 bits/byte)             |
| **Canary Trap Files**    | Hidden bait files that no legitimate process should ever touch              |
| **Process Whitelisting** | Trusted tools (7-Zip, VeraCrypt) are excluded from false positives          |

When thresholds are exceeded, the agent **automatically terminates the offending process** via `psutil` — stopping ransomware mid-encryption.

## Architecture

<div align="center">

![Architecture](assets/sentinel_arch.png)

</div>

### Key Design Decisions

- **User-space only** — no kernel drivers, no BSOD risk, no admin escalation required
- **100% offline** — no cloud dependency, no telemetry, full data sovereignty
- **< 1% CPU overhead** — event-driven (not polling), suitable for legacy hardware

## Dashboard

The project includes an interactive HTML dashboard prototype for real-time monitoring:

<div align="center">

**Live demo — one command:** `python -m sentinel demo` → opens `http://127.0.0.1:8765/`

</div>

The dashboard is wired to the real agent: everything on it is read from the local
audit DB (`audit_log` events + a 4 Hz `metrics` table the agent writes).

- Real-time I/O velocity and Shannon entropy charts with detection thresholds
- Canary file integrity grid and the currently "hot" signals (2 of 3 needed to kill)
- **Launch attack** button: runs `scripts/mock_ransomware.py` against the demo sandbox
  (standard or stealth profile, 10 / 20 / 60 files/s or max) — watch the agent detect and kill it
- Attack panel: plaintext vs. encrypted documents, time to kill, outcome
- Attribution panel: which process the agent blamed, with its write/read ratios
- Full audit log with risk classification

`sentinel demo` points the agent **only at the sandbox** (default `./sandbox`) and
**only kills the simulator launched by the dashboard's button** (and its child
processes) — any other process the agent blames stays alert-only, so a
misattribution on a busy presentation laptop can't take down a real application.
Add `--monitor-only` to rehearse without terminating anything. To watch an agent
started separately (`sentinel run`), use `python -m sentinel dashboard` against the same `--db`.
The server binds to 127.0.0.1 only; the attack/reset endpoints require a custom
header, so other web pages can't trigger them.

## Project Structure

```
sentinel/
├── src/sentinel/
│   ├── event_listener.py      # watchdog wrapper -> normalized FileEvent queue
│   ├── velocity.py            # sliding-window I/O rate detector
│   ├── entropy.py             # Shannon entropy detector (4 KiB mid-file sample)
│   ├── canary.py              # hidden bait-file vaults + integrity sweep
│   ├── decision.py            # k-of-n signal convergence + whitelist
│   ├── attribution.py         # "who is writing?" — per-process write accounting
│   ├── mitigation.py          # suspend -> terminate -> kill the process tree
│   ├── audit.py               # SQLite audit trail
│   ├── config.py              # YAML config loader with defaults
│   ├── agent.py               # wires the pipeline together
│   ├── dashboard.py           # local HTTP server: live dashboard + demo attack API
│   └── __main__.py            # CLI: run | canary | audit | dashboard | demo
├── scripts/
│   └── mock_ransomware.py     # SAFE behavioral simulator (sandbox-only)
├── tests/                     # unit tests + end-to-end agent-vs-mock tests
├── assets/
│   └── architecture.png       # System architecture diagram (Eraser.io)
├── dashboard/
│   └── sentinel_dashboard.html             # Interactive monitoring UI prototype
├── docs/
│   └── proposal.pdf           # Full coursework proposal (19 slides)
├── config.example.yaml        # Sample configuration with defaults
├── pyproject.toml
├── LICENSE                     # Apache 2.0
└── README.md
```

## Quick Start

```bash
python -m venv .venv && .venv\Scripts\activate      # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"

# 1. Build a disposable sandbox of synthetic documents
python scripts/mock_ransomware.py setup --target sandbox --files 300

# 2. Start the agent on it (second terminal)
python -m sentinel run --watch sandbox              # add --monitor-only to never kill

# 3. Launch the simulated attack
python scripts/mock_ransomware.py encrypt --target sandbox

# 4. Inspect what happened
python -m sentinel audit
```

Typical result on a Windows 10 laptop: canary + entropy converge ~80 ms after
the first bait file is hit, the simulator is terminated ~0.3 s later, with
**~5–9 % of the files encrypted** (21/400, 26/300 in test runs).

Run the test suite with `pytest` (end-to-end tests launch the simulator
against a live agent).

### How the agent decides whom to kill

`watchdog` reports *what* changed, never *who*. Without a kernel driver the agent
attributes the burst from user space (`attribution.py`): per-process I/O counters
are sampled (10 Hz while a burst is suspected). The culprit must have **written**
0.9–4× the bytes observed changing in the watched folders, and — because
crypto-ransomware has to read what it encrypts — **read** 0.5–8× of it too. The match
must hold in two consecutive windows (burst start, then a 0.6 s confirm window).
No match, two equally plausible matches, or a whitelisted best match → **alert only,
no kill**. Measured on a busy desktop (browser, Steam, IDE running): 0 wrong
decisions in 68 verdicts across 12 attacks at 10–max files/s.

## Tech Stack

| Component           | Technology            | Purpose                                                      |
| ------------------- | --------------------- | ------------------------------------------------------------ |
| Core Language       | Python 3.10+          | Rapid prototyping, cross-platform                            |
| File Monitoring     | `watchdog`            | Event-driven FS monitoring (inotify / ReadDirectoryChangesW) |
| Process Control     | `psutil`              | Process inspection and termination                           |
| Entropy Math        | `math` (stdlib)       | Shannon entropy calculation                                  |
| Audit Storage       | `sqlite3` (stdlib)    | Local-only event logging                                     |
| Dashboard           | HTML / CSS / Chart.js | Admin UI prototype                                           |
| Testing Environment | VirtualBox            | Isolated sandbox for safe ransomware simulation              |

## Competitive Positioning

| Feature            | Traditional AV     | Enterprise EDR           | **Sentinel**                   |
| ------------------ | ------------------ | ------------------------ | ------------------------------ |
| Zero-Day Detection | ❌ Signature-based | ✅ Behavioral + cloud AI | ✅ **Behavioral I/O + Canary** |
| Cloud Dependency   | Partial            | High                     | **None (100% offline)**        |
| System Impact      | Medium             | High                     | **Minimal (< 1% CPU)**         |
| Cost               | Subscription       | $10,000+/yr              | **Free (open-source)**         |
| Target             | General consumers  | Large enterprises        | **SMBs & legacy systems**      |

## Roadmap

| Phase                              | Status         | Description                                                       |
| ---------------------------------- | -------------- | ----------------------------------------------------------------- |
| **1. Research & Analysis**         | ✅ Done        | Threat landscape, competitive matrix, mathematical foundations    |
| **2. Architecture & Prototyping**  | ✅ Done        | System design, dashboard UI, core engine (`src/sentinel/`)        |
| **3. Sandbox Testing**             | 🔄 In Progress | VirtualBox isolation, crypto-simulation scripts, threshold tuning |
| **4. Integration & Documentation** | 📋 Planned     | SQLite integration, resource profiling, final thesis document     |
