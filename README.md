<div align="center">

# Project Sentinel

### Behavioral Ransomware Detection: Creating an Early Warning System for Endpoints

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](<https://img.shields.io/badge/Status-Phase_2_(In_Progress)-yellow>)]()
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

```
┌─────────────────────────────────────────────────────────┐
│                 User-Space Agent (Python 3.12)          │
│                                                         │
│  ┌──────────┐   ┌─────────────┐   ┌──────────────────┐ │
│  │  Event    │──▶│  Metadata   │──▶│  Detection Engine │ │
│  │ Listener  │   │Preprocessor │   │  (Velocity +     │ │
│  │(watchdog) │   │             │   │   Entropy)       │ │
│  └──────────┘   └─────────────┘   └────────┬─────────┘ │
│                                             │           │
│       ┌─────────────────┐          ┌────────▼─────────┐ │
│       │  Canary Vault   │─ alert ─▶│   Mitigation     │ │
│       │ (Hidden Traps)  │          │ (psutil / os.kill)│ │
│       └─────────────────┘          └──────────────────┘ │
│                                             │           │
│                                    ┌────────▼─────────┐ │
│                                    │ Persistence Layer │ │
│                                    │   (SQLite3 Logs)  │ │
│                                    └──────────────────┘ │
├─────────────────────────────────────────────────────────┤
│            OS Kernel Layer (Windows / Linux)             │
│  ReadDirectoryChangesW  ·  inotify  ·  FSEvents          │
├─────────────────────────────────────────────────────────┤
│                  Local Data Sovereignty                   │
│         sentinel.db  ·  Canary Bait Directory             │
└─────────────────────────────────────────────────────────┘
```

</div>

> Full architecture diagram: [`assets/architecture.png`](assets/architecture.png)

### Key Design Decisions

- **User-space only** — no kernel drivers, no BSOD risk, no admin escalation required
- **100% offline** — no cloud dependency, no telemetry, full data sovereignty
- **< 1% CPU overhead** — event-driven (not polling), suitable for legacy hardware

## Dashboard

The project includes an interactive HTML dashboard prototype for real-time monitoring:

<div align="center">

**[▶ Open `dashboard/sentinel_dashboard.html` in any browser to try it live](dashboard/sentinel_dashboard.html)**

</div>

Features:

- Real-time I/O velocity and Shannon entropy charts
- Canary file integrity grid (12 bait files)
- Active process watchlist with kill controls
- Simulated ransomware attack demo (click _"Simulate attack"_)
- Full audit log with risk classification

## Project Structure

```
sentinel/
├── assets/
│   └── architecture.png       # System architecture diagram (Eraser.io)
├── dashboard/
│   └── sentinel_dashboard.html             # Interactive monitoring UI prototype
├── docs/
│   └── proposal.pdf           # Full coursework proposal (19 slides)
├── config.example.yaml        # Sample configuration with defaults
├── LICENSE                     # Apache 2.0
└── README.md
```

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
| **2. Architecture & Prototyping**  | 🔄 In Progress | System design, dashboard UI, core engine scaffolding              |
| **3. Sandbox Testing**             | 📋 Planned     | VirtualBox isolation, crypto-simulation scripts, threshold tuning |
| **4. Integration & Documentation** | 📋 Planned     | SQLite integration, resource profiling, final thesis document     |

--
