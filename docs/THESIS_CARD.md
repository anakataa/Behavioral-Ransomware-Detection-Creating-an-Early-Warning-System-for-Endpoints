# Thesis Work Card

## Title

**Behavioral Ransomware Detection: Creating an Early Warning System for Endpoints**

## Scope

The thesis covers the design and implementation of a lightweight, host-based
software agent that detects ransomware through behavioral analysis rather than
signature matching. The work includes:

- Real-time file system monitoring (I/O velocity analysis)
- Canary-file trap deployment and integrity monitoring
- Automated malicious process termination
- Validation against simulated ransomware in an isolated virtual environment

The agent targets endpoints in small and medium businesses (SMBs) and legacy
systems where enterprise EDR solutions are too costly or resource-heavy.

**Out of scope:** kernel-level drivers, cloud-based analysis, and protection
against non-encryption malware categories.

## Goal

To develop a proof-of-concept endpoint security agent in Python that detects
and halts zero-day ransomware in real time by monitoring abnormal
file-modification behavior, achieving early detection before encryption
completes, with minimal system overhead (< 1% CPU, < 50 MB RAM) and no
dependency on signature databases.
