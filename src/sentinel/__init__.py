"""Sentinel — behavioral ransomware early-warning agent for endpoints.

Pipeline:  watchdog events -> {velocity, entropy, canary} detectors
           -> decision engine (k-of-n convergence + whitelist)
           -> mitigation (psutil) + audit (SQLite).
"""

__version__ = "0.1.0"
