"""YAML configuration loader.

Every field has a default, so the agent runs with no config file at all.
The YAML layout mirrors ``config.example.yaml`` in the repo root.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


@dataclass
class DetectionConfig:
    velocity_threshold: float = 50.0      # events / second
    velocity_window: float = 1.0          # seconds
    entropy_threshold: float = 7.5        # bits / byte (0..8)
    entropy_sample_bytes: int = 4096
    entropy_min_files: int = 3            # high-entropy writes needed inside entropy_window
    entropy_window: float = 5.0           # seconds
    confirmation_signals: int = 2         # k in "k of 3"
    correlation_window: float = 10.0      # seconds a fired signal stays "hot"


@dataclass
class CanaryConfig:
    enabled: bool = True
    count: int = 12
    vault_dirname: str = ".sentinel_canary"


@dataclass
class MitigationConfig:
    enabled: bool = True
    whitelist: list[str] = field(default_factory=lambda: [
        "7z.exe", "7zG.exe", "WinRAR.exe", "veracrypt.exe", "MsMpEng.exe",
        "tar", "gzip", "rsync",
    ])
    kill_grace_period: float = 0.5


@dataclass
class Config:
    watch_paths: list[Path] = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    canary: CanaryConfig = field(default_factory=CanaryConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)
    audit_db: Path = Path("sentinel_audit.db")
    log_level: str = "INFO"


def expand_path(raw: str | os.PathLike[str]) -> Path:
    """Expand ``~``, ``$VAR`` and Windows-style ``%VAR%`` placeholders."""
    return Path(os.path.expandvars(os.path.expanduser(str(raw))))


def _build(cls: type, data: dict[str, Any] | None, section: str):
    """Instantiate a section dataclass, warning about unknown keys."""
    data = data or {}
    known = {f.name for f in fields(cls)}
    for key in data.keys() - known:
        log.warning("config: unknown key '%s.%s' ignored", section, key)
    return cls(**{k: v for k, v in data.items() if k in known})


def from_dict(raw: dict[str, Any]) -> Config:
    cfg = Config(
        detection=_build(DetectionConfig, raw.get("detection"), "detection"),
        canary=_build(CanaryConfig, raw.get("canary"), "canary"),
        mitigation=_build(MitigationConfig, raw.get("mitigation"), "mitigation"),
    )
    cfg.watch_paths = [expand_path(p) for p in raw.get("watch_paths") or []]
    if "audit_db" in raw:
        cfg.audit_db = expand_path(raw["audit_db"])
    if "log_level" in raw:
        cfg.log_level = str(raw["log_level"]).upper()
    validate(cfg)
    return cfg


def load(path: str | os.PathLike[str] | None) -> Config:
    """Load config from YAML; ``None`` or a missing file yields defaults."""
    if path is None or not Path(path).exists():
        if path is not None:
            log.warning("config file %s not found, using defaults", path)
        cfg = Config()
        validate(cfg)
        return cfg
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return from_dict(raw)


def validate(cfg: Config) -> None:
    d = cfg.detection
    if d.velocity_threshold <= 0 or d.velocity_window <= 0:
        raise ValueError("velocity_threshold and velocity_window must be > 0")
    if not 0 < d.entropy_threshold <= 8:
        raise ValueError("entropy_threshold must be in (0, 8]")
    if d.entropy_sample_bytes <= 0:
        raise ValueError("entropy_sample_bytes must be > 0")
    if not 1 <= d.confirmation_signals <= 3:
        raise ValueError("confirmation_signals must be 1, 2 or 3")
    if cfg.canary.count < 0:
        raise ValueError("canary.count must be >= 0")
