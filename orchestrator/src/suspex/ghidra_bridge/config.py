"""Config dataclass and manifest-path helper for ``suspex.ghidra_bridge``."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Manifest bookkeeping — a caller-restart survives if
# ``~/.suspex0/ghidra_sessions.json`` remembers which input paths were
# open. Same contract as the IDA manifest; separate file so the two
# engines' session namespaces never collide.
GHIDRA_MANIFEST_VERSION = 1


def _default_manifest_path() -> Path:
    """Where the Ghidra session manifest lands.

    Under ``~/.suspex0/`` beside ``ida_sessions.json``; overridable via
    ``SUSPX_GHIDRA_MANIFEST`` for tests.
    """
    override = os.environ.get("SUSPX_GHIDRA_MANIFEST")
    if override:
        return Path(override)
    return Path.home() / ".suspex0" / "ghidra_sessions.json"


@dataclass
class GhidraConfigLite:
    enabled: bool = False
    ghidra_dir: str = ""
    java_home: str = ""
    project_dir: str = ""
    project_name: str = "suspex"
    backend_python: str = ""
    heap_mb: int = 8192
    open_timeout_s: int = 300
    # Soft deadline for the synchronous `open` wrapper — same contract
    # as ida's open_soft_deadline_s: on expiry the in-flight tools/call
    # keeps running and the caller polls open_status(name).
    open_soft_deadline_s: float = 10.0
    command: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: Any) -> "GhidraConfigLite":
        defaults = cls()
        return cls(
            enabled=getattr(cfg, "enabled", False),
            ghidra_dir=getattr(cfg, "ghidra_dir", ""),
            java_home=getattr(cfg, "java_home", ""),
            project_dir=getattr(cfg, "project_dir", ""),
            project_name=getattr(cfg, "project_name", "suspex"),
            backend_python=getattr(cfg, "backend_python", ""),
            heap_mb=int(getattr(cfg, "heap_mb", defaults.heap_mb)),
            open_timeout_s=int(
                getattr(cfg, "open_timeout_s", defaults.open_timeout_s)),
            open_soft_deadline_s=float(
                getattr(cfg, "open_soft_deadline_s",
                        defaults.open_soft_deadline_s)),
            command=list(getattr(cfg, "command", []) or []),
        )
