"""Config dataclass and manifest-path helper for ``suspex.ida_bridge``."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# v0.17 C1-4: manifest bookkeeping — a caller-restart survives if
# ``~/.suspex0/ida_sessions.json`` remembers which input paths were
# open. On the first session-scoped call after a cold start the
# bridge lazily re-opens the DB rather than raising an unknown-name
# error. Version integer means we can grow the shape without silently
# consuming a stale file.
IDA_MANIFEST_VERSION = 1


def _default_manifest_path() -> Path:
    """Where the IDA session manifest lands.

    Under ``~/.suspex0/`` so it sits beside the other orchestrator
    persistent state (findings ledger etc.). Overridable via the
    ``SUSPX_IDA_MANIFEST`` env var; unit tests point that at a
    ``tmp_path`` fixture to avoid touching the user's real
    directory (``_shared.md`` §0.9 test-isolation contract).
    """
    override = os.environ.get("SUSPX_IDA_MANIFEST")
    if override:
        return Path(override)
    return Path.home() / ".suspex0" / "ida_sessions.json"


@dataclass
class IdaConfigLite:
    enabled: bool = True
    ida_path: str = ""
    command: list[str] = field(default_factory=lambda: ["uv", "run", "idalib-mcp", "--stdio"])
    prefer_gui: bool = False
    open_timeout_s: int = 180
    # Soft deadline for the synchronous `open_database` wrapper. If the shim
    # doesn't answer idb_open within this many seconds, the wrapper leaves the
    # in-flight tools/call running (asyncio.shield -- cancelling it would tear
    # the shim's SSE stream) and returns the same pending envelope that
    # open_database_async would have produced, so callers with tight gRPC
    # deadlines transparently fall back to polling open_status(name).
    open_soft_deadline_s: float = 8.0

    @classmethod
    def from_config(cls, cfg: Any) -> "IdaConfigLite":
        defaults = cls()
        return cls(
            enabled=getattr(cfg, "enabled", True),
            ida_path=getattr(cfg, "ida_path", ""),
            command=list(getattr(cfg, "command", defaults.command)),
            prefer_gui=getattr(cfg, "prefer_gui", False),
            open_timeout_s=getattr(cfg, "open_timeout_s", 180),
            open_soft_deadline_s=float(
                getattr(cfg, "open_soft_deadline_s", defaults.open_soft_deadline_s)
            ),
        )
