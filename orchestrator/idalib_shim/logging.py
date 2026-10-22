"""Shim-local logging helpers: stderr line writer and log-file tail.

Kept in its own module so every other submodule can import it without
pulling in the rest of the shim's session/job machinery.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _tail_log(path: Path, lines: int = 20) -> str:
    """Return the last N lines of the backend log for embedding in an
    error message. Silent-on-open failure otherwise loses every clue."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", "replace")
        tail = "\n".join(text.splitlines()[-lines:])
        return f"log tail ({path.name}):\n{tail}" if tail else f"log {path.name} empty"
    except OSError as exc:
        return f"log {path.name} unreadable: {exc}"
