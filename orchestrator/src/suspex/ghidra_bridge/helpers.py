"""Pure helper functions used across the ``suspex.ghidra_bridge`` package."""

from __future__ import annotations

import re
from typing import Any


# Allowed charset for a caller-supplied session `name` — same rule as the
# IDA bridge (the program name lands inside the Ghidra project tree and
# the backend's _safe_program_name uses the same charset).
_SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def _valid_session_name(name: str) -> bool:
    """Return True when ``name`` fits the caller-facing session-name
    charset."""
    return bool(name and _SESSION_NAME_RE.match(name))


# Symbol/PDB classifiers layered on the extension's ``ghidra_status()``
# snapshot — the tool emits the same ``analysis_state``/``functions_count``
# keys as ``ida_status()`` so the classifiers are identical.
def _classify_symbols(status: dict[str, Any]) -> str:
    """Map a ``ghidra_status`` snapshot to one of
    ``loading | loaded | failed | none``."""
    try:
        n = int(status.get("functions_count") or 0)
    except (TypeError, ValueError):
        n = 0
    state = str(status.get("analysis_state") or "")
    if n > 0:
        return "loaded"
    if state == "idle":
        return "failed"
    return "loading"


def _safe_int(val: Any) -> int:
    """Coerce ``val`` to int, returning 0 for None / bad shapes."""
    try:
        return int(val or 0)
    except (TypeError, ValueError):
        return 0


def _classify_pdb(status: dict[str, Any]) -> str:
    """Map ``ghidra_status`` to ``matched | missing | failed | unknown``.

    Ghidra's PDB pipeline is optional (its own parser, no dbghelp); the
    backend reports ``pdb`` the same way ida_status does once that data
    is plumbed through — ``unknown`` until then.
    """
    val = status.get("pdb")
    if isinstance(val, str) and val in ("matched", "missing", "failed"):
        return val
    matched = status.get("pdb_matched")
    if matched is True:
        return "matched"
    if matched is False:
        return "missing"
    return "unknown"


# Actions that never route by MRU — identical semantics to the IDA bridge.
_NON_SESSION_ACTIONS = frozenset({
    "open", "open_async", "open_status", "list", "schemas",
})
