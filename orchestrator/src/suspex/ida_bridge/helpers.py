"""Pure helper functions used across the ``suspex.ida_bridge`` package."""

from __future__ import annotations

import re
from typing import Any


# v0.17 C1-1: allowed charset for a caller-supplied session `name`.
# Kept narrow enough that the resulting artifacts-subdir is a safe
# filesystem path on every host (Windows path separators, control chars,
# ".." traversal and shell metacharacters all excluded); 64-char cap
# matches the shim's session_id budget.
_SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def _valid_session_name(name: str) -> bool:
    """Return True when ``name`` fits the caller-facing session-name
    charset. A leading '.' or '-' is permitted (kept intentionally
    permissive so 'nt.10.0.26100' works) but ``..``, slashes and other
    filesystem escapes never make it through."""
    return bool(name and _SESSION_NAME_RE.match(name))


# v0.17 C1-2: symbol/PDB classifiers layered on the extension's
# ``ida_status()`` snapshot. Every open_status probe adds these three
# fields (`symbols`, `named_functions`, `pdb`) so a caller can tell
# "database opened, symbols loaded" from "database opened, PDB fetch
# silently failed, name searches will return nothing" without having
# to grep :meth:`list_functions` for zero-hit disambiguation.
def _classify_symbols(status: dict[str, Any]) -> str:
    """Map an ``ida_status`` snapshot to one of
    ``loading | loaded | failed | none``.

    Heuristic:
      - ``functions_count > 0`` -> ``loaded`` (analysis produced work)
      - ``functions_count == 0`` and ``analysis_state == "idle"``
        -> ``failed`` (auto-analysis quiesced but produced nothing)
      - otherwise -> ``loading`` (analysis is still churning)
    """
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
    """Coerce ``val`` to int, returning 0 for None / bad shapes.

    Used to keep the ``named_functions`` slot present even when a
    probe returned nothing useful, so downstream code can rely on the
    field being an int rather than gating every read on hasattr /
    isinstance.
    """
    try:
        return int(val or 0)
    except (TypeError, ValueError):
        return 0


def _classify_pdb(status: dict[str, Any]) -> str:
    """Map ``ida_status`` to one of
    ``matched | missing | failed | unknown``.

    The extension's ``ida_status()`` may grow a ``pdb_matched`` field
    (C2-3); until then this stays at ``unknown``. Callers get a
    consistent slot in the envelope either way.
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


# v0.17 C1-3: actions that never route by MRU. ``open`` / ``open_async``
# either create the session or attach to a specific one, ``open_status``
# reports on a specific name, ``list`` / ``schemas`` operate over the
# whole inventory. Anything else (decompile, disasm, xrefs, and every
# passthrough shim tool) is session-scoped and eligible for autofill.
_NON_SESSION_ACTIONS = frozenset({
    "open", "open_async", "open_status", "list", "schemas",
})
