"""Producer-declared coverage blocks for the response envelope.

A ``coverage`` block states how completely a producer looked at the scope
it was asked about, so "empty" (nothing there) is distinguishable from
"couldn't look" (coverage not established) and from "partially looked"
(some reads failed). Shape (top-level envelope key, ABSENT when not
applicable — never ``null``, never empty-dict-only):

    "coverage": {"scope": "mem-read",
                 "status": "complete" | "partial" | "unknown",
                 "limits": ["read_failed_mid_buffer", ...]}

Rules every producer honors:

* Never fabricate ``complete``. If completeness can't be proven, use
  ``unknown`` (or ``partial`` with a ``limits`` entry).
* Paging (``summary.truncated`` / ``next_cursor``) is independent of
  coverage: a fully covered enumeration that is merely paged is
  ``status="complete"`` with paging in ``summary``.
* Empty result + ``status="unknown"`` is the honest "couldn't look"
  answer; empty + ``complete`` means "looked, nothing there".

Every producer goes through :func:`coverage`, which validates the scope
against :data:`APPROVED_SCOPES` so drift fails loudly (a test asserts the
whitelist too).
"""
from __future__ import annotations

import json
from typing import Any

# The exact scope strings the adoption plan approves (test-asserted).
APPROVED_SCOPES: frozenset[str] = frozenset({
    "mem-read",        # mem_rw read/disasm/dt/dps byte windows
    "scan-window",     # mem_rw pattern_scan / pool_scan ranges
    "enumeration",     # mem_rw inventory listings (modules, handles, ...)
    "static-analysis", # bin_manage cfg/xrefs/gadgets/ioctl_surface
    "decompiler",      # ida_manage / ghidra_manage decompile + xref
    "dump-threads",    # dump_manage parse / stack thread walks
    "event-window",    # bp_manage event drain windows
    # v1.0.1 Phase 1.5 / Phase 4
    "pointer-chain",   # mem_rw follow_chain pointer walks
    "leak-kernel_pool",  # mem_rw leak_scan kernel pool coverage
    "leak-module_data",  # mem_rw leak_scan module .data/.rdata coverage
    "leak-per_process",  # mem_rw leak_scan per-process heap coverage
})

_VALID_STATUS: frozenset[str] = frozenset({"complete", "partial", "unknown"})


def coverage(scope: str, status: str, *limits: str) -> dict:
    """Build a validated coverage block. ``limits`` entries are short
    snake_case reasons (empty list when the status speaks for itself)."""
    if scope not in APPROVED_SCOPES:
        raise ValueError(f"coverage scope {scope!r} not in APPROVED_SCOPES")
    if status not in _VALID_STATUS:
        raise ValueError(f"coverage status {status!r} not in {_VALID_STATUS}")
    return {"scope": scope, "status": status,
            "limits": [str(x) for x in limits if x]}


def merge(*blocks: dict) -> dict:
    """Merge sibling coverage blocks (e.g. per-span scans): the weakest
    status wins (unknown > partial > complete), limits concatenate
    deduplicated. All scopes must agree."""
    if not blocks:
        raise ValueError("merge() needs at least one coverage block")
    scopes = {b.get("scope") for b in blocks}
    if len(scopes) > 1:
        raise ValueError(f"merge() scope mismatch: {sorted(scopes)}")
    order = {"unknown": 2, "partial": 1, "complete": 0}
    status = max((str(b.get("status", "unknown")) for b in blocks),
                 key=lambda s: order.get(s, 2))
    limits: list[str] = []
    for b in blocks:
        for x in b.get("limits") or []:
            if x not in limits:
                limits.append(x)
    return {"scope": next(iter(scopes)), "status": status, "limits": limits}


def attach(target: Any, block: dict) -> Any:
    """Attach ``block`` as the ``coverage`` member of a producer result.

    Accepts a dict (legacy tool-body result) or a JSON string (what most
    ``_j``-style call sites hold); returns the same type it was given.
    Already-envelope and already-covered payloads pass through
    untouched, and error envelopes (``ok: false``) never carry coverage —
    only provenance rides on errors.
    """
    if isinstance(target, str):
        try:
            parsed = json.loads(target)
        except (TypeError, ValueError):
            return target
        patched = attach(parsed, block)
        if patched is parsed:
            return target
        return json.dumps(patched, indent=2, default=str)
    if not isinstance(target, dict) or target.get("ok") is False:
        return target
    if "coverage" not in target:
        target["coverage"] = block
    return target
