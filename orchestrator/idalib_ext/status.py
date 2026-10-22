"""Structured backend snapshot + empty-result disambiguation.

``ida_status`` collapses IDA's autoanalysis enum into a small vocabulary
and pairs it with the function count + saved-target so a caller doesn't
have to poll ``ida_auto.get_auto_state`` themselves.

``ida_query_context`` disambiguates an empty tool result (IDA_STATUS_FEEDBACK F3):
``get_xrefs_to(a) == []`` might mean "no xrefs", "address not mapped",
or "region not analysed yet"; a single round trip through this tool
returns every field needed to tell them apart.
"""
from __future__ import annotations

from typing import Annotated

from . import save as _save
from .funcs import _to_ea


def ida_status() -> dict:
    """Structured backend snapshot: analysis state, function count,
    log tail, last error. Removes every 'assume and wait' loop the
    caller would otherwise run against OS-level signals.

    Fields:
      analysis_state    idle | running | busy | unknown
      functions_count   int (may be 0 during early load)
      auto_queue_empty  bool
      percent_done      0..100 or null when not estimable
      input_path        currently-open binary
      idb_target        <input>.i64 (where periodic saves land)
      last_error        last stderr line captured by ext (best effort)
    """
    try:
        import ida_auto
        import ida_funcs
        state = ida_auto.get_auto_state()
        # AU_NONE is the "no autoanalysis running" enum; anything else
        # is a specific work item. We collapse to a small vocabulary.
        state_name = {
            getattr(ida_auto, "AU_NONE", 0): "idle",
        }.get(state, "running")
        try:
            queue_empty = bool(ida_auto.auto_is_ok())
        except Exception:  # noqa: BLE001
            queue_empty = None
        func_count = ida_funcs.get_func_qty()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "analysis_state": "unknown"}
    return {
        "ok": True,
        "analysis_state": state_name,
        "state_code": int(state),
        "functions_count": int(func_count),
        "auto_queue_empty": queue_empty,
        "percent_done": None,  # ida_auto doesn't expose a live percentage
        "input_path": _save._INPUT_PATH_FOR_SAVE,
        "idb_target": _save._safe_save_target(None)[0],
    }


def ida_query_context(
    address: Annotated[str, "Address to check (hex '0x1234' or decimal)"],
) -> dict:
    """Disambiguate empty tool results (IDA_STATUS_FEEDBACK F3).

    `get_xrefs_to(a) == []` is ambiguous: the address may not be mapped in
    this database, the region may not be analysed yet, or there may be
    genuinely no xrefs. This returns, in ONE round trip, everything needed
    to tell those apart: `addr_in_db`, whether the address sits inside a
    (defined) function, and the current analysis state. Call it whenever
    an empty result would otherwise send you polling or guessing.
    """
    try:
        import ida_auto
        import ida_bytes
        import ida_funcs
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    try:
        ea = _to_ea(address)
    except ValueError as exc:
        return {"ok": False, "error": f"bad address: {exc}"}
    state = ida_auto.get_auto_state()
    try:
        queue_empty = bool(ida_auto.auto_is_ok())
    except Exception:  # noqa: BLE001
        queue_empty = None
    fn = ida_funcs.get_func(ea)
    return {
        "ok": True,
        "address": hex(ea),
        "addr_in_db": bool(ida_bytes.is_loaded(ea)),
        "in_function": fn is not None,
        "function_start": hex(fn.start_ea) if fn else None,
        "function_end": hex(fn.end_ea) if fn else None,
        "analysis_state": "idle" if state == getattr(ida_auto, "AU_NONE", 0) else "running",
        "state_code": int(state),
        "auto_queue_empty": queue_empty,
        "functions_count": int(ida_funcs.get_func_qty()),
        "input_path": _save._INPUT_PATH_FOR_SAVE,
    }
