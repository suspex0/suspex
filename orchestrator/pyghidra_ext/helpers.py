"""Shared helpers for the pyghidra backend tool bodies."""
from __future__ import annotations

import re
from typing import Any

from .state import STATE, _j


def _err(kind: str, msg: str, **kw) -> dict:
    out = {"ok": False, "kind": kind, "error": msg}
    out.update(kw)
    return out


def _page(items: list, offset: int = 0, limit: int = 100) -> dict:
    """Slice ``items`` into a page envelope matching the pyghidra-mcp
    paging convention (offset/limit + next_offset)."""
    total = len(items)
    off = max(0, int(offset or 0))
    lim = max(1, int(limit or 100))
    rows = items[off:off + lim]
    return {"count": len(rows), "total": total, "offset": off,
            "next_offset": (off + lim if off + lim < total else None),
            "items": rows}


def _iter_functions(program: Any):
    fm = program.getFunctionManager()
    it = fm.getFunctions(True)
    while it.hasNext():
        yield it.next()


def _addr_str(addr: Any) -> str:
    # Java longs are signed — kernel-space addresses (>= 0x8000...) come
    # through jpype as negative ints; mask to unsigned 64-bit so the hex
    # prints as 0xfffff804... not 0x-7fbd...
    return f"0x{int(addr.getOffset()) & 0xFFFFFFFFFFFFFFFF:x}"


def _match(query: str, name: str) -> bool:
    """Regex-first matcher, substring fallback — list_* tools accept
    both spellings so callers don't have to anchor '.*' patterns."""
    if not query or query == ".*":
        return True
    try:
        return re.search(query, name) is not None
    except re.error:
        return query.lower() in name.lower()


def _resolve_target(program: Any, target: Any) -> Any:
    """name_or_address -> Function, else None."""
    if isinstance(target, (list, tuple)):
        return [STATE.get_function(program, t) for t in target]
    return STATE.get_function(program, target)


def _decompiler(program: Any):
    """Per-program DecompInterface (cached; openProgram once)."""
    key = str(program.getName())
    di = STATE._decomp.get(key)
    if di is None:
        from ghidra.app.decompiler import DecompInterface
        di = DecompInterface()
        di.openProgram(program)
        STATE._decomp[key] = di
    return di


def _decompile(program: Any, func: Any, timeout_sec: int = 30):
    di = _decompiler(program)
    res = di.decompileFunction(func, int(timeout_sec or 30), STATE.monitor())
    if res is None or not res.decompileCompleted():
        return None
    return res
