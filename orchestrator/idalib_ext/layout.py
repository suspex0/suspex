"""PDB-layout cache writer: struct/enum layouts serialized to disk.

Runs inside idalib's embedded interpreter and cannot import the
orchestrator side (``suspex.pdb_layout_cache``); the cache directory
convention + sanitiser are duplicated here on purpose.
"""
from __future__ import annotations

import contextlib
import os
from typing import Annotated, Any

from .funcs import _member_offset_size


def _pdb_cache_dir() -> str:
    """~/.suspex0/pdb_layouts/ — created lazily.

    Kept in-extension (no orchestrator imports) because
    ``suspex_idalib_ext`` runs inside idalib's embedded interpreter
    where ``orchestrator.src.suspex.*`` is unreachable.
    """
    from pathlib import Path as _P
    d = _P(os.path.expanduser("~")) / ".suspex0" / "pdb_layouts"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _safe_cache_component(name: str) -> str:
    """Mirror the sanitizer in ``pdb_layout_cache._safe_component``.

    Only ASCII alnum + ``._-+`` survive; anything else becomes ``_``.
    Two implementations because the reader lives on the orchestrator
    side and the writer here cannot import it — the algorithm is
    tiny and stable.
    """
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789._-+")
    return "".join(c if c in keep else "_" for c in name)


def _iter_named_types() -> list[str]:
    """Enumerate every named type currently in the IDB.

    ``ida_typeinf`` gained ``get_ordinal_qty`` and ``get_numbered_type_name``
    on the modern typeinfo library — use them to grab every ordinal in one
    pass. Older builds can still be walked via ``first_named_type``
    but that path is not needed by the analyst pipeline that ships this
    tool.
    """
    import ida_typeinf
    names: list[str] = []
    try:
        qty = ida_typeinf.get_ordinal_qty(None)
    except TypeError:
        # Older signature — no `til` argument.
        qty = ida_typeinf.get_ordinal_qty()
    for ordinal in range(1, int(qty) + 1):
        try:
            nm = ida_typeinf.get_numbered_type_name(None, ordinal)
        except TypeError:
            nm = ida_typeinf.get_numbered_type_name(ordinal)
        if nm:
            names.append(nm)
    return names


def _dump_struct_layout(tif: Any) -> dict | None:
    """Return ``{size, members:[{name, offset, size, type}]}`` for a UDT.

    Members are captured in declaration order with byte offsets/sizes;
    the ``type`` field is the printed type string (``str(m.type._print())``)
    so downstream consumers see the same repr as
    ``get_struct_member``. Returns ``None`` if the details fetch fails
    (mirrors the live tool's ``udt_details_unavailable`` error).
    """
    import ida_typeinf
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return None
    members: list[dict] = []
    for m in udt:
        off, sz = _member_offset_size(m)
        try:
            type_repr = str(m.type._print())
        except Exception:  # noqa: BLE001 - _print occasionally faults
            type_repr = ""
        members.append({
            "name": m.name,
            "offset": off,
            "size": sz,
            "type": type_repr,
        })
    return {"size": tif.get_size(), "members": members}


def _dump_enum_layout(tif: Any) -> dict | None:
    """Return ``{size, members:[{name, value}]}`` for an enum ``tinfo_t``."""
    import ida_typeinf
    ei = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(ei):
        return None
    return {
        "size": tif.get_size(),
        "members": [{"name": m.name, "value": int(m.value)} for m in ei],
    }


def dump_layout(
    module: Annotated[str, "Module name (e.g. 'ntoskrnl.exe')"],
    build_id: Annotated[str, "PDB build id / version tag"],
    types: Annotated[str, "Optional JSON list of type names; empty = dump every ordinal"] = "",
) -> dict:
    """Dump IDB's named types + enums into `~/.suspex0/pdb_layouts/`.

    Companion to `suspex.pdb_layout_cache` (orchestrator side) —
    lets `struct_info` / `resolve_member` answer without a live
    IDA session. Empty `types` dumps every ordinal (minutes on a
    big PDB); a JSON list keeps the caller in control. Unknown
    names come back in `missing`. Atomic tmp+rename write.
    """
    import ida_typeinf
    import json as _json
    import tempfile as _tmpf

    want: list[str] | None = None
    if types:
        try:
            parsed = _json.loads(types)
        except _json.JSONDecodeError as exc:
            return {"ok": False, "kind": "invalid_parameter",
                    "error": f"bad types JSON: {exc}"}
        if isinstance(parsed, str):
            want = [parsed]
        elif isinstance(parsed, list):
            want = [str(t) for t in parsed if t]
        else:
            return {"ok": False, "kind": "invalid_parameter",
                    "error": "types must be a JSON list or a bare string"}

    all_names = _iter_named_types()
    if want is not None:
        # Preserve the caller's ordering; missing names are collected
        # for the response so a typo is visible in the reply envelope.
        known = set(all_names)
        candidates = [n for n in want if n in known]
        missing = [n for n in want if n not in known]
    else:
        candidates = all_names
        missing = []

    out_types: dict[str, dict] = {}
    out_enums: dict[str, dict] = {}
    for nm in candidates:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, nm):
            missing.append(nm)
            continue
        if tif.is_udt():
            entry = _dump_struct_layout(tif)
            if entry is not None:
                out_types[nm] = entry
            continue
        if tif.is_enum():
            entry = _dump_enum_layout(tif)
            if entry is not None:
                out_enums[nm] = entry
            continue
        # Typedefs / primitives are not part of the layout cache — the
        # caller only wants structs and enums for offset math.

    payload = {
        "module": module,
        "build_id": build_id,
        "types": out_types,
        "enums": out_enums,
    }
    cache_dir = _pdb_cache_dir()
    # Separator matches ``pdb_layout_cache.cache_path`` on the
    # orchestrator side — ``__`` keeps modules with dots in their
    # name (``ntoskrnl.exe``) round-trippable.
    fname = f"{_safe_cache_component(module)}__{_safe_cache_component(build_id)}.json"
    target = os.path.join(cache_dir, fname)
    # Atomic write: json to a sibling temp file, then rename over the
    # target so a concurrent reader either sees the previous file or
    # the fully-written new one.
    fd, tmp = _tmpf.mkstemp(prefix=".pdb_layout.", suffix=".tmp",
                            dir=cache_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            _json.dump(payload, fh, indent=2, sort_keys=True)
        # ``os.replace`` is atomic on Windows and POSIX.
        os.replace(tmp, target)
    except Exception as exc:  # noqa: BLE001 - reflect the disk error
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        return {"ok": False, "kind": "cache_write_failed",
                "error": f"{type(exc).__name__}: {exc}",
                "target": target}
    return {
        "ok": True,
        "module": module,
        "build_id": build_id,
        "target": target,
        "types_dumped": len(out_types),
        "enums_dumped": len(out_enums),
        "missing": missing,
    }
