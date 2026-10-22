"""Datatype tool bodies — type_info, get_struct_member, resolve_offset,
analyze_struct_detailed, list_data_types, dump_layout.

``dump_layout`` writes the SAME JSON shape the IDA extension writes
(``suspex.pdb_layout_cache`` contract), so ``symbols_manage``
struct_info/resolve_member consumers can't tell which engine produced
the cache file.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
from typing import Any

from .helpers import _err
from .state import STATE, _j


def _dtm(program: Any):
    return program.getDataTypeManager()


def _resolve_dt(program: Any, name: str):
    """name -> DataType. Tries exact lookup first, then a name scan
    (category-qualified spellings like '/ntddk/_EPROCESS' are common
    in PDB-applied programs)."""
    dtm = _dtm(program)
    dt = dtm.getDataType(name)
    if dt is not None:
        return dt
    it = dtm.getAllDataTypes()
    found = None
    while it.hasNext():
        d = it.next()
        if d.getName() == name:
            found = d
            break
    return found


def _is_struct(dt: Any) -> bool:
    try:
        from ghidra.program.model.data import Structure
        return isinstance(dt, Structure)
    except Exception:  # noqa: BLE001
        return hasattr(dt, "getComponents")


def _is_enum(dt: Any) -> bool:
    try:
        from ghidra.program.model.data import Enum as _GEnum
        return isinstance(dt, _GEnum)
    except Exception:  # noqa: BLE001
        return hasattr(dt, "getNames") and hasattr(dt, "getValue")


def _struct_members(dt: Any) -> list[dict]:
    out = []
    for c in dt.getComponents():
        out.append({
            "name": c.getFieldName() or "",
            "offset": int(c.getOffset()),
            "size": int(c.getLength()),
            "type": c.getDataType().getName()
                    if c.getDataType() is not None else "",
        })
    return out


def _enum_members(dt: Any) -> list[dict]:
    out = []
    for nm in dt.getNames():
        try:
            out.append({"name": nm, "value": int(dt.getValue(nm))})
        except Exception:  # noqa: BLE001
            pass
    return out


def type_info(binary_name: str, name: str = "") -> str:
    """Named-type introspection: kind/size/member preview."""
    st = STATE.get(binary_name)
    dt = _resolve_dt(st["program"], name)
    if dt is None:
        return _j(_err("not_found", f"type {name!r} not in DataTypeManager"))
    kind = "typedef"
    if _is_struct(dt):
        kind = "struct"
    elif _is_enum(dt):
        kind = "enum"
    out = {"name": dt.getName(), "kind": kind,
           "size": int(dt.getLength()),
           "category": STATE._safe(
               lambda: str(dt.getCategoryPath().getPath()))}
    if kind == "struct":
        members = _struct_members(dt)
        out["member_count"] = len(members)
        out["first_members"] = members[:8]
    elif kind == "enum":
        out["members"] = _enum_members(dt)
    else:
        out["aliased_type"] = STATE._safe(
            lambda: dt.getDataType().getName())
    return _j(out)


def get_struct_member(binary_name: str, struct_name: str = "",
                      member_name: str = "",
                      # short aliases
                      struct: str = "", member: str = "") -> str:
    st = STATE.get(binary_name)
    sname = struct_name or struct
    mname = member_name or member
    dt = _resolve_dt(st["program"], sname)
    if dt is None or not _is_struct(dt):
        return _j(_err("not_found", f"struct {sname!r} not found"))
    for c in dt.getComponents():
        if (c.getFieldName() or "") == mname:
            return _j({"struct": sname, "member": mname,
                       "offset": int(c.getOffset()),
                       "size": int(c.getLength()),
                       "type": (c.getDataType().getName()
                                if c.getDataType() is not None else "")})
    return _j(_err("not_found",
                   f"member {mname!r} not in {sname!r}",
                   members=[c.getFieldName() or ""
                            for c in dt.getComponents()][:40]))


def resolve_offset(binary_name: str, struct_name: str = "",
                   offset: Any = 0, struct: str = "") -> str:
    """Reverse lookup: struct + byte offset -> containing member, with
    nested-UDT recursion and remainder reporting (resolve_offset parity)."""
    st = STATE.get(binary_name)
    sname = struct_name or struct
    dt = _resolve_dt(st["program"], sname)
    if dt is None or not _is_struct(dt):
        return _j(_err("not_found", f"struct {sname!r} not found"))
    try:
        off = int(str(offset), 0)
    except ValueError:
        return _j(_err("bad_arg", f"bad offset {offset!r}"))
    path = []
    cur = dt
    remaining = off
    depth = 0
    while depth < 8:
        comp = None
        for c in cur.getComponents():
            co, cs = int(c.getOffset()), int(c.getLength())
            if co <= remaining < co + max(cs, 1):
                comp = c
                break
        if comp is None:
            return _j({"struct": sname, "offset": off,
                       "path": ".".join(path) if path else "",
                       "remainder": remaining,
                       "member": path[-1] if path else "",
                       "note": "offset past last member or in padding"})
        mn = comp.getFieldName() or f"field_{int(comp.getOffset()):x}"
        path.append(mn)
        remaining -= int(comp.getOffset())
        inner = comp.getDataType()
        if inner is not None and _is_struct(inner) and \
                inner.getName() != cur.getName():
            cur = inner
            depth += 1
            continue
        return _j({"struct": sname, "offset": off,
                   "member": mn,
                   "path": ".".join(path),
                   "member_offset": int(comp.getOffset()),
                   "member_size": int(comp.getLength()),
                   "type": (inner.getName() if inner is not None else ""),
                   "remainder": remaining})
    return _j({"struct": sname, "offset": off,
               "path": ".".join(path), "remainder": remaining,
               "note": "recursion depth cap"})


def analyze_struct_detailed(binary_name: str, name: str = "",
                            struct_name: str = "") -> str:
    st = STATE.get(binary_name)
    sname = struct_name or name
    dt = _resolve_dt(st["program"], sname)
    if dt is None or not _is_struct(dt):
        return _j(_err("not_found", f"struct {sname!r} not found"))
    members = _struct_members(dt)
    return _j({"name": dt.getName(), "size": int(dt.getLength()),
               "member_count": len(members), "members": members})


def list_data_types(binary_name: str, query: str = "",
                    offset: int = 0, limit: int = 200) -> str:
    from .helpers import _match, _page
    st = STATE.get(binary_name)
    it = _dtm(st["program"]).getAllDataTypes()
    rows = []
    while it.hasNext():
        d = it.next()
        if _match(query, d.getName()):
            kind = ("struct" if _is_struct(d)
                    else "enum" if _is_enum(d) else "typedef")
            rows.append({"name": d.getName(), "kind": kind,
                         "size": int(d.getLength())})
    return _j(_page(rows, offset, limit))


# ------------------------------------------------------------ dump_layout ----

def _pdb_cache_dir() -> str:
    """Mirror of idalib_ext.layout._pdb_cache_dir — same directory so
    either engine's dump feeds the orchestrator's pdb_layout_cache."""
    from pathlib import Path as _P
    d = _P(os.path.expanduser("~")) / ".suspex0" / "pdb_layouts"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _safe_cache_component(name: str) -> str:
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789._-+")
    return "".join(c if c in keep else "_" for c in name)


def dump_layout(binary_name: str, module: str = "",
                build_id: str = "", types: str = "") -> str:
    """Dump the program's named structs/enums into the shared
    ``~/.suspex0/pdb_layouts`` cache — identical JSON shape to
    idalib's dump_layout so symbols_manage can't tell the difference.

    ``module``/``build_id`` default to the binary name + 'ghidra' when
    not supplied (Ghidra programs don't carry a PDB build id the way
    IDBs do).
    """
    st = STATE.get(binary_name)
    p = st["program"]
    module = module or binary_name
    build_id = build_id or "ghidra"

    want: list[str] | None = None
    if types:
        try:
            parsed = json.loads(types)
        except json.JSONDecodeError as exc:
            return _j({"ok": False, "kind": "invalid_parameter",
                       "error": f"bad types JSON: {exc}"})
        if isinstance(parsed, str):
            want = [parsed]
        elif isinstance(parsed, list):
            want = [str(t) for t in parsed if t]
        else:
            return _j({"ok": False, "kind": "invalid_parameter",
                       "error": "types must be a JSON list or a bare string"})

    dtm = _dtm(p)
    if want is not None:
        candidates = want
        missing = []
    else:
        candidates = []
        it = dtm.getAllDataTypes()
        while it.hasNext():
            candidates.append(it.next().getName())
        missing = []

    out_types: dict[str, dict] = {}
    out_enums: dict[str, dict] = {}
    for nm in candidates:
        dt = _resolve_dt(p, nm)
        if dt is None:
            missing.append(nm)
            continue
        if _is_struct(dt):
            out_types[nm] = {"size": int(dt.getLength()),
                             "members": _struct_members(dt)}
        elif _is_enum(dt):
            out_enums[nm] = {"size": int(dt.getLength()),
                             "members": _enum_members(dt)}

    payload = {"module": module, "build_id": build_id,
               "types": out_types, "enums": out_enums,
               "engine": "ghidra"}
    cache_dir = _pdb_cache_dir()
    fname = (f"{_safe_cache_component(module)}__"
             f"{_safe_cache_component(build_id)}.json")
    target = os.path.join(cache_dir, fname)
    fd, tmp = tempfile.mkstemp(prefix=".pdb_layout.", suffix=".tmp",
                               dir=cache_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, target)
    except Exception as exc:  # noqa: BLE001
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        return _j({"ok": False, "kind": "cache_write_failed",
                   "error": f"{type(exc).__name__}: {exc}",
                   "target": target})
    return _j({"ok": True, "module": module, "build_id": build_id,
               "target": target, "engine": "ghidra",
               "types_dumped": len(out_types),
               "enums_dumped": len(out_enums),
               "missing": missing})
