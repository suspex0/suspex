"""PDB-cached struct + enum layout helpers (orchestrator-side).

Analysts routinely want `struct.field` layout for a well-known module
(`ntoskrnl.exe`, `tcpip.sys`, `nvlddmkm.sys`) without paying for a
full IDA session. This module reads a JSON cache written by the
extension's `dump_layout` tool and answers `struct_info` /
`resolve_member` queries as pure compute.

Cache layout at ``~/.suspex0/pdb_layouts/<module>.<build_id>.json``::

    {
      "module": "ntoskrnl.exe",
      "build_id": "F1E2A3B4-...",
      "size_of_image": 18546688,
      "types": {
        "_EPROCESS": {
          "size": 2272,
          "members": [
            {"name": "Pcb", "offset": 0, "size": 736, "type": "_KPROCESS"},
            ...
          ]
        }
      },
      "enums": {
        "NL_NEIGHBOR_STATE": {
          "size": 4,
          "members": [{"name": "NlnsProbe", "value": 2}, ...]
        }
      }
    }

The reader is deliberately dependency-free — it uses ``json`` +
``pathlib`` only — so the module works from any orchestrator context
that has the cache path on disk. The writer lives inside the idalib
extension (which cannot import orchestrator modules) and produces
the same JSON shape via ``os.path`` + ``json``.

Every response is a dict shaped like the rest of the IDA envelope
family: ``{"ok": bool, "kind": str, ...}``. Typed error kinds:

* ``pdb_layout_missing``     — no cache file for (module, build_id).
* ``type_not_found``         — cache exists but the requested type is not in it.
* ``offset_out_of_range``    — resolve_member offset lies past the struct end.
* ``invalid_layout``         — cache file is malformed JSON or missing keys.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CACHE_DIR = Path.home() / ".suspex0" / "pdb_layouts"


class LayoutCacheError(Exception):
    """Raised by the low-level ``load`` helper. Public callers reach
    the tools instead, which return typed dicts."""


def _looks_like_udt_name(name: str) -> bool:
    """Rough test: does ``name`` look like a struct/union tag as
    opposed to a primitive typedef (``unsigned __int64``, ``void *``)?

    Used only to decide whether to emit a friendly ``note`` when the
    resolver runs out of cache mid-walk — false negatives just mean
    a quieter reply, false positives mean an unnecessary note. A
    leading underscore is the strongest signal in Windows kernel
    PDBs (``_EPROCESS``, ``_KTHREAD``); the ``struct``/``union``
    keyword catches the C++-style prints.
    """
    n = name.strip()
    if not n:
        return False
    if n.startswith("_"):
        return True
    return n.startswith("struct ") or n.startswith("union ")


def _safe_component(name: str) -> str:
    """Sanitize a module or build-id string for filesystem use.

    Only ASCII alnum, ``._-+`` survive; everything else becomes ``_``.
    Prevents a caller-supplied build id from escaping ``CACHE_DIR``.
    """
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789._-+")
    return "".join(c if c in keep else "_" for c in name)


def cache_path(module: str, build_id: str,
               cache_dir: Path | None = None) -> Path:
    """Path to the (module, build_id) JSON cache file.

    Uses ``__`` as the separator between module and build id so a
    module name that itself contains dots (``ntoskrnl.exe``,
    ``tcpip.sys``) survives round-tripping through the filename.

    ``cache_dir`` overrides the default for tests / relocation.
    """
    base = cache_dir if cache_dir is not None else CACHE_DIR
    return base / f"{_safe_component(module)}__{_safe_component(build_id)}.json"


def load(module: str, build_id: str,
         cache_dir: Path | None = None) -> dict:
    """Read the cache file for (module, build_id).

    Raises ``LayoutCacheError`` when the cache is missing or malformed;
    callers wrap it into a typed envelope.
    """
    p = cache_path(module, build_id, cache_dir=cache_dir)
    if not p.exists():
        raise LayoutCacheError(
            f"no cached PDB layout for {module!r} build {build_id!r} "
            f"at {p}"
        )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LayoutCacheError(
            f"failed to read cache {p}: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise LayoutCacheError(
            f"cache {p} does not contain a JSON object at the top level"
        )
    return data


def list_cached_layouts(cache_dir: Path | None = None) -> list[dict]:
    """Enumerate every ``<module>.<build_id>.json`` under the cache dir.

    Returns ``[{"module":..., "build_id":..., "path":..., "size":...}]``
    with entries sorted by module name then build id. Missing dir is
    treated as empty; the walker never raises.
    """
    base = cache_dir if cache_dir is not None else CACHE_DIR
    if not base.exists():
        return []
    out: list[dict] = []
    for f in sorted(base.glob("*.json")):
        stem = f.stem
        # Filename shape: ``<module>__<build_id>`` — separator picked
        # so a module name that contains dots (``ntoskrnl.exe``,
        # ``tcpip.sys``) round-trips cleanly.
        if "__" not in stem:
            continue
        module, build_id = stem.rsplit("__", 1)
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        out.append({
            "module": module,
            "build_id": build_id,
            "path": str(f),
            "size": size,
        })
    return out


def resolve_build_id(module: str, build_id: str,
                     cache_dir: Path | None = None) -> tuple[str, str]:
    """Map an empty or partial build id onto an installed layout.

    The build_id format is the symsrv GUID+age token (32-hex GUID followed
    by the age, no dashes — exactly what ``symbols_manage(action='info')``
    reports as ``guid``+``age`` and what ``dump_layout`` writes). Callers
    should not have to know that: an empty id resolves to the only
    installed build for the module, and an unambiguous prefix or suffix
    match resolves too.

    Returns ``(effective_build_id, note)`` — ``note`` is "" on an exact
    match and explains the resolution otherwise. An unknown/ambiguous id
    comes back unchanged with a non-empty note the caller turns into a
    typed error.
    """
    installed = [r["build_id"] for r in list_cached_layouts(cache_dir=cache_dir)
                 if r["module"] == _safe_component(module)]
    if not installed:
        return build_id, (f"no cached layouts for module {module!r} — "
                          "run ida_manage(action='dump_layout', ...) from an "
                          "open session first")
    if build_id in installed:
        return build_id, ""
    if not build_id:
        if len(installed) == 1:
            return installed[0], (f"build_id= empty — resolved to the only "
                                  f"installed layout {installed[0]!r}")
        return build_id, (f"build_id= empty and {len(installed)} layouts are "
                          f"installed for {module!r}: "
                          + ", ".join(sorted(installed)))
    prefix = [b for b in installed if b.startswith(build_id)]
    suffix = [b for b in installed if b.endswith(build_id)]
    matches = sorted(set(prefix) | set(suffix))
    if len(matches) == 1:
        return matches[0], (f"build_id={build_id!r} matched installed "
                            f"layout {matches[0]!r}")
    if len(matches) > 1:
        return build_id, (f"build_id={build_id!r} is ambiguous — candidates: "
                          + ", ".join(matches))
    return build_id, (f"build_id={build_id!r} matches no installed layout "
                      f"for {module!r} (have: " + ", ".join(sorted(installed))
                      + ")")


def _missing_layout_error(module: str, build_id: str,
                          cache_dir: Path | None) -> dict:
    """Assemble the ``pdb_layout_missing`` envelope with an installed-
    builds hint so a mismatched build id is easy to spot.
    """
    installed = [
        {"module": r["module"], "build_id": r["build_id"]}
        for r in list_cached_layouts(cache_dir=cache_dir)
        if r["module"] == _safe_component(module)
    ]
    hint = (
        "run ida_manage(action='dump_layout', name='<session>', "
        "args_json='{\"module\":\"" + module + "\","
        "\"build_id\":\"" + build_id + "\"}') "
        "to populate the cache from an open IDA session"
    )
    return {
        "ok": False,
        "kind": "pdb_layout_missing",
        "error": (f"no cached PDB layout for {module!r} "
                  f"build {build_id!r}"),
        "module": module,
        "build_id": build_id,
        "installed_builds": installed,
        "hint": hint,
    }


def struct_info(module: str, build_id: str, struct_name: str,
                cache_dir: Path | None = None) -> dict:
    """Return a terse layout preview for ``struct_name`` in
    (module, build_id) — mirrors the shape of the live-session
    ``type_info`` reply so callers can key off the same envelope.
    """
    try:
        layout = load(module, build_id, cache_dir=cache_dir)
    except LayoutCacheError:
        return _missing_layout_error(module, build_id, cache_dir)
    types = layout.get("types")
    if not isinstance(types, dict):
        return {
            "ok": False,
            "kind": "invalid_layout",
            "error": (f"cache for {module!r} build {build_id!r} is "
                      "missing a 'types' object"),
        }
    entry = types.get(struct_name)
    if not entry:
        return {
            "ok": False,
            "kind": "type_not_found",
            "error": (f"{struct_name!r} not in cached layout for "
                      f"{module!r} build {build_id!r}"),
            "module": module,
            "build_id": build_id,
            "hint": ("call ida_manage(action='type_info', "
                     "args_json='{\"name\":\"" + struct_name + "\"}') "
                     "against an open session, or re-run dump_layout "
                     "with an explicit types=[...] allowlist"),
        }
    members = entry.get("members") or []
    first = [m.get("name", "") for m in members][:10]
    return {
        "ok": True,
        "kind": "struct",
        "name": struct_name,
        "module": module,
        "build_id": build_id,
        "size": entry.get("size"),
        "member_count": len(members),
        "first_members": first,
    }


def _resolve_in_type(layout: dict, tname: str, off: int,
                     path: list[str]) -> dict:
    types = layout.get("types") or {}
    entry = types.get(tname)
    if not entry:
        # Nested member's type is not cached — return partial result so
        # the caller sees which path prefix WAS resolved.
        return {
            "ok": True,
            "path": ".".join(path),
            "member_name": None,
            "requested_offset": f"0x{off:X}",
            "requested_offset_int": off,
            "note": (f"type {tname!r} not cached; stopped at path — "
                     "populate more types with dump_layout to drill "
                     "deeper"),
        }
    for m in entry.get("members", []):
        m_off = int(m.get("offset", 0))
        m_sz = int(m.get("size", 0))
        if not (m_off <= off < m_off + max(m_sz, 1)):
            continue
        remaining = off - m_off
        inner_tname = m.get("type")
        # Only recurse into cached inner types. A member whose type is
        # a primitive (e.g. ``unsigned __int64``) always terminates.
        if (inner_tname
                and isinstance(inner_tname, str)
                and inner_tname in types
                and remaining < m_sz):
            return _resolve_in_type(layout, inner_tname, remaining,
                                    path + [m.get("name", "")])
        out: dict[str, Any] = {
            "ok": True,
            "path": ".".join(path + [m.get("name", "")]),
            "member_name": m.get("name"),
            "member_offset": f"0x{m_off:X}",
            "member_offset_int": m_off,
            "member_size": m_sz,
            "type": inner_tname,
            "requested_offset": f"0x{off:X}",
            "requested_offset_int": off,
            "remaining_offset": f"0x{remaining:X}",
            "remaining_offset_int": remaining,
            "exact": remaining == 0,
        }
        # When the offset landed inside a nested UDT-looking type that
        # itself isn't cached, expose a `note` so the caller can see
        # WHY the recursion stopped and re-dump with the inner type
        # in the allowlist. Heuristic: a leading underscore or a
        # ``struct``/``union`` keyword — primitives never match.
        if (inner_tname
                and isinstance(inner_tname, str)
                and inner_tname not in types
                and remaining > 0
                and _looks_like_udt_name(inner_tname)):
            out["note"] = (f"inner type {inner_tname!r} not cached; "
                           "recursion stopped — re-run dump_layout with "
                           f"types including {inner_tname!r} to drill "
                           "deeper")
        return out
    total = int(entry.get("size", 0))
    return {
        "ok": False,
        "kind": "offset_out_of_range",
        "error": (f"offset 0x{off:X} is past the end of "
                  f"{'.'.join(path)!r} (struct size 0x{total:X})"),
        "struct_name": path[0],
        "struct_size": total,
        "requested_offset": f"0x{off:X}",
        "requested_offset_int": off,
    }


def resolve_member(module: str, build_id: str, struct_name: str,
                   offset: int,
                   cache_dir: Path | None = None) -> dict:
    """Cache-backed twin of the live-session ``resolve_offset`` tool.

    Given a struct in (module, build_id) plus a byte offset, walks the
    cached members and recurses into any inner UDT that has its own
    cached layout — so a ``base + 0x28`` decode returns the full
    dotted path (``_EPROCESS.Pcb.DirectoryTableBase``) without an
    open IDA session.
    """
    try:
        layout = load(module, build_id, cache_dir=cache_dir)
    except LayoutCacheError:
        return _missing_layout_error(module, build_id, cache_dir)
    types = layout.get("types")
    if not isinstance(types, dict):
        return {
            "ok": False,
            "kind": "invalid_layout",
            "error": (f"cache for {module!r} build {build_id!r} is "
                      "missing a 'types' object"),
        }
    if struct_name not in types:
        return {
            "ok": False,
            "kind": "type_not_found",
            "error": (f"{struct_name!r} not in cached layout for "
                      f"{module!r} build {build_id!r}"),
            "module": module,
            "build_id": build_id,
        }
    try:
        off = int(offset)
    except (TypeError, ValueError) as exc:
        return {
            "ok": False,
            "kind": "invalid_parameter",
            "error": f"bad offset: {exc}",
        }
    if off < 0:
        return {
            "ok": False,
            "kind": "invalid_parameter",
            "error": f"negative offset {offset!r} not supported",
        }
    return _resolve_in_type(layout, struct_name, off, [struct_name])


def enum_info(module: str, build_id: str, enum_name: str,
              cache_dir: Path | None = None) -> dict:
    """Return every ``(name, value)`` pair for a cached enum.

    Mirrors the live-session ``type_info`` enum branch — same envelope
    shape, so a caller can key off the same ``kind == "enum"``
    regardless of whether the reply came from an open session or a
    JSON cache.
    """
    try:
        layout = load(module, build_id, cache_dir=cache_dir)
    except LayoutCacheError:
        return _missing_layout_error(module, build_id, cache_dir)
    enums = layout.get("enums") or {}
    entry = enums.get(enum_name)
    if not entry:
        return {
            "ok": False,
            "kind": "type_not_found",
            "error": (f"enum {enum_name!r} not in cached layout for "
                      f"{module!r} build {build_id!r}"),
            "module": module,
            "build_id": build_id,
        }
    members: list[dict[str, Any]] = [
        {"name": m.get("name", ""), "value": int(m.get("value", 0))}
        for m in (entry.get("members") or [])
    ]
    return {
        "ok": True,
        "kind": "enum",
        "name": enum_name,
        "module": module,
        "build_id": build_id,
        "size": entry.get("size"),
        "member_count": len(members),
        "members": members,
    }
