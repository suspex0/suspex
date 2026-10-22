"""Address / struct / JSON-coercion helpers shared across the extension.

Contains the primitive helpers reused by every other submodule:
``_to_ea`` / ``hex_ea`` for address parsing, ``create_function`` and the
struct-member family (``get_struct_member``, ``_member_offset_size``,
``_resolve_offset_recursive``, ``resolve_offset``), plus the JSON-safe
coercion helper (``_coerce_json_safe``) that :func:`exec_idapython` uses
so caller-side ``result`` values round-trip as native JSON.
"""
from __future__ import annotations

import json as _json
from typing import Annotated, Any


def _to_ea(address: str | int) -> int:
    if isinstance(address, int):
        return address
    s = str(address).strip()
    if not s:
        raise ValueError("empty address")
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


def create_function(
    address: Annotated[str, "Address to carve as a function (hex '0x1234' or decimal)"],
) -> dict:
    """Force-create a function at `address`.

    Use when auto-analysis missed code that only reaches it via a vtable
    or a computed call — the address is known (from a string xref, a
    signature, an offset table) but `get_function_by_address` returns
    "no function at that ea". After this, `decompile_function` /
    `get_callers` / `list_functions` work on the new function.
    """
    ea = _to_ea(address)
    import ida_funcs
    import ida_bytes
    # `add_func` refuses when the ea is already inside a function; that's
    # informative, so pass it back verbatim rather than a bare False.
    existing = ida_funcs.get_func(ea)
    if existing is not None:
        return {"ok": True, "already_function": True,
                "address": hex(ea),
                "start": hex(existing.start_ea), "end": hex(existing.end_ea)}
    if not ida_bytes.is_loaded(ea):
        return {"ok": False,
                "error": f"address {hex(ea)} is not mapped in the database"}
    ok = bool(ida_funcs.add_func(ea))
    if not ok:
        return {"ok": False,
                "error": f"add_func({hex(ea)}) failed — try analyzing "
                         "the surrounding bytes first, or check that ea "
                         "points at valid instruction bytes"}
    fn = ida_funcs.get_func(ea)
    return {"ok": True, "address": hex(ea),
            "start": hex(fn.start_ea) if fn else hex(ea),
            "end": hex(fn.end_ea) if fn else None}


# v0.17 D-5: exec_idapython used to `repr(result)`, which is lossy — a dict
# came back as the string ``"{'key': 1}"`` and a caller had to eval/parse
# it. Native JSON now survives; only genuinely unserializable objects fall
# back to ``repr``, and ``result_native`` flags which branch fired.
_EXEC_RESULT_CAP_BYTES = 1 << 20  # 1 MiB safety cap on serialized result


def _coerce_json_safe(value: Any) -> tuple[Any, bool, bool]:
    """Return ``(safe_value, is_native, truncated)`` for ``value``.

    * ``is_native=True`` means the value round-trips as JSON as-is (dict,
      list, int, str, etc., possibly via the ``bytes -> hex`` default hook).
    * ``is_native=False`` means we fell back to :func:`repr` because
      :func:`json.dumps` refused (recursive object, custom type without
      hook coverage, or the JSON serialization exceeded
      :data:`_EXEC_RESULT_CAP_BYTES`).
    * ``truncated=True`` means the native serialization exceeded the byte
      cap; the caller falls back to ``repr`` bounded by the cap.

    ``bytes`` values are surfaced as lower-case hex through the
    ``json.dumps`` default hook — that keeps binary reads (e.g.
    ``ida_bytes.get_bytes(...)``) legible over the wire without dragging
    base64 into the response shape.
    """
    def _default(obj: Any) -> Any:
        if isinstance(obj, (bytes, bytearray)):
            return bytes(obj).hex()
        return str(obj)

    try:
        encoded = _json.dumps(value, default=_default)
    except (TypeError, ValueError, RecursionError):
        return repr(value), False, False
    if len(encoded) > _EXEC_RESULT_CAP_BYTES:
        # Native form exists but is enormous — the JSON transport chokes on
        # multi-MB blobs and callers cannot page a raw exec result. Refuse
        # to smuggle it as native; hand back a bounded repr instead.
        truncated_repr = repr(value)[:_EXEC_RESULT_CAP_BYTES]
        return truncated_repr, False, True
    # ``value`` round-trips; return it as-is so callers see a dict/list.
    return value, True, False


def get_struct_member(
    struct_name: Annotated[str, "Structure name to look up"],
    member_name: Annotated[str, "Field name to return (case-sensitive)"],
) -> dict:
    """Return one field of a struct: name, offset, size, type, comment.

    Cheap alternative to `analyze_struct_detailed` when the caller
    already knows the field name. Typed errors:
    `struct_not_found` | `not_a_udt` | `udt_details_unavailable` |
    `member_not_found` (which echoes the first 20 field names so a
    typo is easy to spot).
    """
    # Written for the RAID_ADAPTER_EXTENSION.Miniport case in the
    # operational review: pulling the full struct via
    # `analyze_struct_detailed` returned a 28 KB / 232-member dump
    # that was greppped locally. This helper avoids that entirely.
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        return {
            "ok": False,
            "kind": "struct_not_found",
            "error": f"struct {struct_name!r} not found in the IDB",
            "hint": "verify the tag vs typedef spelling; try "
                    "search_structures(filter='<pattern>'); PDB types may "
                    "need to be imported first",
        }
    if not tif.is_udt():
        return {
            "ok": False,
            "kind": "not_a_udt",
            "error": f"{struct_name!r} is not a user-defined type",
            "type": str(tif._print()),
        }
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {
            "ok": False,
            "kind": "udt_details_unavailable",
            "error": f"failed to read UDT details for {struct_name!r}",
        }
    for i, member in enumerate(udt):
        if member.name != member_name:
            continue
        offset_bytes = member.begin() // 8
        size_bytes = (member.size // 8
                      if member.size > 0 else member.type.get_size())
        comment = ""
        try:
            comment = member.cmt or ""
        except Exception:  # noqa: BLE001 - cmt attr sometimes missing
            comment = ""
        return {
            "ok": True,
            "struct_name": struct_name,
            "member_name": member.name,
            "index": i,
            "offset": f"0x{offset_bytes:X}",
            "offset_int": offset_bytes,
            "size": size_bytes,
            "type": str(member.type._print()),
            "is_nested_udt": bool(member.type.is_udt()),
            "comment": comment,
        }
    # Miss: list the first few field names so the caller sees typos.
    peek = [m.name for m in udt][:20]
    return {
        "ok": False,
        "kind": "member_not_found",
        "error": f"{struct_name}.{member_name}: no such field",
        "struct_name": struct_name,
        "member_name": member_name,
        "known_fields_preview": peek,
        "hint": ("call analyze_struct_detailed(name=struct_name) to see "
                 "the full field list") if len(peek) == 20 else None,
    }


def _member_offset_size(member: Any) -> tuple[int, int]:
    """(offset_bytes, size_bytes) for a udt_type_data_t member.

    ``begin()``/``size`` are bit-quantities in modern IDA; zero-size
    synthetic members fall back to ``type.get_size()`` so a null-size
    offset table doesn't blank the payload.
    """
    off = member.begin() // 8
    size = member.size // 8 if member.size > 0 else member.type.get_size()
    return off, int(size or 0)


def _resolve_offset_recursive(tif: Any, off: int, path: list[str]) -> dict:
    """Walk into `tif` to find the member containing byte offset `off`.

    Returns the full dotted path so a caller decoding a raw pointer +
    offset can jump straight to a nested field
    (``Miniport.DeviceExtension.QueueLock``) without chaining
    ``get_struct_member`` per hop.
    """
    import ida_typeinf

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return {
            "ok": False,
            "kind": "udt_details_unavailable",
            "error": f"failed to read UDT details for {'.'.join(path)!r}",
        }
    for m in udt:
        m_off, m_sz = _member_offset_size(m)
        if not (m_off <= off < m_off + max(m_sz, 1)):
            continue
        remaining = off - m_off
        if not m.type.is_udt():
            comment = ""
            try:
                comment = m.cmt or ""
            except Exception:  # noqa: BLE001 - cmt attr sometimes missing
                comment = ""
            return {
                "ok": True,
                "path": ".".join(path + [m.name]),
                "member_name": m.name,
                "member_offset": f"0x{m_off:X}",
                "member_offset_int": m_off,
                "member_size": m_sz,
                "type": str(m.type._print()),
                "requested_offset": f"0x{off:X}",
                "requested_offset_int": off,
                "remaining_offset": f"0x{remaining:X}",
                "remaining_offset_int": remaining,
                "exact": remaining == 0,
                "comment": comment,
            }
        # Nested UDT — recurse. Passing the inner tif keeps get_udt_details
        # accurate for that sub-struct without a fresh named-type lookup.
        return _resolve_offset_recursive(m.type, remaining, path + [m.name])
    total = tif.get_size()
    return {
        "ok": False,
        "kind": "offset_out_of_range",
        "error": (f"offset 0x{off:X} is past the end of {'.'.join(path)!r} "
                  f"(struct size 0x{total:X})"),
        "struct_name": path[0],
        "struct_size": total,
        "requested_offset": f"0x{off:X}",
        "requested_offset_int": off,
    }


def resolve_offset(
    struct_name: Annotated[str, "Structure name (case-sensitive tag/typedef)"],
    offset: Annotated[str, "Byte offset into the struct (hex '0x1A0' or decimal)"],
) -> dict:
    """Reverse of get_struct_member: `struct + offset` -> containing field.

    Recurses through nested UDTs and returns the full dotted path
    (``Miniport.DeviceExtension.QueueLock``) plus the offset remainder
    inside that field. Errors:
      * struct_not_found    — unknown type name (typo, or PDB not imported)
      * not_a_udt           — the type resolves but isn't a struct/union
      * udt_details_unavailable — details fetch failed mid-walk
      * offset_out_of_range — offset lies past the struct end
      * invalid_parameter   — offset unparseable / negative
    """
    import ida_typeinf

    try:
        off = _to_ea(offset)
    except ValueError as exc:
        return {"ok": False, "kind": "invalid_parameter",
                "error": f"bad offset: {exc}"}
    if off < 0:
        return {"ok": False, "kind": "invalid_parameter",
                "error": f"negative offset {offset!r} not supported"}
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        return {
            "ok": False,
            "kind": "struct_not_found",
            "error": f"struct {struct_name!r} not found in the IDB",
            "hint": "verify tag vs typedef; try "
                    "search_structures(filter='<pattern>'); PDB types may "
                    "need to be imported first",
        }
    if not tif.is_udt():
        return {
            "ok": False,
            "kind": "not_a_udt",
            "error": f"{struct_name!r} is not a user-defined type",
            "type": str(tif._print()),
        }
    return _resolve_offset_recursive(tif, off, [struct_name])


def hex_ea(ea: int) -> str:
    """Lowercase 0x-prefixed ea string (matches the rest of the extension)."""
    return f"0x{ea:X}"
