"""Named-type introspection + filtered function listings.

``type_info`` handles structs/typedefs/enums through the modern
``ida_typeinf`` path and falls back to the classic ``ida_enum`` map for
enums that pre-date the typeinfo migration. ``list_functions_filter``
mirrors ``list_functions`` but drops the per-caller grep step.
"""
from __future__ import annotations

from typing import Annotated, Any

from .funcs import hex_ea


def _enum_info_tif(name: str, tif: Any) -> dict:
    """Read enum members through the modern ``tinfo_t`` path.

    IDA >= 8.4 exposes ``enum_type_data_t``; older builds only reach the
    same info via the classic ``ida_enum`` module (``_enum_info_classic``).
    Split so the two paths keep independent error surfaces.
    """
    import ida_typeinf

    ei = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(ei):
        return {
            "ok": False,
            "kind": "enum_details_unavailable",
            "error": f"failed to read enum details for {name!r}",
        }
    members = [{"name": m.name, "value": int(m.value)} for m in ei]
    return {
        "ok": True,
        "kind": "enum",
        "name": name,
        "size": tif.get_size(),
        "member_count": len(members),
        "members": members,
    }


def _enum_info_classic(name: str, eid: int) -> dict:
    """Fallback enum walker for IDBs where the enum only lives in the
    classic ``ida_enum`` map (no ``tinfo_t`` view). Uses
    ``for_all_enum_members`` because ``get_enum_member_qty`` +
    ordinal lookups changed shape across IDA versions.
    """
    import ida_enum

    members: list[dict] = []

    def _cb(cid: int, value: int, serial: int) -> int:  # noqa: ARG001
        try:
            nm = ida_enum.get_enum_member_name(cid) or ""
        except Exception:  # noqa: BLE001 - IDA sometimes yields no name
            nm = ""
        members.append({"name": nm, "value": int(value)})
        return 0

    try:
        ida_enum.for_all_enum_members(eid, _cb)
    except Exception as exc:  # noqa: BLE001 - reflect any walker failure
        return {
            "ok": False,
            "kind": "enum_details_unavailable",
            "error": f"failed walking enum {name!r}: {type(exc).__name__}: {exc}",
        }
    try:
        width = int(ida_enum.get_enum_width(eid))
    except Exception:  # noqa: BLE001
        width = 0
    return {
        "ok": True,
        "kind": "enum",
        "name": name,
        "size": width,
        "member_count": len(members),
        "members": members,
    }


def type_info(
    name: Annotated[str, "Type name — struct, union, typedef, or enum"],
) -> dict:
    """One-shot introspection for any named type in the IDB.

    Returns `{kind:"struct"|"enum"|"typedef", size, ...}`. Structs
    get a terse `member_count` + `first_members[:10]` preview (call
    `analyze_struct_detailed` for the full dump). Enums return
    every `(name, value)` pair — a `NL_NEIGHBOR_STATE`-style
    lookup without a hand-rolled recipe. Falls back to the classic
    `ida_enum` map for enums pre-dating the typeinfo migration.
    Typed errors: `type_not_found` | `udt_details_unavailable` |
    `enum_details_unavailable`.
    """
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, name):
        if tif.is_enum():
            return _enum_info_tif(name, tif)
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return {
                    "ok": False,
                    "kind": "udt_details_unavailable",
                    "error": f"failed to read UDT details for {name!r}",
                }
            members_list = list(udt)
            first = [m.name for m in members_list][:10]
            return {
                "ok": True,
                "kind": "struct",
                "name": name,
                "size": tif.get_size(),
                "member_count": len(members_list),
                "first_members": first,
                "hint": ("call analyze_struct_detailed(name=...) for the "
                         "full field dump"),
            }
        return {
            "ok": True,
            "kind": "typedef",
            "name": name,
            "size": tif.get_size(),
            "type": str(tif._print()),
        }

    # Enums pre-dating the typeinfo migration still live only in the
    # classic ida_enum map — probe it as a last resort.
    try:
        import ida_enum  # noqa: PLC0415 - lazy import: not every IDA build has it
        eid = ida_enum.get_enum(name)
        if eid != ida_enum.BADADDR:
            return _enum_info_classic(name, eid)
    except ImportError:
        pass

    return {
        "ok": False,
        "kind": "type_not_found",
        "error": f"no type named {name!r} in the IDB",
        "hint": "verify tag vs typedef; try "
                "search_structures(filter='<pattern>'); PDB types may "
                "need to be imported first",
    }


def list_functions_filter(
    name_filter: Annotated[str, "Case-insensitive substring; empty = no filter"] = "",
    offset: Annotated[int, "Pagination offset into the (post-filter) result"] = 0,
    count: Annotated[int, "Max rows (0 = 200 cap)"] = 200,
) -> dict:
    """Enumerate functions, filtered by a case-insensitive substring
    on the function name inside the extension.

    Response: `{functions:[{address, name}], count, offset,
    total_matched, truncated, name_filter}`. Empty `name_filter`
    degrades to a windowed dump.
    """
    # Vanilla `list_functions` returns every name in the window and
    # forces the caller to grep client-side; a 15 000-function driver
    # is ~120 KB on the wire per pass. Filtering here keeps only the
    # survivors, which is typically a handful.
    import ida_funcs

    cap = int(count) if int(count) > 0 else 200
    skip = max(int(offset), 0)
    needle = (name_filter or "").lower()
    qty = ida_funcs.get_func_qty()
    matched: list[dict] = []
    for i in range(qty):
        fn = ida_funcs.getn_func(i)
        if fn is None:
            continue
        nm = ida_funcs.get_func_name(fn.start_ea) or ""
        if needle and needle not in nm.lower():
            continue
        matched.append({"address": hex_ea(fn.start_ea), "name": nm})
    total = len(matched)
    page = matched[skip:skip + cap]
    return {
        "ok": True,
        "name_filter": name_filter,
        "offset": skip,
        "count": len(page),
        "total_matched": total,
        "truncated": (skip + len(page)) < total,
        "functions": page,
    }
