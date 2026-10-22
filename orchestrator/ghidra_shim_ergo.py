"""Ergonomics helpers for the ghidra stdio shim.

Sibling of ``ida_shim_ergo`` — the Ghidra backend's canonical arg
spellings differ (``name_or_address`` on decompile, ``source`` on
exec_ghidra_script, ``struct_name``/``member_name`` on get_struct_member)
so it gets its own ARG_ALIASES table. The pure JSON/schema helpers are
re-exported from ``ida_shim_ergo`` unchanged.
"""
from __future__ import annotations

from typing import Any

# Pure helpers shared verbatim with the IDA shim.
from ida_shim_ergo import (  # noqa: F401
    collect_string_field_names,
    compute_nearest_function,
    walk_and_coerce,
)


# {tool_name: {alias_name: canonical_name}} — accepted synonyms rewritten
# before the backend sees them. Canonical names are what
# ``pyghidra_ext`` tools declare.
ARG_ALIASES: dict[str, dict[str, str]] = {
    # ida-manage muscle memory: `start_address`/`address`/`ea` ->
    # decompile's `name_or_address`. (Backend also accepts `address`
    # natively; normalizing to one spelling keeps dispatch simple.)
    "decompile_function": {"start_address": "name_or_address",
                           "address": "name_or_address",
                           "ea": "name_or_address"},
    "disassemble_function": {"start_address": "address",
                             "ea": "address",
                             "name_or_address": "address"},
    "get_pcode": {"start_address": "name_or_address",
                  "address": "name_or_address",
                  "ea": "name_or_address"},
    "get_function_by_address": {"start_address": "address",
                                "ea": "address",
                                "name_or_address": "address"},
    "list_xrefs": {"start_address": "name_or_address",
                   "address": "name_or_address",
                   "ea": "name_or_address"},
    "gen_callgraph": {"name": "function_name",
                      "function": "function_name"},
    "exec_ghidra_script": {"code": "source",
                           "script": "source"},
    "get_struct_member": {"struct": "struct_name",
                          "member": "member_name",
                          "name": "struct_name"},
    "resolve_offset": {"struct": "struct_name",
                       "name": "struct_name"},
    "analyze_struct_detailed": {"struct": "name",
                                "struct_name": "name"},
    "type_info": {"struct": "name",
                  "type_name": "name"},
    "search_symbols_by_name": {"name": "query",
                             "pattern": "query",
                             "filter": "query"},
    "list_functions": {"limit": "count",
                       "filter": "query",
                       "pattern": "query"},
    "search_strings": {"pattern": "query",
                       "filter": "query"},
    "list_imports": {"pattern": "query",
                     "filter": "query"},
    "list_exports": {"pattern": "query",
                     "filter": "query"},
    "rename_function": {"address": "name_or_address",
                        "ea": "name_or_address",
                        "start_address": "name_or_address"},
    "rename_variable": {"address": "name_or_address",
                        "function": "function_name_or_address"},
    "set_variable_type": {"address": "name_or_address",
                          "function": "function_name_or_address"},
    "set_function_prototype": {"address": "name_or_address",
                               "ea": "name_or_address",
                               "function": "function_name_or_address"},
    "create_function": {"ea": "address",
                        "start_address": "address"},
    "pattern_scan": {"pattern": "hex_pattern",
                     "hex": "hex_pattern"},
    "qword_value_scan": {"qword": "value",
                         "u64": "value"},
}


def apply_arg_aliases(tool_name: str, args: dict) -> dict:
    """Rewrite alias keys to their canonical names for ``tool_name``.

    Idempotent: unknown tools and canonical keys pass through unchanged.
    When both alias AND canonical are present, the canonical wins and
    the alias is dropped so we don't overwrite an explicit value.
    """
    table = ARG_ALIASES.get(tool_name)
    if not table:
        return args
    out = dict(args)
    for alias, canonical in table.items():
        if alias in out and canonical not in out:
            out[canonical] = out.pop(alias)
        elif alias in out and canonical in out:
            out.pop(alias, None)
    return out


__all__ = [
    "ARG_ALIASES",
    "apply_arg_aliases",
    "collect_string_field_names",
    "compute_nearest_function",
    "walk_and_coerce",
]
