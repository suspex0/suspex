"""Extension entrypoint: register every tool, patch save/open, run core.

Composition order matters: ``_record_input_path`` must patch
``open_database`` first so ``_patch_no_auto``'s wrapper stacks on top and
both wrappers see each other. ``_patch_safe_save`` needs no composition
(it only wraps ``save_database``, which nothing else here patches).
"""
from __future__ import annotations

import ida_pro_mcp.idalib_server as _core

from .funcs import create_function, get_struct_member, resolve_offset
from .layout import dump_layout
from .save import (
    _patch_no_auto,
    _patch_safe_save,
    _record_input_path,
    _spawn_periodic_saver,
    exec_idapython,
    idb_save,
)
from .scan import pattern_scan, qword_value_scan
from .status import ida_query_context, ida_status
from .typeinfo import list_functions_filter, type_info


def main() -> None:
    # Order matters: record_input_path patches open_database first so the
    # no-auto wrapper composes on top and both see the wrapped version.
    # The save guard goes on last but needs no composition — it only
    # wraps save_database, which nothing else here patches.
    _record_input_path()
    _patch_no_auto()
    _patch_safe_save()
    _core.mcp.add_tool(create_function, "create_function")
    _core.mcp.add_tool(exec_idapython, "exec_idapython")
    _core.mcp.add_tool(idb_save, "idb_save")
    _core.mcp.add_tool(ida_status, "ida_status")
    _core.mcp.add_tool(ida_query_context, "ida_query_context")
    _core.mcp.add_tool(get_struct_member, "get_struct_member")
    _core.mcp.add_tool(resolve_offset, "resolve_offset")
    _core.mcp.add_tool(pattern_scan, "pattern_scan")
    _core.mcp.add_tool(qword_value_scan, "qword_value_scan")
    _core.mcp.add_tool(type_info, "type_info")
    _core.mcp.add_tool(dump_layout, "dump_layout")
    _core.mcp.add_tool(list_functions_filter, "list_functions_filter")
    _spawn_periodic_saver()
    _core.main()
