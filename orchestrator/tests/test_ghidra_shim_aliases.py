"""Unit tests for ghidra_shim_ergo arg-alias rewriting — mirrors
test_ida_shim_aliases.py. Pure Python, no JVM/Ghidra needed."""

from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ghidra_shim_ergo import ARG_ALIASES, apply_arg_aliases  # noqa: E402


def test_decompile_address_to_name_or_address():
    out = apply_arg_aliases("decompile_function", {"address": "0x1400"})
    assert out == {"name_or_address": "0x1400"}


def test_decompile_start_address_to_name_or_address():
    out = apply_arg_aliases("decompile_function",
                            {"start_address": "0x1400"})
    assert out == {"name_or_address": "0x1400"}


def test_canonical_wins_over_alias():
    """Both keys supplied: keep the canonical, drop the alias."""
    out = apply_arg_aliases(
        "decompile_function",
        {"name_or_address": "main", "address": "0x1400"})
    assert out == {"name_or_address": "main"}


def test_disasm_normalizes_to_address():
    out = apply_arg_aliases("disassemble_function",
                            {"name_or_address": "0x1400"})
    assert out == {"address": "0x1400"}


def test_rename_variable_function_alias():
    out = apply_arg_aliases("rename_variable",
                            {"function": "sub_1400", "old_name": "v1",
                             "new_name": "counter"})
    assert out["function_name_or_address"] == "sub_1400"
    assert "function" not in out


def test_exec_script_code_to_source():
    out = apply_arg_aliases("exec_ghidra_script", {"code": "print(1)"})
    assert out == {"source": "print(1)"}


def test_pattern_scan_hex_to_hex_pattern():
    out = apply_arg_aliases("pattern_scan", {"hex": "48 8B ?? 20"})
    assert out == {"hex_pattern": "48 8B ?? 20"}


def test_unknown_tool_passthrough():
    args = {"anything": 1}
    assert apply_arg_aliases("not_a_tool", args) == args


def test_no_alias_table_mutation():
    """apply_arg_aliases must not mutate the caller's dict."""
    args = {"address": "0x1400"}
    apply_arg_aliases("decompile_function", args)
    assert args == {"address": "0x1400"}


def test_struct_member_aliases():
    out = apply_arg_aliases("get_struct_member",
                            {"struct": "_EPROCESS", "member": "ImageFileName"})
    assert out == {"struct_name": "_EPROCESS",
                   "member_name": "ImageFileName"}
