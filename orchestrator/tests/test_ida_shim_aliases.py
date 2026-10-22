"""v0.16: unit tests for the shim's arg-alias rewriter and the schema-
driven None -> "" coercion. Lives in `ida_shim_ergo.py` (pure Python,
no IDA dependencies) so pytest can exercise it without stubbing the
shim's IDA-runtime imports."""

from __future__ import annotations

import sys
from pathlib import Path


# The helper module lives at orchestrator/ida_shim_ergo.py, next to the
# shim itself, not under `src/`. Add the orchestrator/ dir to the path
# once for the module import below.
_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import (  # noqa: E402
    ARG_ALIASES,
    apply_arg_aliases,
    collect_string_field_names,
    walk_and_coerce,
)


def test_apply_arg_aliases_rewrites_search_structures_name_to_filter():
    out = apply_arg_aliases("search_structures", {"name": "_RAID"})
    assert out == {"filter": "_RAID"}


def test_apply_arg_aliases_leaves_canonical_arg_alone():
    """A caller who already speaks the canonical arg should not have it
    rewritten."""
    out = apply_arg_aliases("search_structures", {"filter": "_RAID"})
    assert out == {"filter": "_RAID"}


def test_apply_arg_aliases_prefers_canonical_over_alias():
    """Both keys supplied: keep the canonical, drop the alias."""
    out = apply_arg_aliases("search_structures",
                             {"filter": "_RAID", "name": "IGNORED"})
    assert out == {"filter": "_RAID"}


def test_apply_arg_aliases_disassemble_function_address_to_start():
    out = apply_arg_aliases("disassemble_function", {"address": 0x14001d020})
    assert out == {"start_address": 0x14001d020}


def test_apply_arg_aliases_disassemble_function_ea_to_start():
    out = apply_arg_aliases("disassemble_function", {"ea": 0x14001d020})
    assert out == {"start_address": 0x14001d020}


def test_apply_arg_aliases_get_global_variable_value_by_name():
    out = apply_arg_aliases("get_global_variable_value_by_name",
                             {"name": "g_state"})
    assert out == {"variable_name": "g_state"}


def test_apply_arg_aliases_list_functions_limit_to_count():
    out = apply_arg_aliases("list_functions", {"limit": 20, "offset": 40})
    assert out == {"count": 20, "offset": 40}


def test_apply_arg_aliases_unknown_tool_pass_through():
    out = apply_arg_aliases("get_functions", {"name": "foo"})
    assert out == {"name": "foo"}


def test_apply_arg_aliases_returns_original_when_no_alias_hits():
    """No mutation of the input dict when the tool has aliases but the
    caller only supplied unaffected keys."""
    original = {"random": "arg"}
    out = apply_arg_aliases("search_structures", original)
    assert out == {"random": "arg"}


def test_collect_string_field_names_finds_nested_fields():
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "offset": {"type": "integer"},
                "comment": {"type": ["string", "null"]},
                "inner": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "flags": {"type": "integer"},
                    },
                },
            },
        },
    }
    names = collect_string_field_names(schema)
    assert {"name", "comment", "kind"} <= names
    assert "offset" not in names
    assert "flags" not in names


def test_collect_string_field_names_descends_into_anyof():
    schema = {
        "anyOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"type": "object", "properties": {"b": {"type": "string"}}},
        ]
    }
    names = collect_string_field_names(schema)
    assert names == {"a", "b"}


def test_walk_and_coerce_replaces_none_with_empty_string():
    data = [{"name": None, "offset": 4}]
    touched = walk_and_coerce(data, {"name"})
    assert touched is True
    assert data[0]["name"] == ""
    assert data[0]["offset"] == 4  # untouched


def test_walk_and_coerce_no_op_when_no_nones():
    data = {"name": "known", "kids": [{"name": "child"}]}
    touched = walk_and_coerce(data, {"name"})
    assert touched is False


def test_arg_aliases_registered_tools():
    """Fast tripwire: v0.16 shipped alias tables for five tools; v0.17
    C1-5 + C2-3 add exec_idapython and get_struct_member."""
    assert set(ARG_ALIASES) == {
        "search_structures",
        "get_global_variable_value_by_name",
        "disassemble_function",
        "list_functions",
        "list_strings_filter",
        "exec_idapython",
        "get_struct_member",
    }
