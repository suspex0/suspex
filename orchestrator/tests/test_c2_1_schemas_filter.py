"""C2-1: `ida_manage schemas` filter + `action="tools"` inventory.

Exercises the pure helpers exposed in
``orchestrator/src/suspex/mcp/tools.py`` — the filter and one-line
description path — so the schemas-payload trimming is verified without
spinning up the full FastMCP context.
"""
from __future__ import annotations

from suspex.mcp.tools import (  # noqa: E402
    _filter_ida_schemas,
    _one_line_desc,
    _parse_ida_schemas_filter,
)


# --- _one_line_desc -----------------------------------------------------

def test_c2_1_one_line_returns_empty_on_empty_input():
    assert _one_line_desc("") == ""


def test_c2_1_one_line_stops_at_first_sentence():
    txt = "Decompile the given function. Long-running on big binaries."
    assert _one_line_desc(txt) == "Decompile the given function"


def test_c2_1_one_line_stops_at_newline():
    txt = "Decompile the given function.\n\nExtended prose here."
    assert _one_line_desc(txt) == "Decompile the given function"


def test_c2_1_one_line_hard_caps_long_text():
    """A 200 char single-sentence description without a period must still
    fit inside the cap with an ellipsis marker."""
    body = "x" * 200
    out = _one_line_desc(body, cap=120)
    assert len(out) == 120
    assert out.endswith("...")


# --- _parse_ida_schemas_filter -----------------------------------------

def test_c2_1_parse_filter_no_args_returns_empty_set():
    assert _parse_ida_schemas_filter("") == set()
    assert _parse_ida_schemas_filter("{}") == set()


def test_c2_1_parse_filter_list_shape():
    out = _parse_ida_schemas_filter('{"tools": ["decompile_function", "get_xrefs_to"]}')
    assert out == {"decompile_function", "get_xrefs_to"}


def test_c2_1_parse_filter_bare_string_shape():
    """A single tool name as a bare string is convenient sugar."""
    out = _parse_ida_schemas_filter('{"tools": "decompile_function"}')
    assert out == {"decompile_function"}


def test_c2_1_parse_filter_malformed_json_is_empty():
    """Bad JSON must not raise — a caller who typos should still get the
    default full-dump behaviour, not an internal server error."""
    assert _parse_ida_schemas_filter("not-json") == set()


def test_c2_1_parse_filter_ignores_empty_entries():
    out = _parse_ida_schemas_filter('{"tools": ["decompile_function", ""]}')
    assert out == {"decompile_function"}


# --- _filter_ida_schemas -----------------------------------------------

def _mk(name: str, desc: str = "") -> dict:
    return {"name": name, "description": desc,
            "inputSchema": {"type": "object", "properties": {}}}


def test_c2_1_filter_no_filter_returns_all_projected_rows():
    schemas = [_mk("decompile_function", "Decompile."), _mk("get_xrefs_to")]
    out = _filter_ida_schemas(schemas, set())
    assert len(out) == 2
    # Projection keeps exactly the three envelope keys.
    assert set(out[0].keys()) == {"name", "description", "inputSchema"}


def test_c2_1_filter_with_wanted_returns_subset():
    schemas = [_mk("decompile_function"), _mk("get_xrefs_to"),
               _mk("list_functions")]
    out = _filter_ida_schemas(schemas, {"list_functions"})
    assert len(out) == 1
    assert out[0]["name"] == "list_functions"


def test_c2_1_filter_unknown_tool_returns_empty_list():
    """A caller filter that hits nothing returns an empty tools list —
    the ida_manage envelope carries `count:0` + `filtered:true`."""
    schemas = [_mk("decompile_function"), _mk("get_xrefs_to")]
    out = _filter_ida_schemas(schemas, {"never_shipped"})
    assert out == []


def test_c2_1_filter_preserves_source_ordering():
    schemas = [_mk("a"), _mk("b"), _mk("c"), _mk("d")]
    out = _filter_ida_schemas(schemas, {"a", "c", "d"})
    assert [r["name"] for r in out] == ["a", "c", "d"]


# --- inventory-payload perf assertion ----------------------------------

def test_c2_1_tools_inventory_much_smaller_than_full_schemas():
    """The inventory-view payload for a 60-tool backend must be
    substantially smaller than the equivalent full-schemas dump.

    Guardrail against a regression that leaves multi-paragraph
    docstrings in the ``tools`` action's response — the whole point of
    the discovery call is that it stays inexpensive."""
    import json as _json

    long_desc = ("Do a thing across the IDB in a way that is described "
                 "at excruciating length so we prove the one-liner "
                 "collapser does its job. " * 6)
    schemas = [_mk(f"tool_{i:02d}", long_desc) for i in range(60)]
    inventory_rows = [{"name": t["name"],
                       "one_liner": _one_line_desc(t["description"])}
                      for t in schemas]
    full_rows = [{"name": t["name"],
                  "description": t["description"],
                  "inputSchema": t["inputSchema"]} for t in schemas]
    inv_payload = _json.dumps({"count": 60, "tools": inventory_rows})
    full_payload = _json.dumps({"count": 60, "tools": full_rows})
    # Inventory should be an order of magnitude smaller — the
    # one-liner path is the discovery cheap-fetch step.
    assert len(inv_payload) < len(full_payload) / 5, (
        f"inventory={len(inv_payload)} full={len(full_payload)}; "
        "one-liner should give at least a 5x reduction")
    # Absolute ceiling: a 60-tool inventory (name + one-liner) with
    # 120-char one-liners fits well under 12 KB; enforce it.
    assert len(inv_payload) < 12000, (
        f"inventory grew to {len(inv_payload)} bytes; budget < 12000")
