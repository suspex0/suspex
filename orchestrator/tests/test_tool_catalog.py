"""Tool-catalog drift test: the committed snapshot must match the live
FastMCP registry exactly.

On failure regenerate and commit:

    uv run python scripts/gen_tool_catalog.py
"""

from __future__ import annotations

import pytest

import _catalog

KNOWN_TOOLS = {
    "target_manage", "mem_rw", "debug_manage", "bp_manage", "exec_manage",
    "file_manage", "ida_manage", "ghidra_manage", "script_manage",
    "knowledge_manage", "findings_manage", "reg_manage", "watchdog_manage",
    "value_manage", "emulate_manage", "bin_manage", "device_manage",
    "event_manage", "symbols_manage", "dump_manage", "screen_manage",
}


async def test_catalog_matches_live_registry() -> None:
    committed = _catalog.load_catalog()
    live = await _catalog.build_live_catalog()
    if live != committed:
        pytest.fail(
            "tool catalog drifted; run "
            "`uv run python scripts/gen_tool_catalog.py` and commit the result"
        )


def test_catalog_contains_exactly_the_known_tools() -> None:
    catalog = _catalog.load_catalog()
    names = {entry["tool"] for entry in catalog["tools"]}
    assert names == KNOWN_TOOLS


def test_findings_manage_is_knowledge_alias() -> None:
    catalog = _catalog.load_catalog()
    by_name = {entry["tool"]: entry for entry in catalog["tools"]}
    assert by_name["findings_manage"]["alias_of"] == "knowledge_manage"
    assert by_name["knowledge_manage"]["alias_of"] is None
