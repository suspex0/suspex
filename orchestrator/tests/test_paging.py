"""Paging + projection + filter tests for the shared list contract (Layer 3).

Covers `apply_page_opts` — the one helper every list-returning MCP tool
action funnels through. Tests are pure — no target, no session.
"""
from __future__ import annotations

import re

import pytest

from suspex.mcp._envelope import (
    DEFAULT_LIMITS,
    LIMIT_ALIASES,
    apply_page_opts,
    resolve_limit,
)


# ---------------------------------------------------------------------------
# resolve_limit — default table + caps
# ---------------------------------------------------------------------------

def test_resolve_limit_uses_action_default_when_unset():
    # mem_rw modules -> 64
    assert resolve_limit("mem_rw", "modules", 0) == 64
    # mem_rw handles -> 128
    assert resolve_limit("mem_rw", "handles", 0) == 128
    # Unknown (tool, action) -> passed default.
    assert resolve_limit("some", "action", 0, default_limit=42) == 42


def test_resolve_limit_respects_requested():
    assert resolve_limit("mem_rw", "modules", 8) == 8
    assert resolve_limit("mem_rw", "modules", 1024) == 1024


def test_resolve_limit_applies_global_cap():
    assert resolve_limit("mem_rw", "modules", 1024, global_cap=256) == 256


def test_resolve_limit_negative_treated_as_unset():
    # A negative (or zero) `requested` means "use the default for this action".
    assert resolve_limit("mem_rw", "modules", -5) == 64


# ---------------------------------------------------------------------------
# apply_page_opts — slicing
# ---------------------------------------------------------------------------

def _rows(n):
    return [{"i": i, "name": f"row{i}"} for i in range(n)]


def test_apply_slices_at_default_limit():
    items, count, total, next_off, truncated = apply_page_opts(
        _rows(200), tool="mem_rw", action="modules",
    )
    assert count == 64
    assert total == 200
    assert next_off == 64
    assert truncated is True
    assert items[0] == {"i": 0, "name": "row0"}
    assert items[-1] == {"i": 63, "name": "row63"}


def test_apply_respects_explicit_limit_and_offset():
    items, count, total, next_off, truncated = apply_page_opts(
        _rows(200), tool="mem_rw", action="modules",
        limit=32, offset=100,
    )
    assert count == 32
    assert total == 200
    assert items[0]["i"] == 100
    assert next_off == 132
    assert truncated is True


def test_apply_hits_end_of_list_without_truncation():
    items, count, total, next_off, truncated = apply_page_opts(
        _rows(50), tool="mem_rw", action="modules",
        limit=100,
    )
    assert count == 50
    assert total == 50
    assert next_off == 0
    assert truncated is False


def test_apply_global_cap_wins_over_high_limit():
    items, count, total, next_off, truncated = apply_page_opts(
        _rows(500), tool="mem_rw", action="modules",
        limit=1000, global_cap=100,
    )
    assert count == 100


# ---------------------------------------------------------------------------
# apply_page_opts — filter + projection
# ---------------------------------------------------------------------------

def test_apply_string_filter_substring_match():
    rows = [
        {"name": "kernel"},
        {"name": "ntdll.dll"},
        {"name": "user32.dll"},
    ]
    items, count, total, _, _ = apply_page_opts(
        rows, tool="mem_rw", action="modules", filter=".dll",
    )
    assert count == 2
    assert total == 2
    assert all(".dll" in r["name"] for r in items)


def test_apply_dict_filter_and_projection():
    rows = [
        {"pid": 4, "name": "System"},
        {"pid": 8, "name": "Idle"},
        {"pid": 400, "name": "csrss.exe"},
    ]
    items, count, total, _, _ = apply_page_opts(
        rows, tool="mem_rw", action="process_list",
        filter={"name": "s"},
        fields=["pid"],
    )
    # Substring "s" hits System and csrss.exe (case-insensitive).
    assert count == 2
    for r in items:
        # Only pid survives projection.
        assert list(r.keys()) == ["pid"]


def test_apply_dict_filter_with_regex():
    rows = [
        {"path": r"C:\Windows\System32\ntdll.dll"},
        {"path": r"C:\Windows\SysWOW64\ntdll.dll"},
        {"path": r"C:\Program Files\App\ntdll.dll"},
    ]
    pat = re.compile(r"^C:\\Windows\\Sys.*32.*\.dll$", re.IGNORECASE)
    items, count, total, _, _ = apply_page_opts(
        rows, tool="mem_rw", action="modules", filter={"path": pat},
    )
    assert count == 1
    assert "System32" in items[0]["path"]


def test_apply_summary_mode_returns_zero_items():
    items, count, total, next_off, truncated = apply_page_opts(
        _rows(500), tool="mem_rw", action="modules",
        summary=True,
    )
    assert items == []
    assert count == 0
    assert total == 500
    # summary keeps the "there's more" signal so callers know it wasn't 0.
    assert truncated is True


# ---------------------------------------------------------------------------
# Static tables
# ---------------------------------------------------------------------------

def test_default_limits_cover_15_actions():
    # Any drift from the plan's paging table is a code review concern; catch
    # regressions by pinning the size.
    assert len(DEFAULT_LIMITS) >= 15


def test_limit_aliases_cover_known_names():
    for name in ("max_results", "max_matches", "max_frames", "max_ins",
                 "count", "samples", "tail_bytes"):
        assert LIMIT_ALIASES[name] == "limit"


# ---------------------------------------------------------------------------
# list_envelope — composes apply_page_opts + envelope_ok
# ---------------------------------------------------------------------------

from suspex.mcp._envelope import list_envelope


def test_list_envelope_shape():
    env = list_envelope(
        [{"name": f"mod{i}", "base": i * 0x1000} for i in range(200)],
        tool="mem_rw", action="modules",
        limit=8, offset=16,
    )
    assert env["ok"] is True
    assert env["kind"] == "modules"
    assert env["tool"] == "mem_rw"
    assert env["action"] == "modules"
    # Uniform: rows live at data.items regardless of the underlying subject.
    assert list(env["data"].keys()) == ["items"]
    assert len(env["data"]["items"]) == 8
    assert env["data"]["items"][0]["name"] == "mod16"

    s = env["summary"]
    assert s["item_count"] == 8
    assert s["item_total"] == 200
    assert s["truncated"] is True
    assert s["next_cursor"] == "offset:24"


def test_list_envelope_final_page_no_cursor():
    env = list_envelope(
        [{"name": f"mod{i}"} for i in range(50)],
        tool="mem_rw", action="modules",
        limit=100,
    )
    s = env["summary"]
    assert s["item_count"] == 50
    assert s["item_total"] == 50
    assert s["truncated"] is False
    assert "next_cursor" not in s


def test_list_envelope_summary_mode_still_populates_totals():
    env = list_envelope(
        [{"i": i} for i in range(300)],
        tool="mem_rw", action="modules",
        summary=True,
    )
    assert env["data"]["items"] == []
    assert env["summary"]["item_total"] == 300
    assert env["summary"]["item_count"] == 0


def test_list_envelope_extras_land_alongside_items():
    env = list_envelope(
        [{"i": i} for i in range(5)],
        tool="mem_rw", action="modules",
        extras={"space": "kernel", "kernel_lookup": True},
    )
    assert env["data"]["items"] == [{"i": i} for i in range(5)]
    assert env["data"]["space"] == "kernel"
    assert env["data"]["kernel_lookup"] is True
