"""D-2: `analyze_struct_detailed` compact default + members= projection.

The vendored plugin dumped the full 232-member RAID_ADAPTER_EXTENSION
every call (28 KB of wire tokens for a caller who wanted one field).
v0.17 D-2 lands a shim-side transformer that collapses the response to a
summary (name, size, member_count, first 10 members) unless the caller
opts into ``detail=true`` or names specific ``members=[<field>...]``.

Pure logic in :func:`ida_shim_ergo.compact_analyze_struct`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import compact_analyze_struct  # noqa: E402


def _member(name: str, offset: int, size: int, type_repr: str) -> dict:
    return {"name": name, "offset": f"0x{offset:X}",
            "size": size, "type": type_repr}


# --------------------------------------------------------------------------- #
# Compact default (detail=False).
# --------------------------------------------------------------------------- #


def test_d_2_default_returns_summary():
    raw = {
        "name": "RAID_ADAPTER_EXTENSION",
        "size": 0x800,
        "members": [_member(f"Field{i}", i * 8, 8, "u64") for i in range(50)],
    }
    out = compact_analyze_struct(raw)
    assert out["ok"] is True
    assert out["kind"] == "summary"
    assert out["member_count"] == 50
    assert out["size"] == 0x800
    assert out["name"] == "RAID_ADAPTER_EXTENSION"
    # First 10 members preview.
    assert len(out["first_10"]) == 10
    assert out["first_10"][0]["name"] == "Field0"
    assert out["first_10"][9]["name"] == "Field9"
    assert "hint" in out
    assert "detail=true" in out["hint"] or "members=" in out["hint"]


def test_d_2_default_summary_hides_full_member_list():
    raw = {
        "name": "S", "size": 40,
        "members": [_member(f"m{i}", i * 8, 8, "u64") for i in range(5)],
    }
    out = compact_analyze_struct(raw)
    # Summary should not have a top-level `members` key — that's the full
    # dump. The compact preview lives under `first_10`.
    assert "members" not in out


# --------------------------------------------------------------------------- #
# Explicit detail=True — full member list.
# --------------------------------------------------------------------------- #


def test_d_2_detail_true_returns_full():
    members = [_member(f"m{i}", i * 8, 8, "u64") for i in range(15)]
    raw = {"name": "S", "size": 120, "members": members}
    out = compact_analyze_struct(raw, detail=True)
    assert out["kind"] == "detailed"
    assert out["member_count"] == 15
    assert len(out["members"]) == 15


# --------------------------------------------------------------------------- #
# Explicit members=[...] projection — return only named fields.
# --------------------------------------------------------------------------- #


def test_d_2_members_subset_returns_only_named():
    members = [
        _member("Header", 0x00, 0x18, "_DISPATCHER_HEADER"),
        _member("Signature", 0x18, 0x08, "ULONG"),
        _member("Flink", 0x20, 0x08, "LIST_ENTRY *"),
        _member("Blink", 0x28, 0x08, "LIST_ENTRY *"),
    ]
    raw = {"name": "RTL_HTE", "size": 0x30, "members": members}
    out = compact_analyze_struct(raw, members=["Signature", "Flink"])
    assert out["kind"] == "subset"
    assert out["member_count"] == 4  # original total
    assert out["returned"] == 2
    assert out["requested"] == ["Signature", "Flink"]
    names = [m["name"] for m in out["members"]]
    assert names == ["Signature", "Flink"]


def test_d_2_members_subset_takes_precedence_over_detail():
    # Both `detail=True` and `members=[...]` — the explicit projection
    # wins. This mirrors the plan's short-circuit behavior.
    members = [_member("A", 0, 8, "u64"), _member("B", 8, 8, "u64")]
    raw = {"name": "S", "size": 16, "members": members}
    out = compact_analyze_struct(raw, detail=True, members=["A"])
    assert out["kind"] == "subset"
    assert out["returned"] == 1


def test_d_2_members_unknown_field_returns_empty_subset():
    members = [_member("A", 0, 8, "u64")]
    raw = {"name": "S", "size": 8, "members": members}
    out = compact_analyze_struct(raw, members=["ZZZ"])
    assert out["returned"] == 0
    assert out["members"] == []


# --------------------------------------------------------------------------- #
# Shape robustness — raw might be a list, a dict, or an error shape.
# --------------------------------------------------------------------------- #


def test_d_2_list_raw_response_normalised():
    # Older vendored builds returned a bare list of member dicts.
    raw = [_member(f"m{i}", i * 8, 8, "u64") for i in range(3)]
    out = compact_analyze_struct(raw, name="Fallback")
    assert out["kind"] == "summary"
    assert out["member_count"] == 3
    # name comes from the transformer arg since the raw list carried no name.
    assert out["name"] == "Fallback"


def test_d_2_no_members_field_returns_zero_count():
    raw = {"name": "S", "size": 0, "no_such_key": True}
    out = compact_analyze_struct(raw)
    assert out["member_count"] == 0
    assert out["first_10"] == []


def test_d_2_struct_name_key_variant_supported():
    # Some vendored builds emitted `struct_name` instead of `name`.
    raw = {"struct_name": "Odd", "size": 8,
           "members": [_member("m", 0, 8, "u64")]}
    out = compact_analyze_struct(raw)
    assert out["name"] == "Odd"


def test_d_2_first_10_shows_up_to_available_when_under_ten():
    raw = {"name": "Tiny", "size": 24,
           "members": [_member(f"m{i}", i * 8, 8, "u64") for i in range(3)]}
    out = compact_analyze_struct(raw)
    assert len(out["first_10"]) == 3
