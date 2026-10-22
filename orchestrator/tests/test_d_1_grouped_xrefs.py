"""D-1: grouped-by-function xrefs transformer for ``get_xrefs_to``.

The vendored ida-pro-mcp plugin returns ``list[Xref]`` with a fully
nested ``Function`` per xref — 39 xrefs from ~30 unique functions came
to 7.7 KB of mostly duplication on the ARP session. v0.17 D-1 groups by
containing function, projects only the fields the caller asks for, and
opts back into the flat shape via ``group_by_function=False``.

The pure logic lives in :func:`ida_shim_ergo.group_xrefs` so tests can
round-trip a synthetic raw response through the transformer without
booting the IDA runtime.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import group_xrefs  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures — synthetic raw xref rows.
# --------------------------------------------------------------------------- #


def _row(ea: int, kind: str, iscode: bool, fn_ea: int, fn_name: str) -> dict:
    """Return an ``Xref``-shaped row matching what the vanilla plugin emits."""
    return {
        "ea": f"0x{ea:X}",
        "kind": kind,
        "iscode": iscode,
        "function": {"start_ea": f"0x{fn_ea:X}", "name": fn_name},
    }


def _row_no_function(ea: int, kind: str) -> dict:
    """Xref emitted from data or an undefined region (no containing func)."""
    return {"ea": f"0x{ea:X}", "kind": kind, "iscode": False}


# --------------------------------------------------------------------------- #
# Core behaviour.
# --------------------------------------------------------------------------- #


def test_d_1_grouped_default():
    raw = [
        _row(0x1400_10A0, "call", True, 0x1400_1000, "IppInitializeArp"),
        _row(0x1400_10B4, "call", True, 0x1400_1000, "IppInitializeArp"),
        _row(0x1400_20C0, "call", True, 0x1400_2000, "IppSendArpRequest"),
    ]
    out = group_xrefs(raw, target_ea="0x140030000")

    assert out["grouped"] is True
    assert out["function_count"] == 2
    assert out["xref_count"] == 3
    assert out["target_ea"] == "0x140030000"

    # Sorted by start_ea; two IppInitializeArp xrefs get one group with count=2.
    g0, g1 = out["groups"]
    assert g0["function"]["start_ea"] == "0x14001000"
    assert g0["function"]["name"] == "IppInitializeArp"
    assert g0["count"] == 2
    assert g1["function"]["start_ea"] == "0x14002000"
    assert g1["count"] == 1

    # Each row projection keeps every canonical field by default.
    for row in g0["xrefs"]:
        assert set(row) >= {"ea", "kind", "iscode"}
        assert "function" not in row  # header carries the function, not the row


def test_d_1_flat_mode_returns_flat_shape():
    raw = [
        _row(0x1400_10A0, "call", True, 0x1400_1000, "IppInitializeArp"),
        _row(0x1400_20C0, "call", True, 0x1400_2000, "IppSendArpRequest"),
    ]
    out = group_xrefs(raw, group_by_function=False)
    assert out["grouped"] is False
    assert out["xref_count"] == 2
    assert isinstance(out["xrefs"], list)
    assert all("function" not in row for row in out["xrefs"])


def test_d_1_fields_projection_drops_kind():
    raw = [
        _row(0x1400_10A0, "call", True, 0x1400_1000, "IppInitializeArp"),
        _row(0x1400_10B4, "jmp",  True, 0x1400_1000, "IppInitializeArp"),
    ]
    out = group_xrefs(raw, fields=["ea"])
    g = out["groups"][0]
    for row in g["xrefs"]:
        assert set(row) == {"ea"}
        assert "kind" not in row


def test_d_1_data_xref_bucketed_under_zero():
    raw = [
        _row(0x1400_10A0, "call", True, 0x1400_1000, "IppInitializeArp"),
        _row_no_function(0x1400_1CC0, "data"),
    ]
    out = group_xrefs(raw)
    # Two groups: the function group, and the <data> sentinel bucket.
    assert out["function_count"] == 2
    data_group = out["groups"][0]  # start_ea=0 sorts first
    assert data_group["function"]["start_ea"] == "0x0"
    assert data_group["function"]["name"] == "<data>"
    assert data_group["count"] == 1


def test_d_1_deterministic_group_order():
    # Rows arrive in arbitrary order; groups come back sorted by start_ea.
    raw = [
        _row(0x1400_30F0, "call", True, 0x1400_3000, "C"),
        _row(0x1400_10A0, "call", True, 0x1400_1000, "A"),
        _row(0x1400_20B4, "call", True, 0x1400_2000, "B"),
    ]
    out = group_xrefs(raw)
    names = [g["function"]["name"] for g in out["groups"]]
    assert names == ["A", "B", "C"]


def test_d_1_int_ea_normalized_to_hex_string():
    # Raw rows can carry int eas (SWIG). Projection must normalize.
    raw = [{"frm": 0x1400_10A0, "type": "call", "iscode": True,
            "function": {"start_ea": 0x1400_1000, "name": "F"}}]
    out = group_xrefs(raw)
    g = out["groups"][0]
    assert g["function"]["start_ea"] == "0x14001000"
    assert g["xrefs"][0]["ea"] == "0x140010A0"
    assert g["xrefs"][0]["kind"] == "call"


def test_d_1_empty_input_returns_empty_shape():
    out = group_xrefs([])
    assert out["grouped"] is True
    assert out["function_count"] == 0
    assert out["xref_count"] == 0
    assert out["groups"] == []


def test_d_1_flat_empty_projection_still_flat_and_empty():
    out = group_xrefs([], group_by_function=False, fields=["ea"])
    assert out["grouped"] is False
    assert out["xrefs"] == []


def test_d_1_alias_kind_and_frm_map_to_canonical():
    # The vanilla shape used `type` and `frm`; both map to canonical
    # `kind` / `ea` — the caller should not have to know either spelling.
    raw = [{"frm": "0x1234", "type": "call", "iscode": True,
            "function": {"start_ea": "0x1000", "name": "F"}}]
    out = group_xrefs(raw, fields=["ea", "kind"])
    row = out["groups"][0]["xrefs"][0]
    assert row == {"ea": "0x1234", "kind": "call"}
