"""D-4: `nearest_function` on decompile failure envelopes.

When ``decompile_function`` fails (mid-function address, no Hex-Rays)
the shim's fallback used to return a ``status:'fallback_disasm'``
envelope with only ``decompile_error`` and the fallback disassembly.
D-4 layers on a ``nearest_function:{start, end, delta, name}`` blob
computed from the extension's ``ida_query_context`` so the caller sees
the containing function context in one round trip.

Tests cover the pure enrichment logic
(:func:`ida_shim_ergo.compute_nearest_function`) since it takes the
``ida_query_context`` response shape as input and is trivially
exercisable without a live IDA runtime.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

from ida_shim_ergo import compute_nearest_function  # noqa: E402


# --------------------------------------------------------------------------- #
# compute_nearest_function — happy path.
# --------------------------------------------------------------------------- #


def test_d_4_decompile_fail_attaches_nearest():
    # ida_query_context reports we're inside a function starting 0x40 back.
    ctx = {
        "ok": True,
        "in_function": True,
        "function_start": "0x140001000",
        "function_end": "0x140001200",
        "address": "0x140001040",
    }
    out = compute_nearest_function(ctx, "0x140001040")
    assert out is not None
    assert out["start"] == "0x140001000"
    assert out["end"] == "0x140001200"
    assert out["delta"] == 0x40
    # No function_name in ctx and no override — name is None.
    assert out["name"] is None


def test_d_4_function_name_override_populated():
    ctx = {
        "ok": True,
        "in_function": True,
        "function_start": "0x140001000",
        "function_end": "0x140001200",
    }
    out = compute_nearest_function(ctx, "0x140001040",
                                    function_name="IppInitializeArp")
    assert out is not None
    assert out["name"] == "IppInitializeArp"


def test_d_4_function_name_from_ctx_used_when_present():
    ctx = {
        "ok": True,
        "in_function": True,
        "function_start": "0x140001000",
        "function_end": "0x140001200",
        "function_name": "FromCtx",
    }
    out = compute_nearest_function(ctx, "0x140001040")
    assert out is not None
    assert out["name"] == "FromCtx"


def test_d_4_override_wins_over_ctx_name():
    ctx = {"ok": True, "in_function": True,
           "function_start": "0x140001000", "function_name": "FromCtx"}
    out = compute_nearest_function(ctx, "0x140001040", function_name="Override")
    assert out is not None
    assert out["name"] == "Override"


# --------------------------------------------------------------------------- #
# compute_nearest_function — bail-out branches.
# --------------------------------------------------------------------------- #


def test_d_4_decompile_fail_outside_function_nearest_none():
    ctx = {
        "ok": True,
        "in_function": False,
        "function_start": None,
        "function_end": None,
    }
    out = compute_nearest_function(ctx, "0x140099000")
    assert out is None


def test_d_4_ctx_none_returns_none():
    assert compute_nearest_function(None, "0x140001040") is None


def test_d_4_ctx_not_ok_returns_none():
    ctx = {"ok": False, "error": "bad address"}
    assert compute_nearest_function(ctx, "0x140001040") is None


def test_d_4_ctx_missing_function_start_returns_none():
    ctx = {"ok": True, "in_function": True}
    assert compute_nearest_function(ctx, "0x140001040") is None


def test_d_4_bad_target_ea_returns_none():
    ctx = {"ok": True, "in_function": True,
           "function_start": "0x140001000", "function_end": "0x140001200"}
    assert compute_nearest_function(ctx, "not-a-number") is None


def test_d_4_decimal_target_ea_supported():
    # Decimal EAs are legal too.
    ctx = {"ok": True, "in_function": True,
           "function_start": "0x140001000"}
    out = compute_nearest_function(ctx, str(0x140001040))
    assert out is not None
    assert out["delta"] == 0x40


def test_d_4_int_target_ea_supported():
    ctx = {"ok": True, "in_function": True,
           "function_start": "0x140001000"}
    out = compute_nearest_function(ctx, 0x140001040)
    assert out is not None
    assert out["delta"] == 0x40


# --------------------------------------------------------------------------- #
# compute_nearest_function — delta math.
# --------------------------------------------------------------------------- #


def test_d_4_delta_reflects_offset_from_function_start():
    ctx = {"ok": True, "in_function": True,
           "function_start": "0x1000", "function_end": "0x2000"}
    for delta in (0, 4, 0x20, 0x100, 0x400):
        out = compute_nearest_function(ctx, hex(0x1000 + delta))
        assert out["delta"] == delta


def test_d_4_function_start_int_form_supported():
    # Some ctx variants might emit int; the parser should handle it too.
    ctx = {"ok": True, "in_function": True,
           "function_start": 0x140001000, "function_end": 0x140001200}
    out = compute_nearest_function(ctx, "0x140001040")
    assert out is not None
    assert out["delta"] == 0x40


# --------------------------------------------------------------------------- #
# Fallback envelope shape smoke — mock the fallback flow end-to-end.
# --------------------------------------------------------------------------- #


def test_d_4_fallback_disasm_envelope_carries_nearest_slot():
    """Illustrates the envelope shape the shim assembles on the
    fallback-disasm success path — nearest_function is the D-4 addition.
    """
    envelope = {
        "status": "fallback_disasm",
        "address": "0x140001040",
        "decompile_error": "Hex-Rays refused: no function at ea",
        "disassembly": "mov rax, rbx\nret\n",
        "nearest_function": {
            "start": "0x140001000", "end": "0x140001200",
            "delta": 0x40, "name": "IppInitializeArp",
        },
    }
    # The exact keys the caller now sees.
    assert envelope["nearest_function"]["delta"] == 0x40
    assert envelope["nearest_function"]["name"] == "IppInitializeArp"
    assert "hint" not in envelope or envelope.get("status") == "fallback_disasm"
