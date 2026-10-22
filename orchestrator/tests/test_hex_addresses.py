"""Tests for _hex_addresses — the every-address-is-hex normalizer.

Guards against the developer-feedback regression where `mem_rw modules`
returned `base: "18446735308801310720"` (a decimal string overflowing to
0xFFFFF80000ABC000) and every caller had to convert.
"""
from __future__ import annotations

import pytest

from suspex.mcp._hex_addresses import (
    HEX_ADDRESS_KEYS,
    HEX_SIZE_KEYS,
    hexify,
    hexify_dict,
)


def test_hexify_int():
    assert hexify(0) == "0x0"
    assert hexify(1) == "0x1"
    assert hexify(0xFFFFF80000ABC000) == "0xfffff80000abc000"
    assert hexify(-1) == "-0x1"


def test_hexify_decimal_string_overflow_case():
    # The exact case from the feedback: mem_rw modules returning a
    # decimal string for a kernel base VA. Round-trip through int() ensures
    # the hexify handles the full 64-bit range without loss.
    n = 18446735308801310720            # arbitrary large kernel VA
    assert hexify(str(n)) == hex(n)
    assert hexify(str(n)) == "0xfffff80742c20000"


def test_hexify_hex_string_normalized():
    assert hexify("0xABCD") == "0xabcd"
    assert hexify("0X1234") == "0x1234"


def test_hexify_pass_through_non_numeric():
    assert hexify("some name") == "some name"
    assert hexify("") == ""
    # Booleans must not become "0x0" / "0x1"
    assert hexify(True) is True
    assert hexify(False) is False


def test_hexify_dict_shallow():
    inp = {"name": "foo", "base": 0xFFFFF80000ABC000, "size": 4096}
    out = hexify_dict(inp)
    assert out["name"] == "foo"
    assert out["base"] == "0xfffff80000abc000"
    assert out["base_int"] == 0xFFFFF80000ABC000
    assert out["size"] == "0x1000"
    assert out["size_int"] == 4096


def test_hexify_dict_recursive():
    inp = {"module": "foo",
           "regions": [{"start": 0x1000, "end": 0x2000, "protect": 0x20}]}
    out = hexify_dict(inp)
    r = out["regions"][0]
    assert r["start"] == "0x1000"
    assert r["end"] == "0x2000"
    # protect is a size/address-like value only if we list it; not by default
    assert r["protect"] == 0x20      # left alone


def test_hexify_dict_preserves_hint_and_error_strings():
    """Verifies HEX_KEY_EXCLUSIONS: nested text fields don't get scanned."""
    inp = {"error": "call took 4096 bytes to load", "hint": "size 0x1000 requested",
           "base": 0x1234}
    out = hexify_dict(inp)
    assert out["error"] == "call took 4096 bytes to load"
    assert out["hint"] == "size 0x1000 requested"
    assert out["base"] == "0x1234"


def test_hexify_dict_no_int_mirror_when_disabled():
    inp = {"base": 0x1000}
    out = hexify_dict(inp, add_int_mirror=False)
    assert out == {"base": "0x1000"}
    assert "base_int" not in out


def test_hexify_dict_bool_not_hex():
    inp = {"base": 0x1000, "loaded": True, "eof": False}
    out = hexify_dict(inp)
    assert out["loaded"] is True
    assert out["eof"] is False


def test_hexify_dict_rva_mirror():
    """v0.24: symbols_manage resolve returned bare-decimal RVAs (the
    15666624 -> 0xEF2C00 hand-conversion incident). `rva`/`symbol_rva`
    must hexify with an `_int` mirror like every other address-like key."""
    inp = {"symbols": {"PsLoadedModuleList": {"rva": 15666624,
                                              "va": 0xFFFFF80100EF0DC0}},
           "symbol_rva": 15666560}
    out = hexify_dict(inp)
    row = out["symbols"]["PsLoadedModuleList"]
    assert row["rva"] == "0xef0dc0"
    assert row["rva_int"] == 15666624
    assert row["va"] == "0xfffff80100ef0dc0"
    assert out["symbol_rva"] == "0xef0d80"
    assert "rva" in HEX_ADDRESS_KEYS and "symbol_rva" in HEX_ADDRESS_KEYS


def test_all_hex_keys_are_lowercase_strings():
    for k in HEX_ADDRESS_KEYS | HEX_SIZE_KEYS:
        assert isinstance(k, str) and k.islower(), f"bad hex key: {k!r}"


def test_hexify_dict_empty_string_left_alone():
    inp = {"path": "", "base": ""}
    out = hexify_dict(inp)
    assert out["path"] == ""
    assert out["base"] == ""      # empty is not a number; leave alone
