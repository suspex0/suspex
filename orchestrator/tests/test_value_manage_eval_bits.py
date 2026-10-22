"""Bit-manipulation function tests for the value_manage `eval` evaluator.

Covers popcount, ctz, clz, byteswap, rotl/rotr, sign/zero extend, align_up/
down, and in_range. Every function is exercised through the public
``evaluate`` entry point so both the walker and the whitelist wire-up are
exercised together.
"""
from __future__ import annotations

import pytest

from suspex.mcp.value_eval import EvalError, evaluate


class TestBitCountingFunctions:
    def test_popcount(self) -> None:
        assert evaluate("popcount(0xFF)")["result"] == 8
        assert evaluate("popcount(0)")["result"] == 0
        assert evaluate("popcount(0xDEADBEEF)")["result"] == \
            bin(0xDEADBEEF).count("1")

    def test_ctz_basic(self) -> None:
        assert evaluate("ctz(0x100)")["result"] == 8
        assert evaluate("ctz(1)")["result"] == 0
        assert evaluate("ctz(0x80000000)")["result"] == 31

    def test_ctz_of_zero_returns_width(self) -> None:
        # Default width is 64
        assert evaluate("ctz(0)")["result"] == 64

    def test_clz_32_and_64(self) -> None:
        assert evaluate("clz(1, 32)")["result"] == 31
        assert evaluate("clz(0x80000000, 32)")["result"] == 0
        assert evaluate("clz(1, 64)")["result"] == 63
        assert evaluate("clz(0, 64)")["result"] == 64
        assert evaluate("clz(0, 32)")["result"] == 32


class TestByteswap:
    def test_byteswap16(self) -> None:
        assert evaluate("byteswap16(0xABCD)")["result"] == 0xCDAB

    def test_byteswap32(self) -> None:
        assert evaluate("byteswap32(0xDEADBEEF)")["result"] == 0xEFBEADDE

    def test_byteswap64(self) -> None:
        assert evaluate("byteswap64(0x0102030405060708)")["result"] == \
            0x0807060504030201


class TestRotate:
    def test_rotl_width32(self) -> None:
        assert evaluate("rotl(0x80000000, 1, width=32)")["result"] == 1

    def test_rotl_rotr_symmetry_width32(self) -> None:
        # rotr(rotl(x, n), n) == x
        r = evaluate("rotr(rotl(0xDEADBEEF, 5, width=32), 5, width=32)")
        assert r["result"] == 0xDEADBEEF

    def test_rotl_rotr_symmetry_width64(self) -> None:
        r = evaluate("rotr(rotl(0x0123456789ABCDEF, 17), 17)")
        assert r["result"] == 0x0123456789ABCDEF


class TestExtend:
    def test_sign_extend_negative(self) -> None:
        assert evaluate("sign_extend(0x80, 8, 64)")["result"] == \
            0xFFFFFFFFFFFFFF80

    def test_sign_extend_positive(self) -> None:
        assert evaluate("sign_extend(0x7F, 8, 64)")["result"] == 0x7F

    def test_zero_extend(self) -> None:
        assert evaluate("zero_extend(0x80, 8, 64)")["result"] == 0x80
        assert evaluate("zero_extend(0xFF, 8, 64)")["result"] == 0xFF


class TestAlign:
    def test_align_up_needs_to_round(self) -> None:
        assert evaluate("align_up(0x1005, 0x1000)")["result"] == 0x2000

    def test_align_up_already_aligned(self) -> None:
        assert evaluate("align_up(0x1000, 0x1000)")["result"] == 0x1000

    def test_align_down_rounds_toward_zero(self) -> None:
        assert evaluate("align_down(0x1FFF, 0x1000)")["result"] == 0x1000

    def test_align_down_already_aligned(self) -> None:
        assert evaluate("align_down(0x1000, 0x1000)")["result"] == 0x1000

    def test_align_up_non_power_of_two_rejected(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("align_up(0x1000, 0xFFF)")
        assert exc.value.kind == "bad_expr"

    def test_align_down_non_power_of_two_rejected(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("align_down(0x1000, 3)")
        assert exc.value.kind == "bad_expr"


class TestInRange:
    def test_hit(self) -> None:
        assert evaluate("in_range(0x1500, 0x1000, 0x1000)")["result"] == 1

    def test_right_open_upper_bound(self) -> None:
        # Interval is [base, base+size) so base+size is NOT in range
        assert evaluate("in_range(0x2000, 0x1000, 0x1000)")["result"] == 0

    def test_lower_bound_included(self) -> None:
        assert evaluate("in_range(0x1000, 0x1000, 0x1000)")["result"] == 1

    def test_below_range(self) -> None:
        assert evaluate("in_range(0x0FFF, 0x1000, 0x1000)")["result"] == 0


class TestSimpleWrappers:
    def test_abs(self) -> None:
        assert evaluate("abs(-5)", signed=True)["result"] == 5

    def test_min(self) -> None:
        assert evaluate("min(3, 1, 2)")["result"] == 1

    def test_max(self) -> None:
        assert evaluate("max(3, 1, 2)")["result"] == 3

    def test_hex_wrapper(self) -> None:
        r = evaluate("hex(0x100)")
        assert r["result"] == "0x100"
        assert r["result_hex"] is None

    def test_bin_wrapper(self) -> None:
        r = evaluate("bin(0x5)")
        assert r["result"] == "0b101"
        assert r["result_hex"] is None
