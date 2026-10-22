"""Width-masking / signed-reinterpret / mod_wrap tests for the value_manage
`eval` evaluator.

Covers the four axes of the final envelope's integer path: unsigned +
in-range, unsigned + overflow, unsigned + mod_wrap, and signed
reinterpret across widths 32 / 64.
"""
from __future__ import annotations

import pytest

from suspex.mcp.value_eval import EvalError, evaluate


class TestUnsignedOverflow:
    def test_2_pow_64_at_width_64_raises(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("2**64", width=64)
        assert exc.value.kind == "expr_overflow"

    def test_2_pow_64_at_width_64_mod_wrap_returns_zero(self) -> None:
        r = evaluate("2**64", width=64, mod_wrap=True)
        assert r["result"] == 0
        assert r.get("warnings"), "mod_wrap should attach a warning"

    def test_within_width_no_overflow(self) -> None:
        r = evaluate("0xFFFFFFFF", width=32)
        assert r["result"] == 0xFFFFFFFF
        assert "warnings" not in r

    def test_negative_unsigned_raises_without_mod_wrap(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("-1", width=32)
        assert exc.value.kind == "expr_overflow"

    def test_negative_unsigned_mod_wraps_to_max(self) -> None:
        r = evaluate("-1", width=32, mod_wrap=True)
        assert r["result"] == 0xFFFFFFFF
        assert r.get("warnings")


class TestSignedReinterpret:
    def test_u32_all_bits_minus_1(self) -> None:
        r = evaluate("0xFFFFFFFF", width=32, signed=True)
        assert r["result"] == -1
        assert r["result_hex"] == "0xFFFFFFFF"

    def test_u32_minus_2(self) -> None:
        r = evaluate("0xFFFFFFFE", width=32, signed=True)
        assert r["result"] == -2

    def test_u32_min_signed_int(self) -> None:
        r = evaluate("0x80000000", width=32, signed=True)
        assert r["result"] == -2147483648

    def test_u64_all_bits_minus_1(self) -> None:
        r = evaluate("0xFFFFFFFFFFFFFFFF", width=64, signed=True)
        assert r["result"] == -1

    def test_signed_bare_negative_within_range(self) -> None:
        r = evaluate("-1", width=32, signed=True)
        assert r["result"] == -1

    def test_signed_result_hex_reflects_bit_pattern(self) -> None:
        # -2 as u32 bit pattern is 0xFFFFFFFE
        r = evaluate("-2", width=32, signed=True)
        assert r["result"] == -2
        assert r["result_hex"] == "0xFFFFFFFE"


class TestWidthValidation:
    def test_invalid_width_rejected(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("1", width=17)
        assert exc.value.kind == "bad_expr"

    def test_width_128_accepted(self) -> None:
        r = evaluate("1", width=128)
        assert r["result"] == 1
        assert r["width_used"] == 128
        assert r["result_bits"] == 128
