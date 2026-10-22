"""Arithmetic tests for the value_manage `eval` AST evaluator.

Covers mixed-radix literals, operator precedence, ``**`` capping, integer
division, modulo, boolean short-circuit, comparisons that return 1/0, and
the ternary conditional. Also spot-checks the return envelope shape.
"""
from __future__ import annotations

import pytest

from suspex.mcp.value_eval import EvalError, evaluate


class TestLiteralsAndArithmetic:
    def test_headline_example(self) -> None:
        r = evaluate("0x1000 + 0x40*8")
        assert r["result"] == 0x1200  # 4096 + 512 = 4608 = 0x1200
        assert r["result_hex"] == "0x1200"

    def test_mixed_radix_literals(self) -> None:
        r = evaluate("0x100 + 0b1010 + 0o17 + 20")
        assert r["result"] == 256 + 10 + 15 + 20

    def test_float_literal(self) -> None:
        r = evaluate("1.5 + 2.5")
        assert r["result"] == 4.0
        assert r["result_hex"] is None

    def test_operator_precedence(self) -> None:
        assert evaluate("2 + 3 * 4")["result"] == 14
        assert evaluate("(2 + 3) * 4")["result"] == 20
        # Bit-shift is lower precedence than +
        assert evaluate("1 << 4 + 1")["result"] == (1 << 5)

    def test_integer_division(self) -> None:
        assert evaluate("10 // 3")["result"] == 3
        assert evaluate("-10 // 3", signed=True)["result"] == -4

    def test_modulo(self) -> None:
        assert evaluate("10 % 3")["result"] == 1
        assert evaluate("0xFF % 16")["result"] == 15

    def test_pow_within_caps(self) -> None:
        assert evaluate("2 ** 10")["result"] == 1024
        assert evaluate("3 ** 4")["result"] == 81
        assert evaluate("65536 ** 2", mod_wrap=True)["result"] == \
            (65536 ** 2) & ((1 << 64) - 1)

    def test_pow_exponent_capped(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("2 ** 100")
        assert exc.value.kind == "expr_overflow"

    def test_pow_base_capped(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("70000 ** 3")
        assert exc.value.kind == "expr_overflow"

    def test_pow_2_pow_64_at_width_64_wraps_with_mod(self) -> None:
        r = evaluate("2 ** 64", width=64, mod_wrap=True)
        assert r["result"] == 0

    def test_shifts_and_bit_ops(self) -> None:
        assert evaluate("1 << 8")["result"] == 256
        assert evaluate("0xFF00 >> 8")["result"] == 0xFF
        assert evaluate("0xFF & 0x0F")["result"] == 0x0F
        assert evaluate("0xF0 | 0x0F")["result"] == 0xFF
        assert evaluate("0xFF ^ 0x0F")["result"] == 0xF0
        assert evaluate("~0 & 0xFF")["result"] == 0xFF

    def test_unary(self) -> None:
        assert evaluate("+7")["result"] == 7
        assert evaluate("-7", signed=True)["result"] == -7
        assert evaluate("~0", mod_wrap=True)["result"] == (1 << 64) - 1
        # ``not`` returns int 1/0
        assert evaluate("not 0")["result"] == 1
        assert evaluate("not 5")["result"] == 0

    def test_boolean_ops_short_circuit(self) -> None:
        # `and`/`or` return the deciding operand (Python semantics)
        assert evaluate("1 and 2")["result"] == 2
        assert evaluate("0 and 5")["result"] == 0
        assert evaluate("1 or 2")["result"] == 1
        assert evaluate("0 or 5")["result"] == 5

    def test_comparisons_return_int_01(self) -> None:
        assert evaluate("1 < 2")["result"] == 1
        assert evaluate("1 > 2")["result"] == 0
        assert evaluate("0x100 == 256")["result"] == 1
        assert evaluate("1 != 1")["result"] == 0
        assert evaluate("1 <= 1")["result"] == 1
        assert evaluate("1 >= 2")["result"] == 0

    def test_chained_comparison(self) -> None:
        # 1 <= 2 <= 3 is True (returns 1); 3 <= 2 <= 1 is False (returns 0)
        assert evaluate("1 <= 2 <= 3")["result"] == 1
        assert evaluate("3 <= 2 <= 1")["result"] == 0

    def test_conditional(self) -> None:
        assert evaluate("42 if 1 else 0")["result"] == 42
        assert evaluate("42 if 0 else 99")["result"] == 99
        assert evaluate("0xA if (2 > 1) else 0xB")["result"] == 0xA

    def test_env_binding(self) -> None:
        r = evaluate("BASE + OFF", env={"BASE": 0x1000, "OFF": 0x40})
        assert r["result"] == 0x1040
        assert r["result_hex"] == "0x1040"

    def test_env_overrides_would_be_constants(self) -> None:
        # Even if CONSTANTS had a value, env takes precedence
        r = evaluate("X * 2", env={"X": 7})
        assert r["result"] == 14

    def test_response_shape(self) -> None:
        r = evaluate("0x1000")
        assert r["result"] == 0x1000
        assert r["result_hex"] == "0x1000"
        assert r["result_bits"] == 64
        assert r["width_used"] == 64
        assert r["signed"] is False
        assert r["expression"] == "0x1000"
        assert "warnings" not in r

    def test_width_and_as_hex_flags(self) -> None:
        r = evaluate("0xFF", width=32, as_hex=False)
        assert r["result_bits"] == 32
        assert r["width_used"] == 32
        assert r["result_hex"] is None
