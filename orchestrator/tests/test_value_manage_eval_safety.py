"""Adversarial safety tests for the value_manage `eval` evaluator.

Every hostile expression must raise ``EvalError`` with an explicit ``kind``
slug. Nothing here may actually evaluate — the AST whitelist is the primary
safeguard against escapes through attribute walks, comprehensions,
lambdas, walrus, f-strings, subscripts, dict/list/set literals, and calls
to non-whitelisted names.
"""
from __future__ import annotations

import pytest

from suspex.mcp.value_eval import EvalError, evaluate


class TestUnsupportedNodes:
    @pytest.mark.parametrize("expr", [
        "(0).__class__",                   # Attribute
        "[x for x in [1,2]]",              # ListComp
        "{x for x in [1,2]}",              # SetComp
        "{x: 1 for x in [1,2]}",           # DictComp
        "(x for x in [1,2])",              # GeneratorExp
        "x[0]",                             # Subscript
        "lambda: 0",                        # Lambda
        "(a := 1)",                         # NamedExpr (walrus)
        "f'{1}'",                           # JoinedStr / FormattedValue
        "{1: 2}",                           # Dict
        "[1, 2, 3]",                        # List
        "{1, 2, 3}",                        # Set
    ])
    def test_dangerous_node_refused(self, expr: str) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate(expr)
        assert exc.value.kind == "unsupported_op", (
            f"{expr!r} produced kind={exc.value.kind!r}"
        )

    def test_true_division_slash_refused(self) -> None:
        # `/` is deliberately not in the binary-op whitelist
        with pytest.raises(EvalError) as exc:
            evaluate("1 / 2")
        assert exc.value.kind == "unsupported_op"


class TestNonWhitelistedCall:
    def test_call_to_dunder_import(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("__import__('os')")
        assert exc.value.kind == "unsupported_op"

    def test_call_to_open(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("open('/etc/passwd')")
        assert exc.value.kind == "unsupported_op"

    def test_call_via_attribute_refused(self) -> None:
        # `.count(...)` requires an Attribute node the walker refuses
        with pytest.raises(EvalError) as exc:
            evaluate("''.join(['a', 'b'])")
        assert exc.value.kind == "unsupported_op"


class TestParseErrors:
    def test_syntax_error_maps_to_bad_expr(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("1 +")
        assert exc.value.kind == "bad_expr"

    def test_only_whitespace_is_bad_expr(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("   ")
        assert exc.value.kind == "bad_expr"


class TestUndefinedName:
    def test_bare_undefined_name(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("missing_name")
        assert exc.value.kind == "undefined_name"
        assert "missing_name" in str(exc.value)

    def test_undefined_name_in_expression(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("1 + never_bound")
        assert exc.value.kind == "undefined_name"


class TestPowCap:
    def test_exponent_over_cap_is_expr_overflow(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("2 ** 100")
        assert exc.value.kind == "expr_overflow"

    def test_base_over_cap_is_expr_overflow(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("1000000 ** 2")
        assert exc.value.kind == "expr_overflow"


class TestDivisionByZero:
    def test_floordiv_by_zero(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("1 // 0")
        assert exc.value.kind == "division_by_zero"

    def test_mod_by_zero(self) -> None:
        with pytest.raises(EvalError) as exc:
            evaluate("5 % 0")
        assert exc.value.kind == "division_by_zero"


class TestInputTooLarge:
    def test_expr_length_over_cap(self) -> None:
        expr = "1" * 10_000  # well over 8 KiB
        with pytest.raises(EvalError) as exc:
            evaluate(expr)
        assert exc.value.kind == "input_too_large"

    def test_env_entries_over_cap(self) -> None:
        env = {f"v{i}": i for i in range(300)}
        with pytest.raises(EvalError) as exc:
            evaluate("v0", env=env)  # type: ignore[arg-type]
        assert exc.value.kind == "input_too_large"


class TestDepthCap:
    def test_deep_paren_nesting(self) -> None:
        expr = "(" * 200 + "1" + ")" * 200
        with pytest.raises(EvalError) as exc:
            evaluate(expr)
        assert exc.value.kind == "bad_expr"

    def test_deep_binop_nesting(self) -> None:
        # Build a nested BinOp tree of depth > 128 without exceeding the
        # 8 KiB source cap.
        n = 150
        expr = "(" * n + "1" + ("+1)" * n)
        with pytest.raises(EvalError) as exc:
            evaluate(expr)
        assert exc.value.kind == "bad_expr"
