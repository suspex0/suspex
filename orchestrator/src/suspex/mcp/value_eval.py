"""Safe expression evaluator for the `value_manage(action='eval')` action.

Every acceptable node type is explicitly whitelisted; every non-whitelisted
node fails with an ``EvalError`` carrying a typed ``kind`` slug so the
value_ops dispatcher can render {ok:false, kind, error, hint}. The stdlib
``eval`` builtin is never invoked — the walker computes results directly
from the parsed AST.
"""

from __future__ import annotations

import ast
from typing import Any, Callable

try:
    from .value_consts import CONSTANTS  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - fallback when worker C's module is absent
    CONSTANTS: dict[str, int | float] = {}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EvalError(Exception):
    """Every failure surfaced by this module carries a `kind` slug so the
    caller can render {ok:false, kind, error, hint} without regexing English.
    """

    def __init__(self, kind: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.hint = hint


# ---------------------------------------------------------------------------
# Safety guards
# ---------------------------------------------------------------------------

MAX_EXPR_LEN = 8 * 1024
MAX_ENV_ENTRIES = 256
MAX_AST_DEPTH = 128
MAX_NODE_VISITS = 10_000
POW_BASE_CAP = 1 << 16
POW_EXP_CAP = 64
ALLOWED_WIDTHS: tuple[int, ...] = (32, 64, 128)


# ---------------------------------------------------------------------------
# Whitelisted functions
# ---------------------------------------------------------------------------


def _mask_of(width: int) -> int:
    return (1 << width) - 1


def _popcount(x: Any, width: int = 64) -> int:
    return bin(int(x) & _mask_of(width)).count("1")


def _ctz(x: Any, width: int = 64) -> int:
    v = int(x) & _mask_of(width)
    if v == 0:
        return width
    n = 0
    while (v & 1) == 0:
        v >>= 1
        n += 1
    return n


def _clz(x: Any, width: int = 64) -> int:
    v = int(x) & _mask_of(width)
    if v == 0:
        return width
    n = 0
    top = 1 << (width - 1)
    while (v & top) == 0:
        v <<= 1
        n += 1
    return n


def _byteswap16(x: Any) -> int:
    v = int(x) & 0xFFFF
    return int.from_bytes(v.to_bytes(2, "little"), "big")


def _byteswap32(x: Any) -> int:
    v = int(x) & 0xFFFFFFFF
    return int.from_bytes(v.to_bytes(4, "little"), "big")


def _byteswap64(x: Any) -> int:
    v = int(x) & 0xFFFFFFFFFFFFFFFF
    return int.from_bytes(v.to_bytes(8, "little"), "big")


def _rotl(x: Any, n: Any, width: int = 64) -> int:
    mask = _mask_of(width)
    v = int(x) & mask
    k = int(n) % width
    if k == 0:
        return v
    return ((v << k) | (v >> (width - k))) & mask


def _rotr(x: Any, n: Any, width: int = 64) -> int:
    mask = _mask_of(width)
    v = int(x) & mask
    k = int(n) % width
    if k == 0:
        return v
    return ((v >> k) | (v << (width - k))) & mask


def _sign_extend(x: Any, from_bits: Any, to_bits: Any = 64) -> int:
    fb = int(from_bits)
    tb = int(to_bits)
    if fb <= 0 or tb <= 0 or fb > tb:
        raise EvalError(
            "bad_expr",
            f"sign_extend: from_bits={fb} to_bits={tb} out of range",
            hint="require 0 < from_bits <= to_bits",
        )
    v = int(x) & _mask_of(fb)
    if v & (1 << (fb - 1)):
        v |= (~_mask_of(fb)) & _mask_of(tb)
    return v & _mask_of(tb)


def _zero_extend(x: Any, from_bits: Any, to_bits: Any = 64) -> int:
    fb = int(from_bits)
    tb = int(to_bits)
    if fb <= 0 or tb <= 0 or fb > tb:
        raise EvalError(
            "bad_expr",
            f"zero_extend: from_bits={fb} to_bits={tb} out of range",
            hint="require 0 < from_bits <= to_bits",
        )
    return int(x) & _mask_of(fb)


def _align_check(name: str, aln: int) -> None:
    if aln <= 0 or (aln & (aln - 1)) != 0:
        raise EvalError(
            "bad_expr",
            f"{name}: alignment {aln} is not a positive power of 2",
            hint="pass 0x1000, 4096, etc.",
        )


def _align_up(x: Any, aln: Any) -> int:
    a = int(aln)
    _align_check("align_up", a)
    return (int(x) + a - 1) & ~(a - 1)


def _align_down(x: Any, aln: Any) -> int:
    a = int(aln)
    _align_check("align_down", a)
    return int(x) & ~(a - 1)


def _in_range(x: Any, base: Any, size: Any) -> int:
    xi = int(x)
    b = int(base)
    s = int(size)
    return 1 if b <= xi < b + s else 0


def _abs(x: Any) -> Any:
    return abs(x)


def _min(*args: Any) -> Any:
    return min(*args)


def _max(*args: Any) -> Any:
    return max(*args)


def _hex(x: Any) -> str:
    return hex(int(x))


def _bin(x: Any) -> str:
    return bin(int(x))


FUNCS: dict[str, Callable[..., Any]] = {
    "popcount": _popcount,
    "ctz": _ctz,
    "clz": _clz,
    "byteswap16": _byteswap16,
    "byteswap32": _byteswap32,
    "byteswap64": _byteswap64,
    "rotl": _rotl,
    "rotr": _rotr,
    "sign_extend": _sign_extend,
    "zero_extend": _zero_extend,
    "align_up": _align_up,
    "align_down": _align_down,
    "in_range": _in_range,
    "abs": _abs,
    "min": _min,
    "max": _max,
    "hex": _hex,
    "bin": _bin,
}


# ---------------------------------------------------------------------------
# AST evaluator
# ---------------------------------------------------------------------------


_BINOPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
}

_UNARYOPS: dict[type, Callable[[Any], Any]] = {
    ast.UAdd: lambda a: +a,
    ast.USub: lambda a: -a,
    ast.Invert: lambda a: ~a,
    ast.Not: lambda a: 1 if not a else 0,
}

_COMPAREOPS: dict[type, Callable[[Any, Any], bool]] = {
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
}


def _check_pow_cap(base: Any, exp: Any) -> None:
    if isinstance(base, int) and not isinstance(base, bool):
        if abs(base) > POW_BASE_CAP:
            raise EvalError(
                "expr_overflow",
                f"** base {base} exceeds cap {POW_BASE_CAP}",
                hint=f"require abs(base) <= {POW_BASE_CAP}",
            )
    if isinstance(exp, int) and not isinstance(exp, bool):
        if exp > POW_EXP_CAP or exp < -POW_EXP_CAP:
            raise EvalError(
                "expr_overflow",
                f"** exponent {exp} exceeds cap {POW_EXP_CAP}",
                hint=f"require abs(exp) <= {POW_EXP_CAP}",
            )


def _eval(node: ast.AST, env: dict[str, Any],
          state: dict[str, int], depth: int) -> Any:
    state["visits"] += 1
    if state["visits"] > MAX_NODE_VISITS:
        raise EvalError(
            "evaluation_timeout",
            f"expression exceeded node-visit budget of {MAX_NODE_VISITS}",
            hint="simplify the expression",
        )
    if depth > MAX_AST_DEPTH:
        raise EvalError(
            "bad_expr", "expression nested too deeply",
            hint=f"AST depth cap is {MAX_AST_DEPTH}",
        )

    if isinstance(node, ast.Expression):
        return _eval(node.body, env, state, depth + 1)

    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float, str)):
            return v
        raise EvalError(
            "unsupported_op",
            f"literal of type {type(v).__name__} not allowed",
            hint="only int, float, str, bool literals are allowed",
        )

    if isinstance(node, ast.Name):
        name = node.id
        if name in env:
            return env[name]
        if name in CONSTANTS:
            return CONSTANTS[name]
        raise EvalError(
            "undefined_name",
            f"name {name!r} is not defined",
            hint="pass it via env=... or use a built-in constant "
                 "(value_manage action='constants' enumerates them)",
        )

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        left = _eval(node.left, env, state, depth + 1)
        right = _eval(node.right, env, state, depth + 1)
        if op_type is ast.Pow:
            _check_pow_cap(left, right)
            try:
                return left ** right
            except (OverflowError, ValueError) as exc:
                raise EvalError(
                    "expr_overflow", f"** failed: {exc}",
                    hint="reduce base or exponent",
                ) from exc
        fn = _BINOPS.get(op_type)
        if fn is None:
            raise EvalError(
                "unsupported_op",
                f"binary operator {op_type.__name__} not allowed",
                hint="allowed: + - * // % ** & | ^ << >>",
            )
        try:
            return fn(left, right)
        except ZeroDivisionError as exc:
            raise EvalError(
                "division_by_zero",
                f"{op_type.__name__.lower()} by zero",
                hint="check the divisor before evaluating",
            ) from exc
        except TypeError as exc:
            # e.g. a non-numeric env string reaching an arithmetic op —
            # report as bad_expr instead of leaking an internal_error.
            raise EvalError(
                "bad_expr",
                f"operand type mismatch: {exc}",
                hint="env values must be numbers or numeric strings "
                     "(0x… works); got a bare string in arithmetic",
            ) from exc

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        fn_u = _UNARYOPS.get(op_type)
        if fn_u is None:
            raise EvalError(
                "unsupported_op",
                f"unary operator {op_type.__name__} not allowed",
                hint="allowed: + - ~ not",
            )
        return fn_u(_eval(node.operand, env, state, depth + 1))

    if isinstance(node, ast.BoolOp):
        op_type = type(node.op)
        if op_type is ast.And:
            last: Any = 1
            for child in node.values:
                last = _eval(child, env, state, depth + 1)
                if not last:
                    return last
            return last
        if op_type is ast.Or:
            last = 0
            for child in node.values:
                last = _eval(child, env, state, depth + 1)
                if last:
                    return last
            return last
        raise EvalError(
            "unsupported_op",
            f"boolean operator {op_type.__name__} not allowed",
            hint="allowed: and, or",
        )

    if isinstance(node, ast.Compare):
        left = _eval(node.left, env, state, depth + 1)
        for op, comparator in zip(node.ops, node.comparators):
            fn_c = _COMPAREOPS.get(type(op))
            if fn_c is None:
                raise EvalError(
                    "unsupported_op",
                    f"comparison operator {type(op).__name__} not allowed",
                    hint="allowed: < <= > >= == !=",
                )
            right = _eval(comparator, env, state, depth + 1)
            if not fn_c(left, right):
                return 0
            left = right
        return 1

    if isinstance(node, ast.IfExp):
        cond = _eval(node.test, env, state, depth + 1)
        if cond:
            return _eval(node.body, env, state, depth + 1)
        return _eval(node.orelse, env, state, depth + 1)

    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, env, state, depth + 1) for e in node.elts)

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise EvalError(
                "unsupported_op",
                f"call target must be a simple name; got {type(node.func).__name__}",
                hint="attribute / subscript / lambda calls are not allowed",
            )
        fname = node.func.id
        fn_call = FUNCS.get(fname)
        if fn_call is None:
            raise EvalError(
                "unsupported_op",
                f"function {fname!r} is not whitelisted",
                hint="allowed functions: " + ", ".join(sorted(FUNCS)),
            )
        for a in node.args:
            if isinstance(a, ast.Starred):
                raise EvalError(
                    "unsupported_op", "starred call arguments not allowed",
                    hint="pass positional arguments explicitly",
                )
        for kw in node.keywords:
            if kw.arg is None:
                raise EvalError(
                    "unsupported_op", "keyword unpacking (**kwargs) not allowed",
                    hint="pass keyword arguments explicitly",
                )
        args = [_eval(a, env, state, depth + 1) for a in node.args]
        kwargs = {kw.arg: _eval(kw.value, env, state, depth + 1)
                  for kw in node.keywords}
        try:
            return fn_call(*args, **kwargs)
        except EvalError:
            raise
        except ZeroDivisionError as exc:
            raise EvalError(
                "division_by_zero", f"{fname}: {exc}",
                hint="check function arguments",
            ) from exc
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvalError(
                "bad_expr", f"{fname}: {exc}",
                hint="check function arguments and types",
            ) from exc

    raise EvalError(
        "unsupported_op",
        f"AST node {type(node).__name__} not allowed",
        hint="expression grammar is restricted to a safe whitelist",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _max_paren_depth(s: str) -> int:
    """Count the max paren nesting depth in the raw source, skipping string
    literals. Python's parser accepts arbitrarily deep parens (they collapse
    to a single AST node), so this catches deep nesting before ``ast.parse``.
    """
    depth = 0
    max_d = 0
    in_str = False
    quote = ""
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                in_str = False
        elif c in ("'", '"'):
            in_str = True
            quote = c
        elif c == "(":
            depth += 1
            if depth > max_d:
                max_d = depth
        elif c == ")":
            if depth > 0:
                depth -= 1
        i += 1
    return max_d


def _signed_of(v: int, width: int) -> int:
    sign = 1 << (width - 1)
    return v - (1 << width) if v & sign else v


def _envelope(result: Any, result_hex: str | None, result_bits: int,
              width: int, signed: bool, expr: str,
              warnings: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "result": result,
        "result_hex": result_hex,
        "result_bits": result_bits,
        "width_used": width,
        "signed": signed,
        "expression": expr,
    }
    if warnings:
        out["warnings"] = warnings
    return out


def evaluate(expr: str, env: dict[str, int | float] | None = None, *,
             width: int = 64, signed: bool = False,
             mod_wrap: bool = False, as_hex: bool = True) -> dict[str, Any]:
    """Evaluate a whitelisted arithmetic expression and return a data dict."""
    if not isinstance(expr, str):
        raise EvalError(
            "bad_expr",
            f"expr must be str; got {type(expr).__name__}",
            hint="pass the expression as a string",
        )
    if len(expr) > MAX_EXPR_LEN:
        raise EvalError(
            "input_too_large",
            f"expression length {len(expr)} exceeds cap {MAX_EXPR_LEN}",
            hint=f"cap is {MAX_EXPR_LEN} bytes",
        )
    if env is not None and len(env) > MAX_ENV_ENTRIES:
        raise EvalError(
            "input_too_large",
            f"env has {len(env)} entries; cap is {MAX_ENV_ENTRIES}",
            hint=f"reduce env to at most {MAX_ENV_ENTRIES} entries",
        )
    if width not in ALLOWED_WIDTHS:
        raise EvalError(
            "bad_expr",
            f"width={width!r} must be one of {ALLOWED_WIDTHS}",
            hint="pass width=32, 64, or 128",
        )
    if _max_paren_depth(expr) > MAX_AST_DEPTH:
        raise EvalError(
            "bad_expr", "expression nested too deeply",
            hint=f"paren-depth cap is {MAX_AST_DEPTH}",
        )
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise EvalError(
            "bad_expr", f"malformed expression: {exc.msg}",
            hint="check parentheses, operators, and literals",
        ) from exc

    # v0.21 dev-feedback: env_json arrives over the wire as JSON strings
    # ('{"BASE": "0x1000"}'); a str reaching `BASE + SIZE` used to raise a
    # bare TypeError. Coerce numeric-looking strings to int (0x/decimal)
    # or float; leave anything else as a string so str-friendly functions
    # still see it (and arithmetic on it reports bad_expr, not
    # internal_error).
    env_map: dict[str, Any] = dict(env or {})
    warnings: list[str] = []
    coerced: list[str] = []
    for k, v in list(env_map.items()):
        if isinstance(v, str):
            s = v.strip()
            try:
                env_map[k] = int(s, 0)
            except ValueError:
                try:
                    env_map[k] = int(s)
                except ValueError:
                    try:
                        env_map[k] = float(s)
                    except ValueError:
                        continue
            coerced.append(k)
        elif isinstance(v, (dict, list)):
            raise EvalError(
                "bad_expr",
                f"env[{k!r}] is a {type(v).__name__}; env values must be "
                "numbers or numeric strings",
                hint="env_json={'NAME': '0x…'} — flatten nested values "
                     "before passing them in",
            )
    if coerced:
        warnings.append(
            f"env string(s) coerced to numbers: {', '.join(coerced)}")

    state: dict[str, int] = {"visits": 0}
    result = _eval(tree, env_map, state, 0)

    mask = _mask_of(width)
    result_bits = width

    if isinstance(result, bool):
        return _envelope(result, None, result_bits, width, signed,
                         expr, warnings)

    if isinstance(result, int):
        if signed:
            masked = result & mask
            final: Any = _signed_of(masked, width)
        else:
            if 0 <= result <= mask:
                final = result
            elif mod_wrap:
                warnings.append(
                    f"result {result} wrapped modulo 2**{width}"
                )
                final = result & mask
            else:
                raise EvalError(
                    "expr_overflow",
                    f"result {result} does not fit unsigned {width}-bit range",
                    hint="pass mod_wrap=True to mask, widen width, "
                         "or signed=True to reinterpret",
                )
        rhex = f"0x{final & mask:X}" if as_hex else None
        return _envelope(final, rhex, result_bits, width, signed,
                         expr, warnings)

    if isinstance(result, float):
        return _envelope(result, None, result_bits, width, signed,
                         expr, warnings)

    if isinstance(result, (str, tuple)):
        return _envelope(result, None, result_bits, width, signed,
                         expr, warnings)

    raise EvalError(
        "bad_expr",
        f"expression produced unsupported result type {type(result).__name__}",
        hint="result must be int, float, str, bool, or tuple",
    )
