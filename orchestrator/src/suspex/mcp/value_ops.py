"""Per-action implementations for the `value_manage` MCP tool.

Extracted from tools.py so the actions can be unit-tested without spinning
up the MCP server.

Every helper here is pure — no I/O, no globals, no target dependency.
`asyncio.to_thread` offload for the heavy actions (encode/decode/
str_convert/hash) stays in the tools.py wrapper so this module is
plain-sync and importable from any thread.
"""
from __future__ import annotations

import json
from typing import Any

from . import conversions as _cv


# ---------------------------------------------------------------------------
# Public constants — the tools.py wrappers consult these to decide dispatch
# and to build the "unknown_action" error hint.
# ---------------------------------------------------------------------------

VALUE_MANAGE_ACTIONS: list[str] = [
    "cast", "views", "pack", "unpack", "swap", "split", "join",
    "bits", "err_lookup", "time", "guid",
    "encode", "decode", "str_convert", "hash",
    "eval", "constants", "ioctl_decode", "ioctl_encode",
]

# Actions that scale with input size or run heavy crypto — the tools.py
# wrapper offloads these via asyncio.to_thread when the input is above
# conversions.THREAD_OFFLOAD_BYTES so the event loop stays free.
HEAVY_ACTIONS: frozenset[str] = frozenset({
    "encode", "decode", "str_convert", "hash",
})

# Input caps — protect the orchestrator from adversarial payloads. Match
# the mem_rw 4 MiB / stream 32 MiB precedent.
MAX_DATA_HEX = 32 * 1024 * 1024  # 32 MiB hex = 16 MiB bytes
MAX_VALUE_STR = 8 * 1024 * 1024  # for encode/decode string inputs


# ---------------------------------------------------------------------------
# Input-cap check — runs before dispatch so both aliases enforce the same
# limits. Returns a legacy-shape error dict on refusal, or None to proceed.
# ---------------------------------------------------------------------------

def check_input_caps(value: Any, data_hex: Any) -> dict | None:
    if isinstance(data_hex, str) and len(data_hex) > MAX_DATA_HEX:
        return {
            "ok": False, "kind": "input_too_large",
            "error": f"data_hex length {len(data_hex)} exceeds cap {MAX_DATA_HEX}",
            "hint": "split via action=split or chunk on the caller side",
        }
    if isinstance(value, str) and len(value) > MAX_VALUE_STR:
        return {
            "ok": False, "kind": "input_too_large",
            "error": f"value length {len(value)} exceeds cap {MAX_VALUE_STR}",
            "hint": "chunk the input; string-shaped inputs cap at 8 MiB",
        }
    return None


def estimate_bytes(value: Any, data_hex: Any) -> int:
    approx = 0
    if isinstance(data_hex, str):
        approx = max(approx, len(data_hex) // 2)
    if isinstance(value, str):
        approx = max(approx, len(value))
    return approx


# ---------------------------------------------------------------------------
# Dispatch — pure-sync computation. tools.py owns any thread offload.
# ---------------------------------------------------------------------------

def dispatch(
    action: str,
    *,
    value: Any = "",
    from_type: str = "",
    to_type: str = "",
    endian: str = "little",
    width: int = 0,
    count: int = 0,
    data_hex: str = "",
    preset: str = "",
    names_json: str = "",
    parts_json: str = "",
    wrap: int = 0,
    pad: bool = True,
    errors: str = "strict",
    strip_nul: bool = False,
    hmac_key_hex: str = "",
    salt_hex: str = "",
    form: str = "string",
    space: str = "auto",
    width_hint: str = "u64",
    expr: str = "",
    env: dict[str, int | float] | None = None,
    signed: bool = False,
    as_hex: bool = True,
    mod_wrap: bool = False,
    category: str = "",
    device_type: Any = "",
    function: Any = "",
    method: Any = "",
    access: Any = "",
) -> dict:
    """Compute one value_manage action and return a legacy-shape dict.

    The result dict follows the transitional ``{ok: True, action, ...}`` /
    ``{ok: False, kind, error, hint}`` shape that ``envelope_from_result``
    coerces into the v0.14 unified envelope. A ``warnings: [...]`` key on
    success is lifted to the envelope top level by ``envelope_from_result``.
    """
    if action == "cast":
        result: dict[str, Any] = {
            "ok": True, "action": "cast",
            "input": {"value_repr": repr(value),
                      "from": _cv.canonicalize_type(from_type),
                      "endian": endian},
            "output": _cv.do_cast(value, from_type, to_type, endian),
        }
    elif action == "views":
        result = {"ok": True, "action": "views",
                  **_cv.views(value, width_hint or (from_type or "u64"))}
    elif action == "pack":
        result = {"ok": True, "action": "pack",
                  **_cv.do_pack(value, from_type, endian)}
    elif action == "unpack":
        result = {"ok": True, "action": "unpack",
                  **_cv.do_unpack(data_hex, to_type, endian)}
    elif action == "swap":
        w = width or 4
        result = {"ok": True, "action": "swap", **_cv.do_swap(value, w)}
    elif action == "split":
        result = {"ok": True, "action": "split",
                  **_cv.do_split(value, width or 8, count, data_hex)}
    elif action == "join":
        try:
            parts = json.loads(parts_json or "[]")
        except json.JSONDecodeError as exc:
            raise _cv.ConversionError(
                "unparseable_value", f"parts_json is not valid JSON: {exc}",
                hint="pass parts_json='[\"0xDEAD\",\"0xBEEF\"]' (a JSON array)")
        result = {"ok": True, "action": "join",
                  **_cv.do_join(parts, width or 4, endian)}
    elif action == "bits":
        names_map = None
        if names_json:
            try:
                names_map = json.loads(names_json)
            except json.JSONDecodeError as exc:
                raise _cv.ConversionError(
                    "unparseable_value",
                    f"names_json is not valid JSON: {exc}",
                    hint="pass names_json='{\"0x1\":\"FLAG_A\",\"0x2\":\"FLAG_B\"}'")
        result = {"ok": True, "action": "bits",
                  **_cv.decode_bits(value, preset, names_map)}
    elif action == "err_lookup":
        result = {"ok": True, "action": "err_lookup",
                  **_cv.lookup_err(value, space)}
    elif action == "time":
        result = {"ok": True, "action": "time",
                  **_cv.time_convert(value, from_type or "filetime",
                                     to_type or "iso8601", data_hex)}
    elif action == "guid":
        result = {"ok": True, "action": "guid",
                  **_cv.guid_convert(value, form, data_hex)}
    elif action == "encode":
        result = {"ok": True, "action": "encode",
                  **_cv.encode_bytes(data_hex, to_type, wrap, pad)}
    elif action == "decode":
        result = {"ok": True, "action": "decode",
                  **_cv.decode_text(value if isinstance(value, str) else str(value),
                                    from_type)}
    elif action == "str_convert":
        result = {"ok": True, "action": "str_convert",
                  **_cv.str_convert(value=value, data_hex=data_hex,
                                    from_type=from_type or "utf-8",
                                    to_type=to_type or "str",
                                    errors=errors, strip_nul=strip_nul)}
    elif action == "hash":
        result = {"ok": True, "action": "hash",
                  **_cv.hash_bytes(data_hex, to_type or "sha256",
                                   hmac_key_hex, salt_hex)}
    elif action == "eval":
        result = _dispatch_eval(expr=expr, env=env or {}, width=width or 64,
                                signed=signed, as_hex=as_hex, mod_wrap=mod_wrap)
    elif action == "constants":
        result = _dispatch_constants(category=category)
    elif action == "ioctl_decode":
        result = {"ok": True, "action": "ioctl_decode",
                  **_cv.decode_ctl_code(value)}
    elif action == "ioctl_encode":
        result = {"ok": True, "action": "ioctl_encode",
                  **_cv.encode_ctl_code(device_type, function, method,
                                        access)}
    else:
        raise _cv.ConversionError(
            "internal", f"dispatcher missed action {action!r}",
            hint="report a bug — this action is listed but not wired")

    return result


# ---------------------------------------------------------------------------
# eval + constants — thin wrappers around value_eval / value_consts. The
# helper modules land in the same package during v0.17.1; keep imports
# local so a bare-repo import of tools.py does not fail if the helpers
# are absent (e.g. during a partial checkout mid-branch).
# ---------------------------------------------------------------------------

def _dispatch_eval(*, expr: str, env: dict[str, int | float],
                   width: int, signed: bool, as_hex: bool,
                   mod_wrap: bool) -> dict:
    from . import value_eval as _ve  # local import — see module doc
    try:
        data = _ve.evaluate(expr, env=env, width=width,
                            signed=signed, as_hex=as_hex, mod_wrap=mod_wrap)
    except _ve.EvalError as exc:
        raise _cv.ConversionError(exc.kind, str(exc),
                                  hint=getattr(exc, "hint", "") or "")
    warnings = data.pop("warnings", None)
    result: dict[str, Any] = {"ok": True, "action": "eval", **data}
    if warnings:
        result["warnings"] = list(warnings)
    return result


def _dispatch_constants(*, category: str) -> dict:
    from . import value_consts as _vc  # local import — see module doc
    entries = _vc.CONST_ENTRIES
    if category:
        entries = [e for e in entries if e.get("category") == category]
    rendered = [{
        "name": e["name"],
        "value": int(e["value"]),
        "value_hex": _fmt_hex(e["value"]),
        "category": e["category"],
        "note": e.get("note", ""),
    } for e in entries]
    data: dict[str, Any] = {
        "ok": True, "action": "constants",
        "count": len(rendered),
        "categories": sorted(_vc.CATEGORIES.keys()),
        "constants": rendered,
    }
    if category:
        data["filtered_by"] = category
    return data


def _fmt_hex(v: int) -> str:
    if v < 0:
        return f"-0x{-v:X}"
    return f"0x{v:X}"
