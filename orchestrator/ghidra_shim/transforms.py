"""Client-side response transformer glue for the ghidra shim.

The idalib shim's D-1/D-2/D-3 transformers are IDA-payload-specific
(grouped xref rows, Hex-Rays annotation trailers); the Ghidra backend
already emits compact shapes, so the transformer args are accepted and
dropped (kept for arg-compatibility with callers reusing ida-manage
muscle memory) and only the None->"" output-schema coercion is live —
the mcp SDK's output validator refuses null strings the same way.
"""
from __future__ import annotations

import json
from typing import Any

from ghidra_shim_ergo import (
    collect_string_field_names as _collect_string_field_names,
    walk_and_coerce as _walk_and_coerce,
)


# Transformer knobs accepted for arg-compatibility; the Ghidra backend
# emits compact shapes natively so they currently no-op. Popped BEFORE
# the backend call so they never reach a tool signature that doesn't
# know them.
_POP_ARGS = ("group_by_function", "fields", "detail", "members",
             "annotations", "around_address", "window_lines", "max_bytes")


def _pop_transformer_args(name: str, args: dict) -> dict:
    """Strip transformer knobs off ``args``; return what was popped."""
    popped: dict[str, Any] = {}
    for k in _POP_ARGS:
        if k in args:
            popped[k] = args.pop(k)
    return popped


def _apply_response_transforms(name: str,
                               args: dict,
                               transformer_args: dict,
                               result_content: list) -> list:
    """Placeholder for future per-tool reshapers (grouped xrefs, struct
    compaction). Today the backend's shapes are already compact, so the
    content passes through unchanged."""
    return result_content


def _coerce_none_string_fields(tool_name: str, sess, result) -> None:
    """Walk `result.content` in place and coerce None -> \"\" on any
    object field the tool's outputSchema declared as `string` — same
    mcp-SDK output-validator rescue as the idalib shim."""
    tool_meta = None
    try:
        for t in getattr(sess, "_cached_tools", []) or []:
            if getattr(t, "name", None) == tool_name:
                tool_meta = t
                break
    except Exception:  # noqa: BLE001
        return
    if tool_meta is None:
        return
    schema = getattr(tool_meta, "outputSchema", None) or {}
    string_fields = _collect_string_field_names(schema)
    if not string_fields:
        return
    for content in getattr(result, "content", None) or []:
        text = getattr(content, "text", None)
        if not isinstance(text, str) or not text or text[0] not in "[{":
            continue
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            continue
        if _walk_and_coerce(data, string_fields):
            content.text = json.dumps(data)
