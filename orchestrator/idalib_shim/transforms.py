"""v0.17 D-1/D-2/D-3 client-side response transformer args + coercion.

Split-out from ``idalib_stdio_shim.py``.  Pure-logic transformer glue —
picks up the argument-alias / windowing / grouping helpers from
``ida_shim_ergo`` and applies them to the shim's raw backend responses.
"""
from __future__ import annotations

import json
from typing import Any

from ida_shim_ergo import (
    apply_decompile_window as _apply_decompile_window,
    collect_string_field_names as _collect_string_field_names,
    compact_analyze_struct as _compact_analyze_struct,
    group_xrefs as _group_xrefs,
    walk_and_coerce as _walk_and_coerce,
)


# v0.17 D-1/D-2/D-3: client-side response transformer args. These knobs are
# not part of the vendored plugin's signature, so we pop them off ``args``
# BEFORE calling the backend and apply the transformer to the raw response.
# ``group_by_function`` / ``fields`` — D-1 grouped xrefs.
# ``detail`` / ``members``           — D-2 compact struct.
# ``annotations`` / ``around_address`` / ``window_lines`` / ``max_bytes``
#                                    — D-3 decompile windowing.
_D1_ARGS = ("group_by_function", "fields")
_D2_ARGS = ("detail", "members")
_D3_ARGS = ("annotations", "around_address", "window_lines", "max_bytes")


def _pop_transformer_args(name: str, args: dict) -> dict:
    """Strip the D-1/D-2/D-3 knobs off ``args`` and return them.

    Returns a dict with three sub-dicts (``xrefs``, ``struct``, ``decomp``)
    so :func:`_apply_response_transforms` knows which transformer was
    requested and what params to pass. Missing knobs default to the D-1/2/3
    "on" defaults (grouped, summary, annotations off).
    """
    popped: dict[str, dict] = {"xrefs": {}, "struct": {}, "decomp": {}}
    if name == "get_xrefs_to":
        for k in _D1_ARGS:
            if k in args:
                popped["xrefs"][k] = args.pop(k)
    elif name == "analyze_struct_detailed":
        for k in _D2_ARGS:
            if k in args:
                popped["struct"][k] = args.pop(k)
    elif name == "decompile_function":
        for k in _D3_ARGS:
            if k in args:
                popped["decomp"][k] = args.pop(k)
    return popped


def _apply_response_transforms(name: str,
                               args: dict,
                               transformer_args: dict,
                               result_content: list) -> list:
    """Apply the appropriate D-1 / D-2 / D-3 transform to ``result_content``.

    The vendored plugin serialises its response as a single JSON string on
    the first content entry. We parse it, transform, re-serialise. If the
    payload isn't JSON (or the shape doesn't fit) we return the content
    unchanged so the transformer degrades gracefully.
    """
    if not result_content:
        return result_content
    entry = result_content[0]
    text = getattr(entry, "text", None)
    if not isinstance(text, str) or not text or text[0] not in "[{":
        return result_content
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return result_content

    reshaped: Any = None
    if name == "get_xrefs_to":
        raw_rows = payload if isinstance(payload, list) else payload.get("xrefs")
        if isinstance(raw_rows, list):
            reshaped = _group_xrefs(
                raw_rows,
                target_ea=str(args.get("address", "")),
                group_by_function=bool(transformer_args.get("group_by_function", True)),
                fields=list(transformer_args.get("fields") or []),
            )
    elif name == "analyze_struct_detailed":
        reshaped = _compact_analyze_struct(
            payload,
            name=str(args.get("name") or args.get("struct_name") or ""),
            detail=bool(transformer_args.get("detail", False)),
            members=list(transformer_args.get("members") or []),
        )
    elif name == "decompile_function":
        raw_text = payload if isinstance(payload, str) else payload.get("text")
        if raw_text is None and isinstance(payload, dict):
            # Some vendored builds emit the whole response as a JSON object
            # with the pseudo-C under a different key; fall back to the
            # first string value we find.
            for v in payload.values():
                if isinstance(v, str):
                    raw_text = v
                    break
        if isinstance(raw_text, str):
            window = _apply_decompile_window(
                raw_text,
                annotations=bool(transformer_args.get("annotations", False)),
                around_address=str(transformer_args.get("around_address", "")),
                window_lines=int(transformer_args.get("window_lines", 40)),
                max_bytes=int(transformer_args.get("max_bytes", 0)),
            )
            # Preserve any non-text fields the backend also carried.
            envelope: dict[str, Any] = {}
            if isinstance(payload, dict):
                envelope.update({k: v for k, v in payload.items()
                                 if k not in ("text", "pseudo_c", "code")})
            envelope["start_address"] = str(args.get("start_address")
                                            or args.get("address") or "")
            envelope.update(window)
            reshaped = envelope

    if reshaped is None:
        return result_content
    entry.text = json.dumps(reshaped)
    return result_content


def _coerce_none_string_fields(tool_name: str, sess, result) -> None:
    """Walk `result.content` in place and coerce None -> \"\" on any object
    field the tool's outputSchema declared as `string`.

    Fixes the vanilla plugin's `mcp-plugin.py` build of
    `StackFrameVariable` / `StructureDefinition` from IDA APIs that
    return None for anonymous types — the mcp SDK's output validator
    refuses the response otherwise. Scoped by outputSchema so we don't
    hide legitimate None-signals on non-string fields.
    """
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
