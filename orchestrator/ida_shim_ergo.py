"""v0.16: ergonomics helpers for the idalib stdio shim.

Kept out of ``idalib_stdio_shim.py`` so pytest can exercise them without
stubbing the shim's IDA-runtime dependencies (mcp.ClientSession,
mcp.server.stdio, …). The shim imports the public names from here.

Pieces:

* ``ARG_ALIASES`` + :func:`apply_arg_aliases` — accept the alias arg
  names callers naturally reach for (``address`` on
  ``disassemble_function``, ``name`` on ``search_structures``, …) and
  rewrite them to the vanilla ida-pro-mcp plugin's canonical spelling.
* :func:`collect_string_field_names` — scan a JSON Schema and return the
  set of property names declared as ``string`` (or ``string|null``),
  descending through ``items`` / ``anyOf`` / ``oneOf`` / ``allOf``.
* :func:`walk_and_coerce` — walk a decoded JSON structure and replace
  ``None`` with ``""`` on every dict key that is in the given set.
  Together the two coercion helpers let the shim rescue an mcp SDK output-
  validator refusal caused by the vanilla plugin's anonymous-name
  ``None`` responses.
* v0.17 D-1/D-2/D-3 — client-side response transformers that reshape a
  raw vendored-plugin response into a compact, group-by-function, or
  windowed form before the shim forwards it to the MCP caller. These live
  outside the shim so pytest can round-trip a synthetic backend response
  through them without stubbing the IDA runtime.
"""

from __future__ import annotations

import re
from typing import Any


# {tool_name: {alias_name: canonical_name}} — accepted synonyms rewritten
# before the backend sees them. The canonical name is what the vanilla
# ida-pro-mcp plugin expects; the aliases are what our callers naturally
# reach for after using neighbouring tools. Kept narrow: only aliases we
# observed misused, not a broad rename layer.
ARG_ALIASES: dict[str, dict[str, str]] = {
    "search_structures":                 {"name": "filter", "pattern": "filter"},
    "get_global_variable_value_by_name": {"name": "variable_name"},
    "disassemble_function":              {"address": "start_address",
                                          "ea": "start_address"},
    "list_functions":                    {"limit": "count"},
    "list_strings_filter":               {"limit": "count"},
    # v0.17 C1-5: exec_idapython's canonical arg is `source`; callers
    # naturally reach for `code` (JS/Python REPL habits) or `script`
    # after using the exec_manage neighbour, so accept both as aliases.
    "exec_idapython":                    {"code": "source",
                                          "script": "source"},
    # v0.17 C2-3: short single-word aliases for get_struct_member so
    # callers can write `{struct: "_EPROCESS", member: "Pcb"}` without
    # remembering the full canonical `struct_name`/`member_name`.
    "get_struct_member":                 {"struct": "struct_name",
                                          "member": "member_name"},
}


def apply_arg_aliases(tool_name: str, args: dict) -> dict:
    """Rewrite alias keys to their canonical names for ``tool_name``.

    Idempotent: unknown tools and canonical keys pass through unchanged.
    When both alias AND canonical are present, the canonical wins and the
    alias is dropped so we don't overwrite an explicit value.
    """
    table = ARG_ALIASES.get(tool_name)
    if not table:
        return args
    out = dict(args)
    for alias, canonical in table.items():
        if alias in out and canonical not in out:
            out[canonical] = out.pop(alias)
        elif alias in out and canonical in out:
            out.pop(alias, None)
    return out


def collect_string_field_names(schema: dict) -> set[str]:
    """Return every property name in ``schema`` declared as a string type.

    Descends into ``properties``, ``items``, ``anyOf``, ``oneOf``,
    ``allOf`` so nested response shapes are covered. Types like
    ``["string", "null"]`` count as string.
    """
    names: set[str] = set()
    stack: list[Any] = [schema]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            for field, sub in props.items():
                if not isinstance(sub, dict):
                    continue
                t = sub.get("type")
                if t == "string" or (isinstance(t, list) and "string" in t):
                    names.add(field)
                stack.append(sub)
        items = node.get("items")
        if isinstance(items, dict):
            stack.append(items)
        for k in ("anyOf", "oneOf", "allOf"):
            v = node.get(k)
            if isinstance(v, list):
                stack.extend(v)
    return names


def walk_and_coerce(node: Any, string_fields: set[str]) -> bool:
    """Walk ``node`` in place; replace ``None`` with ``""`` on any dict
    key in ``string_fields``. Returns True when at least one replacement
    was made so the caller can decide whether to re-encode."""
    touched = False
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if k in string_fields and v is None:
                node[k] = ""
                touched = True
            elif isinstance(v, (dict, list)):
                if walk_and_coerce(v, string_fields):
                    touched = True
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                if walk_and_coerce(item, string_fields):
                    touched = True
    return touched


# --------------------------------------------------------------------------- #
# v0.17 D-1 — grouped xrefs transformer.
# --------------------------------------------------------------------------- #
#
# The vanilla ``get_xrefs_to`` returns ``list[Xref]`` with a fully nested
# ``Function`` per xref — 39 xrefs × ~30 unique functions came out to 7.7 KB
# of mostly duplication (arp session). Grouping by containing function and
# projecting the columns callers actually need cuts the payload by ~65% on
# a real dispatch table.
#
# The transformer is applied AFTER the backend returns; opting back into
# the flat shape (``group_by_function=False``) is honored client-side so
# the vendored plugin doesn't need to know about the new arg.
# --------------------------------------------------------------------------- #


# Xref-row field allowlist for :func:`group_xrefs`. Aliases (``frm`` /
# ``address`` / ``from_ea`` are all just the source ea) fold into a single
# canonical key here so a caller who asks for ``fields=["ea"]`` sees the ea
# regardless of the raw shape the vendored plugin emits.
_XREF_FIELD_ALIASES: dict[str, str] = {
    "ea": "ea", "frm": "ea", "address": "ea", "from_ea": "ea", "src_ea": "ea",
    "kind": "kind", "type": "kind", "xref_type": "kind",
    "iscode": "iscode", "is_code": "iscode", "code": "iscode",
    "to": "to", "to_ea": "to", "target": "to",
}


def _xref_row_get(row: dict, canonical: str) -> Any:
    """Look ``canonical`` up in an xref row via alias tolerant lookup."""
    for src, dst in _XREF_FIELD_ALIASES.items():
        if dst == canonical and src in row:
            return row[src]
    return None


def _containing_function(row: dict) -> dict | None:
    """Extract the ``function`` dict from an xref row.

    Rows may carry ``function``, ``containing_function``, or a plain
    ``func`` key depending on the ida-pro-mcp version. We accept all three.
    """
    for k in ("function", "containing_function", "func"):
        v = row.get(k)
        if isinstance(v, dict):
            return v
    return None


def _project_xref_row(row: dict, fields: list[str]) -> dict:
    """Return the projection of ``row`` to the requested fields.

    Empty ``fields`` returns every canonical field the row carries. Unknown
    fields are silently dropped so a caller that asks for a non-existent
    column doesn't get a KeyError — just an empty projection.
    """
    all_fields = ("ea", "kind", "iscode", "to")
    out: dict[str, Any] = {}
    keep = fields or all_fields
    for f in keep:
        canonical = _XREF_FIELD_ALIASES.get(f, f)
        if canonical not in all_fields:
            continue
        value = _xref_row_get(row, canonical)
        if value is None:
            continue
        # Normalize `ea` and `to` to hex strings if they came in as ints —
        # matches the rest of the tool surface (envelope Layer 4 does the
        # same in the outer envelope).
        if canonical in ("ea", "to") and isinstance(value, int):
            value = f"0x{value:X}"
        out[canonical] = value
    return out


def _fn_start_ea_int(fn_meta: dict) -> int:
    """Return the numeric start_ea from a function meta blob, best-effort."""
    for k in ("start_ea", "ea", "start", "address"):
        v = fn_meta.get(k)
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            try:
                return int(v, 16) if v.lower().startswith("0x") else int(v, 0)
            except ValueError:
                continue
    return 0


def _fn_meta_shape(fn_meta: dict | None) -> dict:
    """Return a compact ``{start_ea, name}`` blob for the group header."""
    if not fn_meta:
        return {"start_ea": "0x0", "name": "<data>"}
    start = _fn_start_ea_int(fn_meta)
    name = fn_meta.get("name") or fn_meta.get("function_name") or ""
    return {"start_ea": f"0x{start:X}",
            "name": name or ("<unnamed>" if start else "<data>")}


def group_xrefs(raw: list[dict],
                *,
                target_ea: str = "",
                group_by_function: bool = True,
                fields: list[str] | None = None) -> dict:
    """Reshape a flat ``get_xrefs_to`` response into a grouped envelope.

    ``raw`` is the ``list[Xref]`` the vanilla plugin returns; each row is
    a dict carrying at minimum ``ea`` / ``frm`` (the source ea), and a
    nested ``function`` dict for xrefs from within a carved function.
    Xrefs from data regions (no containing function) bucket under the
    zero-ea ``<data>`` sentinel group.

    When ``group_by_function=False`` the response falls back to a flat
    projection — same rows, honoring ``fields=[...]`` — so a caller who
    parses the historical shape still works.

    ``fields=[]`` (or ``None``) keeps every canonical xref field
    (``ea``, ``kind``, ``iscode``, ``to``); a non-empty list projects
    those fields only. Group headers always carry ``function.start_ea``
    and ``function.name`` regardless of ``fields``.
    """
    if fields is None:
        fields = []

    if not group_by_function:
        rows = [_project_xref_row(row, fields) for row in raw]
        return {"grouped": False,
                "target_ea": target_ea or "",
                "xref_count": len(rows),
                "xrefs": rows}

    # Bucket rows by containing-function start_ea.
    buckets: dict[int, list[dict]] = {}
    fn_meta_by_ea: dict[int, dict] = {}
    for row in raw:
        fn_meta = _containing_function(row)
        f_ea = _fn_start_ea_int(fn_meta) if fn_meta else 0
        buckets.setdefault(f_ea, []).append(_project_xref_row(row, fields))
        # First-writer-wins on the group header — later xrefs from the
        # same function are assumed to carry the same nested Function.
        if f_ea not in fn_meta_by_ea:
            fn_meta_by_ea[f_ea] = _fn_meta_shape(fn_meta)

    groups = [
        {"function": fn_meta_by_ea[k],
         "xrefs": v,
         "count": len(v)}
        for k, v in buckets.items()
    ]
    # Deterministic ordering by numeric start_ea so tests / diff tools see
    # the same shape run-to-run.
    groups.sort(key=lambda g: _fn_start_ea_int(g["function"]))

    return {"grouped": True,
            "target_ea": target_ea or "",
            "function_count": len(groups),
            "xref_count": sum(g["count"] for g in groups),
            "groups": groups}


# --------------------------------------------------------------------------- #
# v0.17 D-2 — analyze_struct_detailed compact default.
# --------------------------------------------------------------------------- #
#
# The vendored ``analyze_struct_detailed`` unconditionally returns every
# member. RAID_ADAPTER_EXTENSION was 232 rows / 28 KB — but the caller
# usually wants the header (size, count) plus a preview or one specific
# member. The transformer collapses to the compact shape unless the caller
# passes ``detail=true`` or an explicit ``members=[...]`` projection.


_ANALYZE_STRUCT_PREVIEW_ROWS = 10


def _extract_struct_members(raw: Any) -> tuple[list[dict], dict]:
    """Return ``(members_list, header_carry_over)`` from a raw analyze
    response.

    The vendored plugin has drifted through several shapes over the years:
      * ``list[dict]`` — the members list at the top level.
      * ``{"members": [...], "size": N, "name": "..."}`` — the modern shape.
      * ``{"struct_name": "...", "member_count": N, "members": [...]}``.
    Callers of :func:`compact_analyze_struct` should not care which one
    the backend emitted; the transformer normalises them here.
    """
    if isinstance(raw, list):
        return list(raw), {}
    if isinstance(raw, dict):
        members = raw.get("members")
        if isinstance(members, list):
            # Preserve the header fields the vendored plugin already sent.
            header = {k: v for k, v in raw.items() if k != "members"}
            return list(members), header
    return [], {}


def compact_analyze_struct(raw: Any,
                           *,
                           name: str = "",
                           detail: bool = False,
                           members: list[str] | None = None) -> dict:
    """Transform an ``analyze_struct_detailed`` response.

    ``detail=False`` (default) collapses the response to
    ``{ok, name, size, member_count, kind:"summary", first_N:[...]}`` with
    only the first ten members inlined. ``detail=True`` returns the full
    member list (subject to the outer envelope's auto-spill). Passing
    ``members=[<name>...]`` short-circuits both branches and returns only
    the named members verbatim.

    Header fields the vendored plugin already emits (``size``,
    ``struct_name``, ``member_count``) survive the transform — the
    transformer never fabricates them and does not require any particular
    top-level shape.
    """
    members = list(members or [])
    all_members, header = _extract_struct_members(raw)
    total = len(all_members)
    struct_name = header.get("name") or header.get("struct_name") or name

    if members:
        subset = [m for m in all_members if _member_name(m) in members]
        return {
            "ok": True,
            "name": struct_name,
            "size": header.get("size"),
            "member_count": total,
            "returned": len(subset),
            "requested": list(members),
            "members": subset,
            "kind": "subset",
        }

    if not detail:
        preview = all_members[:_ANALYZE_STRUCT_PREVIEW_ROWS]
        return {
            "ok": True,
            "name": struct_name,
            "size": header.get("size"),
            "member_count": total,
            "kind": "summary",
            "first_10": preview,
            "hint": (
                "member_count=" + str(total) + " — pass detail=true for the "
                "full list, or members=['field_a','field_b'] for just the "
                "fields you need."
            ),
        }

    return {
        "ok": True,
        "name": struct_name,
        "size": header.get("size"),
        "member_count": total,
        "kind": "detailed",
        "members": all_members,
    }


def _member_name(member: Any) -> str:
    if isinstance(member, dict):
        return str(member.get("name") or member.get("field_name") or "")
    return ""


# --------------------------------------------------------------------------- #
# v0.17 D-3 — decompile_function windowing + annotations toggle.
# --------------------------------------------------------------------------- #
#
# The vendored ``decompile_function`` always emits per-line
# ``/* line: N, address: 0x… */`` comments — measured at 30-40% overhead
# across a 35 KB decompilation of ``nvlddmkm.sys``. The transformer:
#   * strips the annotation trailers when ``annotations=false`` (the new
#     default; opt back in with ``annotations=true``);
#   * narrows the returned text to a line window around a given address
#     when ``around_address`` is set;
#   * truncates the response at ``max_bytes`` and flags ``truncated:true``.
#
# The transformer is pure text-in / text-out; the shim wraps it around the
# raw decompile text pulled off the backend response.


_ANNOT_RE = re.compile(
    r"[ \t]*/\*\s*line:\s*\d+,\s*address:\s*0x[0-9a-fA-F]+\s*\*/"
)
_ADDR_HINT_RE = re.compile(r"address:\s*0x([0-9a-fA-F]+)")


def strip_decompile_annotations(text: str) -> str:
    """Remove trailing ``/* line: N, address: 0x… */`` comments in ``text``.

    Preserves blank lines and indentation; the annotation is always on the
    tail of a source line so trimming trailing whitespace after the strip
    keeps the diff to what the caller expects.
    """
    if not text:
        return text
    out: list[str] = []
    for ln in text.split("\n"):
        stripped = _ANNOT_RE.sub("", ln)
        out.append(stripped.rstrip())
    return "\n".join(out)


def _parse_hex_ea(value: str | int) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v, 0)
    except ValueError:
        return None


def _window_by_address(text: str,
                      target_ea: int,
                      window_lines: int) -> tuple[str, dict | None]:
    """Return ``(windowed_text, {first_line, last_line})`` around ``target_ea``.

    Uses per-line ``address:`` hints in the raw decompile to locate the
    closest ea; if the text has been de-annotated already there are no
    hints to key on, so the caller sees the full text and ``span=None``.
    """
    lines = text.split("\n")
    best_idx = -1
    best_ea = -1
    for i, ln in enumerate(lines):
        m = _ADDR_HINT_RE.search(ln)
        if not m:
            continue
        try:
            lea = int(m.group(1), 16)
        except ValueError:
            continue
        # Choose the closest hint at or below the target — matches how
        # Hex-Rays lays out its line->ea mapping (each source line covers a
        # range starting at its address).
        if lea <= target_ea and lea > best_ea:
            best_ea = lea
            best_idx = i
    if best_idx < 0:
        return text, None
    lo = max(0, best_idx - window_lines)
    hi = min(len(lines), best_idx + window_lines + 1)
    return "\n".join(lines[lo:hi]), {"first_line": lo, "last_line": hi}


def apply_decompile_window(text: str,
                           *,
                           annotations: bool = False,
                           around_address: str | int = "",
                           window_lines: int = 40,
                           max_bytes: int = 0) -> dict:
    """Apply the D-3 transforms to a raw Hex-Rays decompilation.

    Returns ``{text, annotations, windowed, window_span, truncated,
    byte_count}``. ``window_span`` is ``None`` when the caller passed no
    ``around_address`` or when the text carries no annotation hints to
    key on (windowing degrades gracefully — full text back, ``windowed=
    False`` — instead of guessing).
    """
    if text is None:
        text = ""

    # Windowing keys off the raw ``address:`` hints — so strip AFTER we
    # slice the window. Callers who pass both ``annotations=false`` and
    # ``around_address`` still get the correct window.
    span: dict | None = None
    windowed = False
    if around_address:
        target = _parse_hex_ea(around_address)
        if target is not None:
            wtext, span = _window_by_address(text, target, window_lines)
            text = wtext
            windowed = span is not None

    if not annotations:
        text = strip_decompile_annotations(text)

    truncated = False
    if max_bytes and len(text) > max_bytes:
        text = text[:max_bytes]
        truncated = True

    return {
        "text": text,
        "annotations": bool(annotations),
        "windowed": windowed,
        "window_span": span,
        "truncated": truncated,
        "byte_count": len(text),
    }


# --------------------------------------------------------------------------- #
# v0.17 D-4 — nearest_function on decompile failure envelopes.
# --------------------------------------------------------------------------- #
#
# When ``decompile_function`` fails (mid-function address, no Hex-Rays,
# corrupted analysis) the caller sees ``decompile_error`` but the address
# has no other context — the analyst either has to call
# ``ida_query_context`` themselves or fetch the function list and grep.
# D-4 auto-computes ``nearest_function`` from ida_query_context and
# attaches it to the failure envelope so the analyst sees the containing
# function's start / end / delta in the same round trip.


def compute_nearest_function(query_ctx: dict | None,
                             target_ea_str: str | int,
                             function_name: str | None = None
                             ) -> dict | None:
    """Return a ``{start, end, delta, name}`` blob for ``target_ea_str``.

    ``query_ctx`` is the response of the extension's ``ida_query_context``
    call (``{ok, in_function, function_start, function_end, ...}``).
    Returns ``None`` when the ctx is missing / errored, when the caller
    isn't inside a defined function, or when ``function_start`` is absent.

    ``function_name`` is optional; when the ctx already carries it (a
    future extension may), pass it through; otherwise the caller can
    resolve the name via ``get_function_by_address`` and re-invoke.
    """
    if not isinstance(query_ctx, dict):
        return None
    if not query_ctx.get("ok"):
        return None
    if not query_ctx.get("in_function"):
        return None
    fn_start_str = query_ctx.get("function_start")
    if not fn_start_str:
        return None
    fn_start = _parse_hex_ea(fn_start_str)
    ea = _parse_hex_ea(target_ea_str)
    if fn_start is None or ea is None:
        return None
    return {
        "start": fn_start_str,
        "end": query_ctx.get("function_end"),
        "delta": ea - fn_start,
        "name": function_name or query_ctx.get("function_name"),
    }


__all__ = [
    "ARG_ALIASES",
    "apply_arg_aliases",
    "apply_decompile_window",
    "collect_string_field_names",
    "compact_analyze_struct",
    "compute_nearest_function",
    "group_xrefs",
    "strip_decompile_annotations",
    "walk_and_coerce",
]
