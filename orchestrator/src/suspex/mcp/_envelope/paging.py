"""Layer 3 paging helper + ``list_envelope`` composer.

Split out of ``_envelope.py`` (Phase 2b modular split). Holds
``apply_page_opts``, its ``_filter_rows`` / ``_project`` support, and the
``list_envelope`` convenience that composes paging + ``envelope_ok`` for
list-returning actions.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .build import envelope_ok
from .opts import resolve_kind, resolve_limit


# The opaque ``next_cursor`` we emit is ``"offset:N"``. Decode it here so a
# caller can hand the echoed cursor straight back as ``cursor=...`` instead of
# having to parse the string into ``offset=N`` themselves (the field it is
# passed back through used to be silently ignored).
_CURSOR_RE = re.compile(r"^offset:(\d+)$")


def decode_cursor(cursor: str) -> int:
    """Return the offset encoded in a ``"offset:N"`` cursor, or 0 when the
    cursor is empty/unrecognized (treated as "start from the top")."""
    if not cursor:
        return 0
    m = _CURSOR_RE.match(str(cursor).strip())
    return int(m.group(1)) if m else 0


# ---------------------------------------------------------------------------
# Paging helper (Layer 3)
# ---------------------------------------------------------------------------

def apply_page_opts(
    rows: list,
    *,
    tool: str,
    action: str,
    limit: int = 0,
    offset: int = 0,
    cursor: str = "",
    fields: Iterable[str] = (),
    filter: Any = "",
    summary: bool = False,
    global_cap: int = 0,
    default_limit: int = 64,
) -> tuple[list, int, int, int, bool]:
    """Apply the shared paging + projection + filter contract to a row list.

    Returns (items, item_count, item_total, next_offset_or_zero, truncated).
    The caller wraps `items` into `data = {"items": items}` and lifts the
    counters into `summary` via envelope_ok(...).

    * `filter` is a substring match against a str(row) rendering when str,
      or a dict of `{field: value_or_regex}` predicates ANDed together.
    * `fields` projects each dict-row down to just those keys (identity
      when empty). Non-dict rows pass through.
    * `summary=True` returns [] items and only the counters — for callers
      that just want to know "how many are there?" without the payload.
    """
    total = len(rows)

    # 1. Filter.
    if filter:
        rows = _filter_rows(rows, filter)

    filtered_total = len(rows)

    # 2. Projection.
    fields_list = [f for f in fields if f]
    if fields_list:
        rows = [_project(r, fields_list) for r in rows]

    # 3. Summary short-circuit.
    if summary:
        return [], 0, filtered_total, 0, filtered_total > 0

    # 4. Slice. An explicit offset wins; otherwise fall back to the offset
    #    encoded in a passed-back cursor ("offset:N").
    offset = max(0, int(offset)) or decode_cursor(cursor)
    lim = resolve_limit(tool, action, limit,
                        default_limit=default_limit, global_cap=global_cap)
    end = offset + lim
    sliced = rows[offset:end]
    next_offset = end if end < filtered_total else 0
    return sliced, len(sliced), filtered_total, next_offset, next_offset > 0


def _filter_rows(rows: list, spec: Any) -> list:
    """Filter `rows` by a substring/predicate spec. Str -> substring match
    over `str(row)`. Dict -> AND of {field: needle} where needle can be a
    plain value (equality) or a compiled regex."""
    if not spec:
        return rows
    if isinstance(spec, str):
        needle = spec.lower()
        return [r for r in rows if needle in str(r).lower()]
    if isinstance(spec, dict):
        import re as _re
        preds = []
        for k, v in spec.items():
            if isinstance(v, _re.Pattern):
                preds.append(lambda r, k=k, v=v: bool(v.search(str(r.get(k, "")))))
            else:
                needle = str(v).lower()
                preds.append(lambda r, k=k, n=needle: n in str(r.get(k, "")).lower())
        return [r for r in rows if all(p(r) for p in preds)]
    return rows


def _project(row: Any, fields: list[str]) -> Any:
    if not isinstance(row, dict):
        return row
    return {k: row[k] for k in fields if k in row}


def list_envelope(
    rows: list,
    *,
    tool: str,
    action: str,
    kind: str | None = None,
    limit: int = 0,
    offset: int = 0,
    cursor: str = "",
    fields: Iterable[str] = (),
    filter: Any = "",
    summary: bool = False,
    global_cap: int = 0,
    default_limit: int = 64,
    extras: dict | None = None,
) -> dict:
    """Compose apply_page_opts + envelope_ok into a full v0.14 envelope for
    a list-returning action. Every migrated list action returns:
        return _list_envelope(rows, tool="mem_rw", action="modules", ...)
    and inherits the uniform {data: {items: [...]}, summary: {item_count,
    item_total, truncated, next_cursor?}} shape automatically.
    """
    items, count, total, next_offset, truncated = apply_page_opts(
        rows, tool=tool, action=action,
        limit=limit, offset=offset, cursor=cursor, fields=fields, filter=filter,
        summary=summary,
        global_cap=global_cap, default_limit=default_limit,
    )
    data: dict[str, Any] = {"items": items}
    if extras:
        data.update(extras)
    next_cursor = None
    if next_offset > 0:
        # Opaque cursor — we only encode `offset:N` for now, but future
        # spilled-list follow-up may replace it with a sha256 pointer.
        next_cursor = f"offset:{next_offset}"
    return envelope_ok(
        data,
        kind=resolve_kind(tool, action, kind),
        tool=tool, action=action,
        item_count=count,
        item_total=total,
        truncated=truncated,
        next_cursor=next_cursor,
    )
