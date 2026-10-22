"""Read-side views over retained evidence records.

``summary_view`` — counts + provenance + coverage only (no payload rows or
bytes): the inline ``data`` for ``detail="summary"`` results.

``page_view`` — ``(page, total, truncated)`` over the record's main payload
field, the one ``_spill`` would have picked (via ``_spill._pick_biggest_field``).
Strings page by characters, lists by rows; anything else is a single
one-row blob. The import from ``_spill`` is function-local: ``_spill``
lazily imports this package for spill-path retention, and a top-level
import here would close an import cycle.
"""
from __future__ import annotations

from typing import Any


def main_field(record: dict) -> str | None:
    """Name of the record's main payload field (``None`` when data is not
    a dict of fields)."""
    data = record.get("data") if isinstance(record, dict) else None
    if isinstance(data, dict):
        from .._spill import _pick_biggest_field
        name, _value = _pick_biggest_field(data)
        return name
    return None


def _sized_len(value: Any) -> int | None:
    if isinstance(value, (str, list, dict)):
        return len(value)
    return None


def summary_view(record: dict) -> dict:
    """Counts + provenance + coverage only — no payload rows/bytes.

    Shape: ``{counts: {field: len}, coverage?: {...}, provenance?: {...},
    request: sanitized_request}``. ``coverage``/``provenance`` are the
    Part 1 blocks copied verbatim from the complete result — a summary
    never rewrites them."""
    record = record if isinstance(record, dict) else {}
    data = record.get("data")
    counts: dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            n = _sized_len(v)
            if n is not None:
                counts[str(k)] = n
    elif isinstance(data, list):
        counts["items"] = len(data)
    elif isinstance(data, str):
        counts["text"] = len(data)
    out: dict[str, Any] = {"counts": counts,
                           "request": record.get("request") or {}}
    if isinstance(record.get("coverage"), dict):
        out["coverage"] = record["coverage"]
    if isinstance(record.get("provenance"), dict):
        out["provenance"] = record["provenance"]
    return out


def page_view(record: dict, *, offset: int, limit: int) -> tuple[Any, int, bool]:
    """``(rows_or_bytes_page, total, truncated)`` for the record's main
    payload field. ``offset``/``limit`` are clamped >= 0; ``limit <= 0``
    means "everything remaining"."""
    record = record if isinstance(record, dict) else {}
    data = record.get("data")
    offset = max(0, int(offset))
    limit = max(0, int(limit))

    value: Any = data
    if isinstance(data, dict):
        from .._spill import _pick_biggest_field
        _name, value = _pick_biggest_field(data)
        if value is None:
            value = data  # no spillable field — one blob row

    if value is None:
        return [], 0, False
    if isinstance(value, (str, list)):
        total = len(value)
        end = offset + limit if limit > 0 else total
        page = value[offset:end]
        return page, total, (offset + len(page)) < total
    return [value], 1, False
