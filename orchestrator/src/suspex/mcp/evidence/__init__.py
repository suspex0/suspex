"""Evidence store: deterministic retained records for heavy tool results.

Every heavy result (memory reads, decompilations, dump parses) is retained
verbatim under ``artifacts/evidence/<2-hex>/<ev_...>.json`` and addressable
by a deterministic ``evidence_id`` (``ev_`` + first 32 hex of sha256 over
the canonical ``{request, record}`` blob). The inline answer can be a
bounded summary (``detail="summary"``); the full record pages back via
``knowledge_manage(action='evidence_get', evidence_id=..., offset=...,
limit=...)`` instead of re-running the operation on the target.

Modules:
    store  — ids, atomic saves, retention, heavy-tool ``detail`` stamping.
    views  — summary_view / page_view over a retained record.

Envelope contract (shared with Part 1's ``provenance``/``coverage``): the
optional top-level ``evidence`` block is absent when not applicable, never
``null``. Legacy ``artifact``/``replay_hint`` spill blocks are untouched;
``evidence.continuation`` supersedes ``replay_hint``.
"""
from __future__ import annotations

from .store import (
    DETAIL_ACTIONS,
    EvidenceIdError,
    build_record,
    continuation,
    delete,
    delete_all,
    detail_applies,
    load,
    record_id,
    retain,
    retain_record,
    save,
    split_detail,
    stamp_result,
    valid_id,
    with_evidence,
)
from .views import main_field, page_view, summary_view

__all__ = [
    "DETAIL_ACTIONS",
    "EvidenceIdError",
    "build_record",
    "continuation",
    "delete",
    "delete_all",
    "detail_applies",
    "load",
    "main_field",
    "page_view",
    "record_id",
    "retain",
    "retain_record",
    "save",
    "split_detail",
    "stamp_result",
    "summary_view",
    "valid_id",
    "with_evidence",
]
