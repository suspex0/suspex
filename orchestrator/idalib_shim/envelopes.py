"""v0.14 pending/artifact envelopes emitted by the shim when a passthrough
tool call gets promoted to a background job or when its serialised
result exceeds ``CHUNK_BYTES``.

Mechanical split-out from ``idalib_stdio_shim.py``; no behavior changes.
"""
from __future__ import annotations

import json

from .jobs import CHUNK_BYTES, _chunk_count, _write_listing_spill
from .listing import _preview


def _pending_envelope(job_id: str, tool: str, *, action: str = "",
                      elapsed_ms: int = 0) -> str:
    """v0.14 envelope for a still-running background job.

    Shape:
      {ok: true, kind: 'pending', tool: 'ida_manage',
       action: <backend tool name>,
       data: {job_id, state: 'running'},
       summary: {elapsed_ms},
       warnings: ["job still running; poll ida_manage(action='ida_job_status', ...)"]}
    """
    return json.dumps({
        "ok": True,
        "kind": "pending",
        "tool": "ida_manage",
        "action": action or tool,
        "data": {"job_id": job_id, "state": "running"},
        "summary": {"elapsed_ms": int(elapsed_ms)},
        "warnings": [
            f"job still running; poll ida_manage(action='ida_job_status', "
            f"job_id={job_id!r})"
        ],
    })


def _chunked_envelope(job_id: str, tool: str, text: str, *,
                      action: str = "") -> str:
    """v0.14 envelope for a completed but over-budget result.

    Also writes the full listing bytes to <spill_dir>/<sha256>.listing
    so `file_manage(action='read_artifact', sha256=...)` can serve them
    by content hash. The caller records `sha256` on the JOBS entry so
    the legacy `ida_result(job_id=..., page=N)` fetch path still works
    against the same payload (via the in-memory JOBS cache).
    """
    raw = text.encode("utf-8", errors="replace")
    total_bytes = len(raw)
    total_chunks = _chunk_count(total_bytes, CHUNK_BYTES)
    sha = _write_listing_spill(raw)
    preview = _preview(text)
    return json.dumps({
        "ok": True,
        "kind": "artifact",
        "tool": "ida_manage",
        "action": action or tool,
        "data": {"job_id": job_id, "preview": preview},
        "summary": {
            "item_total": total_chunks,
            "size_bytes": total_bytes,
            "truncated": True,
            "next_page": 0,
        },
        "artifact": {
            "sha256": sha,
            "size": total_bytes,
            "content_type": "listing",
            "field": "listing",
            "preview": preview,
            "replay_hint": (
                # page_size defaults to the shim's CHUNK_BYTES, which
                # read_listing_page also uses when the caller passes
                # anything < 1024 — spell it out so the hint's numbers
                # match what read_listing_page will actually return.
                f"file_manage(action='read_artifact', sha256='{sha}', "
                f"page=0, page_size={CHUNK_BYTES})"
            ),
        },
    })
