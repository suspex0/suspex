"""Pending/artifact envelopes emitted by the shim when a passthrough
tool call gets promoted to a background job or when its serialised
result exceeds ``CHUNK_BYTES``.

Same v0.14 envelope shape as ``idalib_shim.envelopes`` — the bridge's
poller parses ``kind:'pending'``/``kind:'artifact'`` — with the tool
name stamped ``ghidra_manage``.
"""
from __future__ import annotations

import json

from .jobs import CHUNK_BYTES, _chunk_count, _write_listing_spill
from .listing import _preview


def _pending_envelope(job_id: str, tool: str, *, action: str = "",
                      elapsed_ms: int = 0) -> str:
    """Envelope for a still-running background job."""
    return json.dumps({
        "ok": True,
        "kind": "pending",
        "tool": "ghidra_manage",
        "action": action or tool,
        "data": {"job_id": job_id, "state": "running"},
        "summary": {"elapsed_ms": int(elapsed_ms)},
        "warnings": [
            f"job still running; poll ghidra_manage(action='ghidra_job_status', "
            f"job_id={job_id!r})"
        ],
    })


def _chunked_envelope(job_id: str, tool: str, text: str, *,
                      action: str = "") -> str:
    """Envelope for a completed but over-budget result.

    Also writes the full listing bytes to <spill_dir>/<sha256>.listing
    so `file_manage(action='read_artifact', sha256=...)` can serve them
    by content hash. The caller records `sha256` on the JOBS entry so
    the legacy `ghidra_result(job_id=..., page=N)` fetch path still works
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
        "tool": "ghidra_manage",
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
                f"file_manage(action='read_artifact', sha256='{sha}', "
                f"page=0, page_size={CHUNK_BYTES})"
            ),
        },
    })
