"""Passthrough job store: chunk math, retention pruning, result stash,
background job spawn, spill-directory resolution, and listing spill.

Direct port of ``idalib_shim.jobs`` — the machinery is engine-agnostic;
the JOBS record shape is identical so ``ghidra_job_*``/``ghidra_result``
behave exactly like their ``ida_job_*``/``ida_result`` counterparts.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from pathlib import Path

from .logging import _log


# Same budgeting model as the IDA shim: anything the backend doesn't
# return within SOFT_DEADLINE_S OR whose serialised text exceeds
# CHUNK_BYTES becomes a job the caller polls/pages.  Ghidra decompile of
# a large function is slower than Hex-Rays, so the default soft deadline
# is a bit more generous.
SOFT_DEADLINE_S = float(os.environ.get("SUSPX_GHIDRA_JOB_SOFT_DEADLINE_S", "30"))
CHUNK_BYTES = int(os.environ.get("SUSPX_GHIDRA_JOB_CHUNK_BYTES", "24000"))
JOB_RETENTION_S = float(os.environ.get("SUSPX_GHIDRA_JOB_RETENTION_S", "1800"))


# job_id -> {tool, args, task, status, result_text, error, started_at, ...}
# result_text is set once the task completes; chunks/total are derived
# from it on the fly by ghidra_result. See _stash_result / _spawn_job.
JOBS: dict[str, dict] = {}
JOBS_LOCK = asyncio.Lock()


def _chunk_count(total_bytes: int, chunk_bytes: int) -> int:
    if total_bytes <= 0:
        return 0
    return (total_bytes + chunk_bytes - 1) // chunk_bytes


async def _prune_jobs_locked() -> None:
    now = time.monotonic()
    stale = [jid for jid, j in JOBS.items()
             if j.get("finished_at") and now - j["finished_at"] > JOB_RETENTION_S]
    for jid in stale:
        JOBS.pop(jid, None)


async def _stash_result(tool: str, args: dict, sid: str, text: str) -> str:
    """Create a done job holding `text`. Returns job_id."""
    job_id = "j_" + uuid.uuid4().hex[:12]
    async with JOBS_LOCK:
        await _prune_jobs_locked()
        JOBS[job_id] = {
            "tool": tool, "args": args, "sid": sid,
            "task": None, "started_at": time.monotonic(),
            "status": "done", "result_text": text,
            "error": None, "total_bytes": len(text),
            "chunk_bytes": CHUNK_BYTES,
            "finished_at": time.monotonic(),
        }
    return job_id


async def _spawn_job(tool: str, args: dict, sid: str,
                     coro_factory) -> str:
    """Create a pending job that runs `coro_factory()` to completion in
    the background. Returns job_id immediately. On completion, the task
    stores result_text on the JOBS entry."""
    # Imported lazily to keep this module free of the listing/content
    # cycle at import time.
    from .listing import _flat_text_from_content

    job_id = "j_" + uuid.uuid4().hex[:12]
    started = time.monotonic()

    async def _run() -> None:
        try:
            content = await coro_factory()
            text = _flat_text_from_content(content) if isinstance(content, list) else str(content)
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is None:
                    return
                j["status"] = "done"
                j["result_text"] = text
                j["total_bytes"] = len(text)
                j["finished_at"] = time.monotonic()
        except asyncio.CancelledError:
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is not None and j["status"] == "pending":
                    j["status"] = "cancelled"
                    j["finished_at"] = time.monotonic()
            raise
        except Exception as exc:  # noqa: BLE001
            async with JOBS_LOCK:
                j = JOBS.get(job_id)
                if j is not None:
                    j["status"] = "error"
                    j["error"] = f"{type(exc).__name__}: {exc}"
                    j["finished_at"] = time.monotonic()

    task = asyncio.create_task(_run(), name=f"ghidra-job-{tool}-{job_id}")
    async with JOBS_LOCK:
        await _prune_jobs_locked()
        JOBS[job_id] = {
            "tool": tool, "args": args, "sid": sid,
            "task": task, "started_at": started,
            "status": "pending", "result_text": None,
            "error": None, "total_bytes": 0,
            "chunk_bytes": CHUNK_BYTES,
            "finished_at": None,
        }
    return job_id


def _shim_spill_dir() -> Path:
    """Where to write full-listing bytes for chunked envelopes so
    file_manage(action='read_artifact', sha256=...) can serve them by
    content hash long after the in-memory JOBS entry has expired.

    Same resolution order as the idalib shim: SUSPX_MCP_SPILL_DIR >
    <SUSPX_ARTIFACTS_DIR>/spill > <repo>/artifacts/spill.
    """
    envd = os.environ.get("SUSPX_MCP_SPILL_DIR")
    if envd:
        return Path(envd)
    artifacts = os.environ.get("SUSPX_ARTIFACTS_DIR")
    if artifacts:
        return Path(artifacts) / "spill"
    return Path(__file__).resolve().parent.parent.parent / "artifacts" / "spill"


def _write_listing_spill(raw: bytes) -> str:
    """Write full listing bytes to <spill_dir>/<sha256>.listing (dedup
    by content hash). Returns the sha256 hex digest. Filesystem errors
    are logged but non-fatal — the envelope still carries the sha256 +
    preview, and the in-memory JOBS cache remains available for
    legacy ghidra_result(job_id, page) fetches.
    """
    sha = hashlib.sha256(raw).hexdigest()
    try:
        spill_dir = _shim_spill_dir()
        spill_dir.mkdir(parents=True, exist_ok=True)
        dest = spill_dir / f"{sha}.listing"
        if not dest.exists():
            dest.write_bytes(raw)
    except OSError as exc:
        _log(f"shim: spill write failed for {sha[:12]}...: {exc}")
    return sha
