"""Auto-spill: replace over-budget response payloads with on-disk artifacts.

Layer 2 of the v0.14 hard cutover. Every envelope produced by `_guard` flows
through `maybe_spill(env, budget_bytes, spill_dir)` in `_envelope.finalize`.
When the serialized envelope exceeds the byte budget, the largest field in
`data` is written to `<spill_dir>/<sha256>.<ext>` and the inline value is
replaced by a small preview plus an `env["artifact"]` slot the caller uses
to fetch the rest.

The caller retrieves spilled content via a new action on `file_manage`:

    file_manage(action="read_artifact", sha256=..., offset=..., length=...)
    file_manage(action="read_artifact", sha256=..., page=..., page_size=...)

Content types:
    hex     — the field was a hex string, written as raw bytes (.bin)
    text    — the field was arbitrary text (.txt)
    jsonl   — list of records, one per line, indexed by a .idx sidecar
    json    — structured payload (dict / list of scalars) written pretty
    listing — text listing that grows in "pages" (IDA disasm / decompile); rare

Sha256 is over the RAW bytes written to disk, so identical payloads dedupe.
A sidecar `.idx` next to a `.jsonl` file holds the byte offset of each row
so `read_rows(page, page_size)` seeks in O(1).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

# Field names that carry byte-buffer content. Their string value is either
# hex-encoded bytes (default) or plain text (some tools).
_HEX_FIELDS: frozenset[str] = frozenset({
    "hex", "bytes_hex", "raw", "content_hex", "dump",
})
_TEXT_FIELDS: frozenset[str] = frozenset({
    "stdout", "stderr", "output", "text", "payload", "roundtrip",
    "cmd_output", "content", "listing",
})
# Fields we should never spill — they are metadata, not payload.
_NEVER_SPILL: frozenset[str] = frozenset({
    "summary", "artifact", "warnings", "error", "kind", "tool", "action", "ok",
    "size", "size_bytes", "item_count", "item_total", "sha256", "preview",
    "count", "truncated", "next_cursor", "next_page", "elapsed_ms",
    "encoding", "replay_hint", "content_type",
})

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# ---------------------------------------------------------------------------
# Public: read a spilled artifact back
# ---------------------------------------------------------------------------

def read_slice(sha256: str, spill_dir: Path,
               offset: int = 0, length: int = 0,
               *, path: Path | None = None) -> dict[str, Any]:
    """Read a byte range from a spilled artifact. Works for .bin / .txt / .json.
    `length=0` reads to EOF (bounded by 4 MiB per read to keep responses
    within the caller's budget). Returns a dict suitable for use as an
    envelope's `data` field.

    `path=` (v0.27) reads a resolved artifact file directly — the
    whole-store sha index (``_artifacts.find_artifact_by_sha``) finds
    dumps/ingested payloads that never passed through spill/."""
    if path is None:
        path = _resolve_by_sha(sha256, spill_dir)
    total = path.stat().st_size
    offset = max(0, int(offset))
    max_read = 4 * 1024 * 1024
    length = min(int(length) if length > 0 else total - offset, total - offset, max_read)

    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(length)

    ct = _content_type_from_ext(path.suffix)
    result: dict[str, Any] = {
        "sha256": sha256,
        "content_type": ct,
        "size": total,
        "offset": offset,
        "length": len(data),
        "next_offset": offset + len(data) if offset + len(data) < total else None,
    }
    if ct in ("text", "json", "jsonl", "listing"):
        result["text"] = data.decode("utf-8", errors="replace")
    else:
        result["hex"] = data.hex()
    return result


def read_rows(sha256: str, spill_dir: Path,
              page: int = 0, page_size: int = 64) -> dict[str, Any]:
    """Read a page of rows from a .jsonl spill using the .idx sidecar for
    O(1) seek. Returns a dict with `items` and next-page metadata suitable
    for envelope data."""
    path = _resolve_by_sha(sha256, spill_dir)
    if path.suffix != ".jsonl":
        raise ValueError(
            f"read_rows: artifact {sha256[:12]}... is not a .jsonl spill "
            f"(got {path.suffix}); use offset/length reads instead"
        )
    idx_path = path.with_suffix(".idx")
    if not idx_path.exists():
        raise FileNotFoundError(
            f"read_rows: index sidecar missing for {sha256[:12]}..."
        )

    offsets: list[int] = json.loads(idx_path.read_text(encoding="utf-8"))
    total = len(offsets)
    page = max(0, int(page))
    page_size = max(1, min(int(page_size), 1000))
    start = page * page_size
    end = min(start + page_size, total)

    items: list[dict] = []
    if start < total:
        with path.open("rb") as f:
            f.seek(offsets[start])
            end_off = offsets[end] if end < total else path.stat().st_size
            blob = f.read(end_off - offsets[start])
        for line in blob.splitlines():
            if not line.strip():
                continue
            items.append(json.loads(line))

    result: dict[str, Any] = {
        "sha256": sha256,
        "content_type": "jsonl",
        "items": items,
        "page": page,
        "page_size": page_size,
        "item_count": len(items),
        "item_total": total,
    }
    if end < total:
        result["next_page"] = page + 1
    return result


# ---------------------------------------------------------------------------
# Public: spill a payload if it's over budget
# ---------------------------------------------------------------------------

def maybe_spill(env: dict, *, budget_bytes: int, spill_dir: Path,
                preview_bytes: int = 512,
                artifacts_root: Path | None = None,
                ledger: Any | None = None,
                request: dict | None = None) -> dict:
    """If the envelope's serialized size is over budget, pick the biggest
    field in `data` and spill it. Mutates `env` in place and returns it.

    Rules:
      * Never spill from `error`, `summary`, `warnings`, or top-level metadata.
      * Prefer known byte-buffer fields (hex, bytes_hex, stdout, ...).
      * Fall back to the largest value in `data` by serialized size.
      * Skip when `data` isn't a dict/list (nothing to peel off).
      * Skip when budget is <= 0 (caller disabled spill).

    Part 3 evidence wiring: the keyword args `artifacts_root`, `ledger`,
    and `request` default to None, and a bare call behaves exactly as
    before. When all three are wired (from `_emit`), a successful spill
    ALSO retains the complete pre-spill payload as an evidence record and
    sets `env["evidence"]` with a `continuation` handle pointing at
    `knowledge_manage(action='evidence_get')` — `continuation` supersedes
    the legacy `replay_hint`, which is kept unchanged for back-compat.
    A producer-stamped `env["evidence"]` (heavy tools with detail=)
    already owns the complete record; only the continuation is added then.
    """
    if budget_bytes is None or budget_bytes <= 0:
        return env

    try:
        current_size = len(json.dumps(env, default=str))
    except (TypeError, ValueError):
        return env

    if current_size <= budget_bytes:
        return env

    data = env.get("data")
    if not isinstance(data, (dict, list)):
        return env

    spill_dir.mkdir(parents=True, exist_ok=True)
    wired = artifacts_root is not None and ledger is not None

    # Case 1: data is a list of records — spill the whole list as .jsonl.
    if isinstance(data, list):
        if _spill_list(env, data, spill_dir, preview_bytes=preview_bytes):
            _mark_truncated(env)
            if wired:
                _evidence_after_spill(env, data=data,
                                      artifacts_root=artifacts_root,
                                      ledger=ledger, request=request,
                                      field="data")
        return env

    # Case 2: data is a dict — find the biggest spillable field.
    field_name, field_value = _pick_biggest_field(data)
    if field_name is None:
        return env

    original = dict(data) if wired else None
    if _spill_field(env, data, field_name, field_value, spill_dir,
                    preview_bytes=preview_bytes):
        _mark_truncated(env)
        if wired:
            _evidence_after_spill(env, data=original,
                                  artifacts_root=artifacts_root,
                                  ledger=ledger, request=request,
                                  field=field_name)
    return env


def _evidence_after_spill(env: dict, *, data: Any,
                          artifacts_root: Path | None,
                          ledger: Any, request: dict | None,
                          field: str) -> None:
    """Part 3: retain the pre-spill payload as an evidence record after a
    successful spill. Best-effort — the spill itself already succeeded, so
    retention failures only skip the `evidence` block."""
    try:
        from .evidence import store as _ev_store
    except Exception:  # pragma: no cover — import safety
        return
    block = env.get("evidence")
    if isinstance(block, dict) and block.get("evidence_id"):
        # Heavy tool already retained the complete record; just add the
        # continuation handle (the payload was NOT fully delivered inline).
        block.setdefault(
            "continuation",
            _ev_store.continuation(str(block["evidence_id"])))
        return
    if data is None:
        return
    if artifacts_root is None:
        return
    try:
        _record, ev_block = _ev_store.retain_record(
            request=request or {}, data=data,
            artifacts_root=artifacts_root, ledger=ledger,
            tool=str(env.get("tool") or ""),
            action=str(env.get("action") or ""),
            detail="complete", operation=f"spill:{field}")
        # The inline payload was NOT fully delivered — the continuation
        # is mandatory for spill-path evidence (Task 3.3).
        ev_block["continuation"] = _ev_store.continuation(
            str(ev_block["evidence_id"]))
        env["evidence"] = ev_block
    except Exception as exc:  # noqa: BLE001 — retention is best-effort
        log.warning("evidence retention after spill dropped: %s", exc)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _resolve_by_sha(sha256: str, spill_dir: Path) -> Path:
    if not sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError(f"invalid sha256 {sha256!r}")
    for ext in (".bin", ".txt", ".jsonl", ".json", ".listing"):
        p = spill_dir / f"{sha256.lower()}{ext}"
        if p.exists():
            return p
    raise FileNotFoundError(
        f"no spilled artifact with sha256 {sha256[:12]}... in {spill_dir}"
    )


def _content_type_from_ext(ext: str) -> str:
    return {
        ".bin": "hex",
        ".txt": "text",
        ".jsonl": "jsonl",
        ".json": "json",
        ".listing": "listing",
    }.get(ext, "bin")


def _pick_biggest_field(data: dict) -> tuple[str | None, Any]:
    """Return (name, value) for the biggest spillable field in `data`,
    scored by serialized JSON size. Deterministic across process runs —
    frozenset iteration order over the known-field allowlist is
    randomized under PYTHONHASHSEED, so we score every candidate the
    same way instead of returning the first known-name hit."""
    known = _HEX_FIELDS | _TEXT_FIELDS
    biggest: tuple[str | None, Any, int] = (None, None, 0)
    for k, v in data.items():
        if k in _NEVER_SPILL:
            continue
        if not _is_spillable(k, v):
            continue
        try:
            sz = len(json.dumps(v, default=str))
        except (TypeError, ValueError):
            continue
        # Known-name fields tie-break as bigger — they carry byte-buffer
        # semantics the caller expects to spill (hex/stdout/output/...),
        # and we lean toward preserving those over a wider row-list
        # sibling with slightly higher serialized size.
        weight = sz * 2 if k in known else sz
        if weight > biggest[2]:
            biggest = (k, v, weight)
    return biggest[0], biggest[1]


def _is_spillable(name: str, value: Any) -> bool:
    if name in _NEVER_SPILL:
        return False
    if isinstance(value, str):
        return len(value) > 128
    if isinstance(value, (list, dict)):
        return True
    return False


def _spill_field(env: dict, data: dict, name: str, value: Any,
                 spill_dir: Path, *, preview_bytes: int) -> bool:
    """Spill one field. Returns True on success (mutates env/data)."""
    if isinstance(value, str):
        if name in _HEX_FIELDS and _HEX_RE.fullmatch(value) and len(value) % 2 == 0:
            raw = bytes.fromhex(value)
            ext, ct = ".bin", "hex"
            preview = raw[: min(64, preview_bytes // 8)].hex()
        elif name in _HEX_FIELDS:
            # A `hex` field that isn't valid hex — treat as text.
            raw = value.encode("utf-8", errors="replace")
            ext, ct = ".txt", "text"
            preview = value[:preview_bytes]
        else:
            raw = value.encode("utf-8", errors="replace")
            ext, ct = ".txt", "text"
            preview = value[:preview_bytes]
    elif isinstance(value, list):
        # If every item is a dict, use jsonl; otherwise json.
        if value and all(isinstance(x, dict) for x in value):
            raw, offsets = _serialize_jsonl(value)
            ext, ct = ".jsonl", "jsonl"
            preview_rows = value[:8]
        else:
            raw = json.dumps(value, indent=2, default=str).encode("utf-8")
            ext, ct = ".json", "json"
            preview_rows = value[:8] if len(value) > 8 else value
        preview = None
    elif isinstance(value, dict):
        raw = json.dumps(value, indent=2, default=str).encode("utf-8")
        ext, ct = ".json", "json"
        preview = None
    else:
        return False

    sha = hashlib.sha256(raw).hexdigest()
    dest = spill_dir / f"{sha}{ext}"
    if not dest.exists():
        dest.write_bytes(raw)
    if ct == "jsonl":
        idx_path = dest.with_suffix(".idx")
        if not idx_path.exists():
            idx_path.write_text(json.dumps(offsets), encoding="utf-8")

    # Replace field in `data` with a compact reference.
    if ct == "jsonl":
        data[name] = {
            "spilled": True,
            "preview_rows": preview_rows,
        }
        item_total = len(value)
        env.setdefault("summary", {}).setdefault("item_total", item_total)
    elif ct == "json":
        data[name] = {
            "spilled": True,
            "preview": preview_rows if isinstance(value, list) else None,
        }
    else:
        data[name] = {
            "spilled": True,
            "preview": preview,
        }

    env["artifact"] = {
        "sha256": sha,
        "size": len(raw),
        "content_type": ct,
        "field": name,
        "preview": preview if preview is not None else "",
        "replay_hint": (
            f"file_manage(action='read_artifact', sha256='{sha}', "
            + ("page=0, page_size=64)" if ct == "jsonl" else "offset=0)")
        ),
    }
    return True


def _spill_list(env: dict, data: list, spill_dir: Path,
                *, preview_bytes: int) -> bool:
    """Spill an entire list payload (when `data` itself is a list of records)."""
    if data and all(isinstance(x, dict) for x in data):
        raw, offsets = _serialize_jsonl(data)
        ext, ct = ".jsonl", "jsonl"
    else:
        raw = json.dumps(data, indent=2, default=str).encode("utf-8")
        ext, ct = ".json", "json"

    sha = hashlib.sha256(raw).hexdigest()
    dest = spill_dir / f"{sha}{ext}"
    if not dest.exists():
        dest.write_bytes(raw)
    if ct == "jsonl":
        idx_path = dest.with_suffix(".idx")
        if not idx_path.exists():
            idx_path.write_text(json.dumps(offsets), encoding="utf-8")

    env["data"] = {
        "spilled": True,
        "preview_rows": data[:8] if ct == "jsonl" else data[:8],
        "item_total": len(data),
    }
    env.setdefault("summary", {})["item_total"] = len(data)
    env["artifact"] = {
        "sha256": sha,
        "size": len(raw),
        "content_type": ct,
        "field": "data",
        "preview": "",
        "replay_hint": (
            f"file_manage(action='read_artifact', sha256='{sha}', "
            + ("page=0, page_size=64)" if ct == "jsonl" else "offset=0)")
        ),
    }
    return True


def _serialize_jsonl(rows: Iterable[dict]) -> tuple[bytes, list[int]]:
    """Serialize a list of dicts as line-delimited JSON, returning bytes and
    the byte offset of each row so a .idx sidecar can seek in O(1)."""
    out = bytearray()
    offsets: list[int] = []
    for row in rows:
        offsets.append(len(out))
        line = json.dumps(row, default=str).encode("utf-8")
        out.extend(line)
        out.append(0x0A)  # '\n'
    return bytes(out), offsets


def _mark_truncated(env: dict) -> None:
    # ``truncated`` is shared with the paging boundary signal, so a caller
    # cannot tell from it alone whether to recover via ``offset``/cursor (more
    # pages) or via the on-disk artifact (payload spilled). ``spilled`` is the
    # unambiguous spill marker; the ``artifact``/``evidence`` blocks carry the
    # retrieval handle. ``truncated`` stays set for back-compat.
    summary = env.setdefault("summary", {})
    summary["truncated"] = True
    summary["spilled"] = True


def read_listing_page(sha256: str, spill_dir: Path,
                      page: int = 0, page_size: int = 0) -> dict[str, Any]:
    """Read a page of a ``.listing`` spill (from the L6 IDA disasm/decompile
    fold) as a fixed-size byte chunk.

    Chunk size defaults to ``SUSPX_IDA_JOB_CHUNK_BYTES`` (24 KiB), the same
    unit the fold uses to grow the listing on disk. A caller-supplied
    ``page_size`` below 1024 bytes is ignored so the row-paging default
    (64) does not fragment the listing into micro-chunks.
    """
    path = _resolve_by_sha(sha256, spill_dir)
    if path.suffix != ".listing":
        raise ValueError(
            f"read_listing_page: artifact {sha256[:12]}... is not a "
            f".listing spill (got {path.suffix}); use offset/length reads"
        )

    # Default MUST match idalib_stdio_shim.CHUNK_BYTES (24000) — the shim
    # writes .listing files in that unit, and its `summary.item_total`
    # advertised in the chunked envelope is computed with the same
    # constant. A mismatch would make the reader disagree with the
    # producer about how many pages a listing has.
    default_chunk = 24000
    try:
        default_chunk = int(os.environ.get(
            "SUSPX_IDA_JOB_CHUNK_BYTES", default_chunk))
    except (TypeError, ValueError):
        pass
    if default_chunk <= 0:
        default_chunk = 24000

    page = max(0, int(page))
    ps = int(page_size)
    chunk = ps if ps >= 1024 else default_chunk

    total = path.stat().st_size
    item_total = (total + chunk - 1) // chunk if chunk > 0 else 0
    start = page * chunk
    end = min(start + chunk, total)
    if start >= total:
        blob = b""
    else:
        with path.open("rb") as f:
            f.seek(start)
            blob = f.read(end - start)

    result: dict[str, Any] = {
        "sha256": sha256,
        "content_type": "listing",
        "size": total,
        "page": page,
        "page_size": chunk,
        "item_count": len(blob),
        "item_total": item_total,
        "text": blob.decode("utf-8", errors="replace"),
    }
    if end < total:
        result["next_page"] = page + 1
    return result


__all__ = [
    "maybe_spill",
    "read_slice",
    "read_rows",
    "read_listing_page",
]
