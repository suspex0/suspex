"""Evidence record store — deterministic ids, atomic saves, retention.

Storage layout (under the existing artifacts root):

    artifacts/evidence/<2-hex>/<ev_<32hex>>.json   # complete record, canonical JSON

``ev_`` id format: ``ev_`` + 32 lowercase hex chars (sha256 prefix over the
canonical ``{"request": sanitized_request, "record": complete_record}``
blob). Lookup validation regex ``^ev_[0-9a-f]{32}$`` — anything else is a
``missing_evidence`` error, never a filesystem path: ids are validated
BEFORE any path join, so traversal via a crafted id is impossible.

``split_detail`` / ``stamp_result`` / ``with_evidence`` implement Task 3.4:
the shared ``detail`` kwarg on heavy actions. ``detail="summary"`` retains
the complete record first, then replaces the inline payload with
``views.summary_view``; ``detail="complete"`` (default) delivers inline AND
retains so a later ``evidence_get`` works. Retention failures never break
the tool response — the original result passes through.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable, Coroutine

from .._envelope.build import sanitize_received_args

log = logging.getLogger(__name__)

EVIDENCE_ID_RE = re.compile(r"^ev_[0-9a-f]{32}$")
PREVIEW_BYTES = 512

# Heavy (tool, action) pairs that carry the `detail` parameter (Task 3.4).
# ida_manage/ghidra_manage passthroughs are handled in detail_applies —
# their action space is open-ended.
DETAIL_ACTIONS: dict[str, frozenset[str]] = {
    "mem_rw": frozenset({
        # reads / decode
        "read", "disasm", "dt", "dps", "idt", "resolve_range", "walk_list",
        "read_qwords", "read_unicode_string", "read_ansi_string",
        # scans
        "pattern_scan", "scan_result", "strings", "iocs", "entropy",
        # inventory
        "modules", "process_list", "vad", "handles", "imports", "exports",
        "heaps", "phys_ranges", "pool_scan", "threads", "obj_enum",
    }),
    "dump_manage": frozenset({"parse", "stack"}),
}

# ida/ghidra verbs that are session/discovery plumbing, never payload.
_META_ACTIONS = frozenset({
    "actions", "list", "schemas", "tools", "health", "open", "open_async",
    "open_status", "close",
})
_META_ACTION_PREFIXES = (
    "ida_job_", "ida_log", "ida_result",
    "ghidra_job_", "ghidra_log", "ghidra_result",
)


class EvidenceIdError(ValueError):
    """An evidence id failed ``^ev_[0-9a-f]{32}$`` validation."""


def valid_id(evidence_id: str) -> bool:
    """True only for well-formed ``ev_<32 lowercase hex>`` ids."""
    return bool(evidence_id) and bool(EVIDENCE_ID_RE.fullmatch(str(evidence_id)))


def record_id(complete_record: dict, request: dict) -> str:
    """Deterministic ``ev_`` + first 32 hex of sha256 over
    ``json.dumps({"request": sanitized_request,
    "record": complete_record}, sort_keys=True, separators=(",", ":"))``.
    Same request + same record -> same id, regardless of dict key order."""
    sanitized = sanitize_received_args(request)
    blob = json.dumps({"request": sanitized, "record": complete_record},
                      sort_keys=True, separators=(",", ":"), default=str)
    return "ev_" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _path_for(digest_id: str, artifacts_root: Path) -> Path:
    # Callers MUST run valid_id() before this join — enforced here too.
    if not valid_id(digest_id):
        raise EvidenceIdError(f"invalid evidence id {digest_id!r}")
    return (Path(artifacts_root) / "evidence" / digest_id[3:5]
            / f"{digest_id}.json")


def save(digest_id: str, complete_record: dict, *,
         artifacts_root: Path) -> Path:
    """Write ``artifacts/evidence/<digest[3:5]>/<digest>.json`` (canonical
    JSON, atomic: ``.tmp`` then ``os.replace``). Returns the path."""
    dest = _path_for(digest_id, artifacts_root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(complete_record, sort_keys=True, separators=(",", ":"),
                      default=str)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(blob, encoding="utf-8")
    os.replace(tmp, dest)
    return dest


def load(digest_id: str, *, artifacts_root: Path) -> dict:
    """Load a retained record. Raises ``EvidenceIdError`` for malformed ids
    (before any filesystem access) and ``FileNotFoundError`` for unknown
    but well-formed ids."""
    path = _path_for(digest_id, artifacts_root)
    if not path.exists():
        raise FileNotFoundError(f"no evidence record {digest_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def delete(digest_id: str, *, artifacts_root: Path) -> bool:
    """Remove one retained record file. False when it was already gone."""
    path = _path_for(digest_id, artifacts_root)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def delete_all(artifacts_root: Path) -> int:
    """Remove every retained record file under ``artifacts/evidence/``.
    Only filenames matching the id regex are touched. Returns the count."""
    root = Path(artifacts_root) / "evidence"
    if not root.is_dir():
        return 0
    n = 0
    for p in root.glob("*/*.json"):
        if EVIDENCE_ID_RE.fullmatch(p.stem):
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    return n


def continuation(evidence_id: str, offset: int = 0, limit: int = 64) -> dict:
    """The ``continuation`` handle pointing at knowledge_manage/evidence_get."""
    return {"tool": "knowledge_manage", "action": "evidence_get",
            "args": {"evidence_id": evidence_id, "offset": int(offset),
                     "limit": int(limit)}}


def build_record(request: dict, data: Any, *, coverage: dict | None = None,
                 provenance: dict | None = None, tool: str = "",
                 action: str = "") -> dict:
    """``{request: sanitized, data: payload}`` plus optional Part 1 blocks
    and tool/action labels — the shape ``views.*`` and the id digest read."""
    rec: dict[str, Any] = {"request": sanitize_received_args(request),
                           "data": data}
    if tool:
        rec["tool"] = tool
    if action:
        rec["action"] = action
    if isinstance(coverage, dict):
        rec["coverage"] = coverage
    if isinstance(provenance, dict):
        rec["provenance"] = provenance
    return rec


def retain_record(*, request: dict, data: Any, artifacts_root: Path,
                  ledger: Any, tool: str, action: str,
                  detail: str = "complete", coverage: dict | None = None,
                  provenance: dict | None = None, parent_id: str = "",
                  operation: str = "") -> tuple[dict, dict]:
    """Build + persist the record, write the unattached ``tool_result``
    ledger row, return ``(record, envelope evidence block)``.

    The row id IS the digest, so double retention (tool stamp + spill path)
    collapses to one row via INSERT OR IGNORE."""
    record = build_record(request, data, coverage=coverage,
                          provenance=provenance, tool=tool, action=action)
    ev = record_id(record, request)
    save(ev, record, artifacts_root=artifacts_root)
    size = len(json.dumps(record, sort_keys=True, separators=(",", ":"),
                          default=str))
    cov_json = (json.dumps(coverage, default=str)
                if isinstance(coverage, dict) else "")
    preview = json.dumps(data, default=str)[:PREVIEW_BYTES]
    if ledger is not None:
        ledger.add_evidence_record(ev, tool, action, operation, cov_json,
                                   size, detail, parent_id, preview)
    block: dict[str, Any] = {"evidence_id": ev, "detail": detail}
    if detail == "summary":
        # Fully inline small complete results omit the continuation;
        # summaries always page back, so they always carry it.
        block["continuation"] = continuation(ev)
    return record, block


def retain(*, request: dict, data: Any, artifacts_root: Path, ledger: Any,
           tool: str, action: str, detail: str = "complete",
           coverage: dict | None = None, provenance: dict | None = None,
           parent_id: str = "", operation: str = "") -> dict:
    """``retain_record`` returning just the envelope evidence block."""
    _record, block = retain_record(
        request=request, data=data, artifacts_root=artifacts_root,
        ledger=ledger, tool=tool, action=action, detail=detail,
        coverage=coverage, provenance=provenance, parent_id=parent_id,
        operation=operation)
    return block


def split_detail(detail: Any) -> tuple[str, bool]:
    """Normalize the shared ``detail`` kwarg -> ``(evidence_detail, bool)``.

    mem_rw's ``detail`` predates the evidence envelope: on ``disasm`` it
    was a bool switching capstone detail. Both meanings coexist:
    ``True`` -> legacy on + "complete"; ``False`` -> legacy off +
    "complete"; ``"summary"``/``"complete"`` -> that detail, legacy off.
    """
    if detail is True:
        return "complete", True
    if not detail:  # False / None / ""
        return "complete", False
    s = str(detail).strip().lower()
    if s == "summary":
        return "summary", False
    if s == "complete":
        return "complete", False
    return "complete", bool(detail)


def detail_applies(tool: str, action: str) -> bool:
    """Does this (tool, action) carry the ``detail`` parameter (Task 3.4)?"""
    if tool in ("ida_manage", "ghidra_manage"):
        return (action not in _META_ACTIONS
                and not action.startswith(_META_ACTION_PREFIXES))
    return action in DETAIL_ACTIONS.get(tool, frozenset())


def _to_int(v: Any) -> int:
    try:
        return int(v, 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return 0


def stamp_result(ctx: Any, tool: str, action: str, request: dict,
                 result: Any, detail: str) -> Any:
    """Post-process one heavy-tool result for the evidence envelope.

    Runs between the tool body and ``_guard``'s coercion. Accepts both
    result shapes the heavy tools produce — a JSON string (``_j`` /
    ``_j_hex``) or a ready dict (``_hexify_dict`` returns, e.g. the
    mem.py ``_list_envelope`` envelopes):
      * ``detail="complete"`` — retain the complete record, attach the
        ``evidence`` block (``envelope_from_result`` lifts it to
        ``env["evidence"]``).
      * ``detail="summary"`` — retain FIRST (never re-execute), then
        replace the inline payload with ``views.summary_view(record)``
        (counts + provenance + coverage; ``coverage`` is copied from the
        complete result so ``unknown`` is never laundered into
        ``complete``).

    Anything that isn't a successful JSON object result passes through
    unchanged; a retention failure logs and passes the ORIGINAL result
    through so a summary can never lose the payload to a store hiccup.
    """
    if detail not in ("complete", "summary"):
        return result
    ledger = getattr(ctx, "ledger", None)
    cfg = getattr(ctx, "cfg", None)
    if ledger is None or cfg is None:
        return result
    # Tool bodies return either a JSON string (_j/_j_hex) or a ready dict
    # (e.g. mem.py's `return _hexify_dict(env)`); stamp both shapes.
    encoded = isinstance(result, str)
    if encoded:
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return result
    elif isinstance(result, dict):
        parsed = result
    else:
        return result
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        return result
    if isinstance(parsed.get("evidence"), dict):
        return result  # producer already stamped — idempotent
    already_env = "kind" in parsed and "data" in parsed
    payload = (parsed.get("data") if already_env else
               {k: v for k, v in parsed.items()
                if k not in ("ok", "warnings", "evidence")})
    try:
        record, block = retain_record(
            request=request or {}, data=payload,
            artifacts_root=Path(cfg.artifacts_dir()), ledger=ledger,
            tool=tool, action=action, detail=detail,
            coverage=(parsed.get("coverage")
                      if isinstance(parsed.get("coverage"), dict) else None),
            provenance=(parsed.get("provenance")
                        if isinstance(parsed.get("provenance"), dict)
                        else None),
        )
    except Exception as exc:  # noqa: BLE001 — retention is best-effort
        log.warning("evidence retain failed (%s %s): %s", tool, action, exc)
        return result
    if detail == "summary":
        from .views import summary_view
        out = summary_view(record)
        out["ok"] = True
        out["evidence"] = block
        return json.dumps(out, default=str) if encoded else out
    parsed["evidence"] = block
    return json.dumps(parsed, default=str) if encoded else parsed


def with_evidence(ctx: Any, tool: str, action: str, request: dict,
                  fn: Callable[..., Coroutine[Any, Any, Any]],
                  detail: Any) -> Callable[..., Coroutine[Any, Any, Any]]:
    """Wrap a heavy tool's ``run`` so its result is evidence-stamped before
    ``_guard`` envelopes it. Zero-overhead pass-through when the action
    doesn't carry ``detail`` (see ``detail_applies``)."""
    ev_detail, _legacy = split_detail(detail)
    if not detail_applies(tool, action):

        async def _passthrough() -> Any:
            return await fn()

        return _passthrough

    async def _stamped() -> Any:
        return stamp_result(ctx, tool, action, request, await fn(), ev_detail)

    return _stamped
