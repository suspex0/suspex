"""Envelope constructors + finalize step.

Split out of ``_envelope.py`` (Phase 2b modular split). Holds the three
constructors (``envelope_ok`` / ``envelope_err`` / ``envelope_from_result``)
plus the single ``finalize`` pass every response funnels through before
wire.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

from .._error_enrich import enrich_error

from .opts import EnvelopeOpts, resolve_kind
from .render import (
    _apply_compact_transform,
    _collapse_flag_wrappers,
    _strip_mirror_keys,
)


# ---------------------------------------------------------------------------
# Envelope constructors
# ---------------------------------------------------------------------------

def envelope_ok(
    data: Any,
    *,
    kind: str,
    tool: str = "",
    action: str = "",
    warnings: Iterable[str] = (),
    item_count: int | None = None,
    item_total: int | None = None,
    truncated: bool | None = None,
    next_cursor: str | None = None,
    next_page: int | None = None,
    elapsed_ms: int | None = None,
    provenance: dict | None = None,
    coverage: dict | None = None,
    evidence: dict | None = None,
) -> dict:
    """Build a success envelope. `summary` is populated from any non-None
    counter kwargs; empty summary is omitted. `provenance`/`coverage` set
    the optional top-level blocks when applicable (absent, never null).
    `evidence` (Part 3) sets the retained-record block the same way."""
    env: dict[str, Any] = {"ok": True, "kind": kind}
    if tool:
        env["tool"] = tool
    if action:
        env["action"] = action
    env["data"] = data

    summary: dict[str, Any] = {}
    if elapsed_ms is not None:
        summary["elapsed_ms"] = int(elapsed_ms)
    if item_count is not None:
        summary["item_count"] = int(item_count)
    if item_total is not None:
        summary["item_total"] = int(item_total)
    if truncated is not None:
        summary["truncated"] = bool(truncated)
    if next_cursor is not None:
        summary["next_cursor"] = str(next_cursor)
    if next_page is not None:
        summary["next_page"] = int(next_page)
    if summary:
        env["summary"] = summary

    warn_list = [str(w) for w in warnings]
    if warn_list:
        env["warnings"] = warn_list
    if provenance is not None:
        env["provenance"] = provenance
    if coverage is not None:
        env["coverage"] = coverage
    if evidence is not None:
        env["evidence"] = evidence
    return env


# Keys whose values never land in an error echo (tokens, creds). The echo
# exists to diagnose arg-stripping in transit; leaking a token through it
# would be worse than the bug it reports.
_SECRET_KEY_RE = re.compile(
    r"token|secret|passw|passwd|api_?key|credential|bearer|auth", re.I)


def sanitize_received_args(args: dict | None) -> dict:
    """Post-binding kwargs as the server actually saw them, values capped —
    attached to error envelopes so 'param X missing' failures self-report
    whether the caller sent it and transport ate it, or never sent it."""
    if not args:
        return {}
    out: dict[str, Any] = {}
    for k, v in args.items():
        if _SECRET_KEY_RE.search(str(k)):
            out[k] = "<redacted>"
        elif isinstance(v, str):
            out[k] = v if len(v) <= 96 else v[:93] + "..."
        else:
            out[k] = v
    return out


def envelope_err(
    exc_or_msg: Any,
    *,
    tool: str,
    action: str,
    ctx: Any = None,
    extra: dict | None = None,
    received_args: dict | None = None,
    provenance: dict | None = None,
    coverage: dict | None = None,
    evidence: dict | None = None,
) -> dict:
    """Build a failure envelope. `exc_or_msg` may be an Exception or a raw
    string. Runs `_error_enrich.enrich_error` for the classified
    `{error, kind, hint}` triple, nested under `error:` (hard cutover — no
    flat error/kind/hint at the top level).

    `extra` is merged into `data` when the caller wants to surface partial
    results alongside the failure (e.g. `{bytes_hex: "...", first_bad_offset: N}`
    from a partial mem read).
    """
    if isinstance(exc_or_msg, BaseException):
        raw = f"{type(exc_or_msg).__name__}: {exc_or_msg}"
    else:
        raw = str(exc_or_msg)
    enriched = enrich_error(tool, action, raw)

    err_body: dict[str, Any] = {
        "error": enriched.get("error", raw),
        "kind": enriched.get("kind", "unknown"),
    }
    if enriched.get("hint"):
        err_body["hint"] = enriched["hint"]
    # v14: echo the post-binding args back — a "required param missing" error
    # now shows what arrived, so a marshaling-stripped param is obvious in
    # one round trip instead of fifteen retries.
    ra = sanitize_received_args(received_args)
    if ra:
        err_body["received_args"] = ra

    env: dict[str, Any] = {
        "ok": False,
        "kind": "error",
        "tool": tool,
        "action": action,
        "error": err_body,
    }
    if extra:
        env["data"] = dict(extra)
    # Error text can quote target output — a marked action's failure
    # keeps the provenance marker (function of (tool, action), not of
    # success/failure). Coverage is producer-declared on success shapes
    # only, but an explicit kwarg is honored for parity. Same parity for
    # the Part 3 `evidence` block (e.g. a failure after retention).
    if provenance is not None:
        env["provenance"] = provenance
    if coverage is not None:
        env["coverage"] = coverage
    if evidence is not None:
        env["evidence"] = evidence

    if ctx is not None:
        try:
            ctx.session.record_tool_call(
                tool, action, ok=False, error=err_body["error"]
            )
        except Exception:
            # Session recording is best-effort; never mask the original error.
            pass
    return env


def envelope_from_result(
    result: Any,
    *,
    tool: str,
    action: str,
    kind: str | None = None,
    elapsed_ms: int | None = None,
) -> dict:
    """Coerce a legacy `run()` return value into an envelope.

    Handles the four shapes tool bodies still emit while the codebase is
    being migrated:

      1. Already an envelope: pass through, filling tool/action if missing.
      2. Legacy flat error dict `{ok: false, error: "...", kind?, hint?}`
         (or the `_err()` result), or already-nested error:
         routed to `envelope_err`, extra keys land under `data`.
      3. Plain success dict (`{ok: true, ...}` or no `ok`): wrap under `data`.
      4. Non-dict scalar/list: wrap under `data` as-is.

    Once every tool body is migrated (later PRs) this coercion goes away and
    tool bodies build envelopes directly.
    """
    resolved_kind = resolve_kind(tool, action, kind)

    # Non-dict — wrap unconditionally.
    if not isinstance(result, dict):
        return envelope_ok(
            result, kind=resolved_kind, tool=tool, action=action,
            elapsed_ms=elapsed_ms,
        )

    # Already-envelope: has ok + kind + (data or error).
    if (
        result.get("ok") in (True, False)
        and "kind" in result
        and ("data" in result or "error" in result)
        and isinstance(result.get("error"), (dict, type(None)))
    ):
        # Nested error envelope or nested success envelope — pass through.
        result.setdefault("tool", tool)
        result.setdefault("action", action)
        return result

    # Legacy flat error dict: `{ok: false, error: "...", kind?, hint?, ...}`.
    if result.get("ok") is False:
        raw_msg = result.get("error") or "unknown error"
        # Preserve any non-standard keys (bytes_hex, hint, size, ...) under
        # data so the caller can still inspect the partial result.
        extra = {
            k: v for k, v in result.items()
            if k not in {"ok", "error", "kind", "hint", "tool", "action"}
        }
        env = envelope_err(
            raw_msg,
            tool=result.get("tool") or tool,
            action=result.get("action") or action,
            extra=extra or None,
        )
        # An explicit caller-supplied kind is a real contract — a preflight
        # (_require_driver) picks kind="no_target" precisely so the LLM can
        # branch on it, and the regex classifier's guess must not silently
        # override it. Same rule for hint — the caller's phrasing is more
        # actionable than a generic template.
        if result.get("kind"):
            env["error"]["kind"] = result["kind"]
        if result.get("hint"):
            env["error"]["hint"] = result["hint"]
        return env

    # Legacy success dict — wrap under data. Drop redundant `ok: true`
    # since the envelope carries it at the top level. Any top-level
    # `warnings` key is a documented envelope field, not payload — lift it
    # out of `data` so it surfaces at the envelope top level. Same for the
    # optional `provenance`/`coverage` blocks when a producer embedded
    # them in the legacy dict, and for the Part 3 `evidence` block.
    warn_list = result.get("warnings") or []
    payload = {
        k: v for k, v in result.items()
        if k not in ("ok", "warnings", "provenance", "coverage", "evidence")
    }
    return envelope_ok(
        payload, kind=resolved_kind, tool=tool, action=action,
        warnings=warn_list,
        elapsed_ms=elapsed_ms,
        provenance=result.get("provenance"),
        coverage=result.get("coverage"),
        evidence=(result.get("evidence")
                  if isinstance(result.get("evidence"), dict) else None),
    )


# ---------------------------------------------------------------------------
# Finalize — the one function every response runs through before wire.
# Layer 1: compute size_bytes. Layer 2 will hook `_spill.maybe_spill` in.
# Layer 4 will hook hex/decode/flag compaction in.
# ---------------------------------------------------------------------------

def finalize(env: dict, *, opts: EnvelopeOpts | None = None) -> dict:
    """Post-process an envelope. Runs in `_guard` after every tool returns.

    Layer 4 folds the compact-by-default post-processors into this step:
      * `_int` mirrors on hex fields — stripped unless verbosity="full" or
        include_int=True.
      * `_decoded` enum siblings — kept only at verbosity="full" (or with
        include_decoded=True); stripped at the default "normal" and at
        "compact" (v1.0.1).
      * `_flag` wrappers ({value, source, note?}) around booleans — collapsed
        to the value unless verbosity="full".

    v0.17 A-2 adds text-line collapse for select list actions — a row of
    ``{addr, bytes, mnemonic, op_str}`` becomes ``"0x1234  90 90 90  nop"``.
    v1.0.1: the collapse runs at the default ``verbosity="normal"`` as well as
    ``"compact"`` (it previously fired only at ``"compact"``), so the savings
    apply by default; ``"full"``/``"raw"`` keep the structured rows. Registered
    per ``(tool, action)`` in :data:`COMPACT_TRANSFORMS`.

    Runs bottom-up so a payload built with `_j_hex` / `_j_hex_decoded` at a
    tool call site still ends up compact at the wire. Auto-spill lives in
    `_spill.maybe_spill` and is chained into `_emit` in `tools.py`.
    """
    if opts is None:
        opts = EnvelopeOpts()

    if opts.verbosity == "raw":
        return env

    data = env.get("data")
    if data is not None:
        want_int = opts.include_int or opts.verbosity == "full"
        # v1.0.1 (context-efficiency): `_decoded` enum siblings double every
        # enum field on the wire. They are kept only at verbosity="full" (or
        # with include_decoded=True) now — at the default "normal" the raw
        # value stays and the decoded sibling is dropped. value_manage /
        # verbosity="full" recover the symbolic name when needed.
        want_decoded = opts.include_decoded or opts.verbosity == "full"
        want_flag = opts.verbosity == "full"

        # Order matters: strip mirrors first (they can't be affected by
        # flag collapse), then collapse wrappers, so nested `_int` inside
        # a `_flag` dict falls out cleanly.
        if not want_int:
            data = _strip_mirror_keys(data, suffix="_int")
        if not want_decoded:
            data = _strip_mirror_keys(data, suffix="_decoded")
        if not want_flag:
            data = _collapse_flag_wrappers(data)
        env["data"] = data

        # A-2: text-line collapse. Runs AFTER the mirror strips so a
        # transform sees clean dicts (no ``addr_int`` alongside ``addr``).
        # v1.0.1: applied at the default "normal" too (not just "compact") —
        # the documented 55-70% row-collapse savings on disasm/handles/vad/
        # heaps/exports/imports now fire by default. verbosity="full"/"raw"
        # still return the structured rows for programmatic callers.
        if opts.verbosity in ("compact", "normal"):
            _apply_compact_transform(env)

    try:
        size = len(json.dumps(env, default=str))
        env.setdefault("summary", {})["size_bytes"] = size
    except (TypeError, ValueError):
        # A payload we can't serialize will surface elsewhere; don't mask.
        pass
    return env
