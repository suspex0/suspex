"""Warning + ops-aggregation helpers, plus the FastMCP ``to_tool_result``
wrapper.

Split out of ``_envelope.py`` (Phase 2b modular split). Holds:

* :func:`warn` / :func:`warn_if` — shared idiom for building the
  envelope-level ``warnings: [str]`` list without duplicates.
* :func:`summarize_ops` — per-``method`` aggregate for the
  ``target_manage recent_ops`` ring.
* :func:`to_tool_result` — A-1 single-encode wrapper that hands FastMCP
  a :class:`ToolResult` with ``structured_content=env`` so the envelope
  ships on the wire once, not twice.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any


_log = logging.getLogger(__name__)


# FastMCP result types — imported lazily so a partial install (e.g. unit
# tests that only import ``_envelope`` without pulling FastMCP) still works.
# When FastMCP is unavailable :func:`to_tool_result` degrades to a JSON
# string, matching the pre-A-1 wire shape.
try:  # pragma: no cover - trivial import shim
    from fastmcp.tools.base import ToolResult as _ToolResult
    from mcp.types import TextContent as _TextContent
    _HAS_FASTMCP = True
except Exception:  # noqa: BLE001 - fastmcp is a soft dep in unit-test envs
    _ToolResult = None  # type: ignore[assignment, misc]
    _TextContent = None  # type: ignore[assignment, misc]
    _HAS_FASTMCP = False


# A-1: env flag preserved for one release so any MCP client that still
# reads ``content[0].text`` instead of ``structuredContent`` keeps working
# while we migrate. Remove in v0.18.
_LEGACY_DUAL_ENV = "SUSPX_MCP_LEGACY_DUAL_CONTENT"


def _legacy_dual_active() -> bool:
    return os.environ.get(_LEGACY_DUAL_ENV, "").strip() == "1"


# ---------------------------------------------------------------------------
# Warning helper (A-5 · v0.17) — shared idiom for every worker so callers
# publishing a `warnings: [str]` field don't rebuild the list by hand.
# ---------------------------------------------------------------------------

def warn(env: dict, msg: str) -> dict:
    """Append ``msg`` to ``env['warnings']`` (created if absent).

    Idempotent — the same message text appears only once per envelope so a
    caller that emits the same warning from two branches doesn't produce
    duplicate rows. Empty / falsey messages are dropped. Returns ``env`` for
    chaining, so callers can do ``return warn(env, "...")`` at a return site.
    """
    if not msg:
        return env
    wl = env.setdefault("warnings", [])
    text = str(msg)
    if text not in wl:
        wl.append(text)
    return env


def warn_if(env: dict, cond: Any, msg: str) -> dict:
    """Convenience: :func:`warn` only when ``cond`` is truthy. Returns ``env``.

    Threading truthy checks through :func:`warn_if` keeps the tool-site
    branching flat — e.g. ``warn_if(env, foreign, "bare arm on foreign id")``.
    """
    if cond:
        warn(env, msg)
    return env


# ---------------------------------------------------------------------------
# A-4 · ``recent_ops`` summary aggregator
# ---------------------------------------------------------------------------
#
# ``target_manage recent_ops`` returns the full ``AgentClient._recent_ops``
# ring — 128 rows of ``{method, elapsed_ms, ok, ts, ...}`` — which the
# caller often just wants aggregated by method so they can see
# "AttachProcess: 32 calls, 3 failures, avg 12ms" at a glance.
#
# ``PageOpts.summary=True`` already short-circuits list-returning actions
# to return zero items, but that's not what a caller of ``recent_ops``
# wants either. This helper produces the per-method aggregate; Agent E
# wires it at the action site inside ``target_manage`` (see plan §A-4).

def summarize_ops(rows: list[dict]) -> list[dict]:
    """Aggregate a ``recent_ops`` ring by ``method``.

    Returns a list of ``{method, count, ok_count, err_count, min_ms,
    max_ms, avg_ms, last_ts}`` records, sorted by ``count`` descending
    (busiest method first). Empty input returns an empty list.
    """
    from collections import defaultdict

    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        buckets[str(r.get("method", "?"))].append(r)

    out: list[dict] = []
    for method, xs in buckets.items():
        ok_count = sum(1 for x in xs if x.get("ok"))
        err_count = len(xs) - ok_count
        latencies = [int(x.get("elapsed_ms", 0) or 0) for x in xs]
        timestamps = [x.get("ts", 0) or 0 for x in xs]
        out.append({
            "method": method,
            "count": len(xs),
            "ok_count": ok_count,
            "err_count": err_count,
            "min_ms": min(latencies) if latencies else 0,
            "max_ms": max(latencies) if latencies else 0,
            "avg_ms": round(sum(latencies) / len(latencies), 1)
                      if latencies else 0.0,
            "last_ts": max(timestamps) if timestamps else 0,
        })

    out.sort(key=lambda r: r["count"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# A-1 · Single-encode MCP tool responses
# ---------------------------------------------------------------------------
#
# Before v0.17 every tool body returned ``json.dumps(env, ...)`` — a JSON
# string. FastMCP then wrapped that string as both ``content[0].text`` and
# ``structuredContent.result`` (the tool has an output_schema, so FastMCP's
# ``convert_result`` populates both slots). Result: the envelope shipped
# on the wire twice, doubling per-call token cost on responses > 1 KB.
#
# :func:`to_tool_result` turns an envelope dict into a FastMCP
# :class:`ToolResult` with ``content=[]`` and ``structured_content=env`` —
# FastMCP's ``convert_result`` detects the ``ToolResult`` and passes it
# through unchanged (see fastmcp/tools/base.py). Result: one copy of the
# envelope reaches the client, under ``structuredContent``.
#
# The wrapper is what ``tools.py:_j`` calls when its input looks like an
# envelope (has a top-level ``"ok"`` key). ``_j`` still returns a plain
# JSON string for the non-envelope call-sites (ledger evidence writes that
# store the parity report / yara matches) so the ownership box stays at
# a single seam. Non-FastMCP callers (unit tests, dashboards) receive a
# JSON string when FastMCP is not importable — same shape as pre-A-1.
#
# ``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` restores the dual-emit shape for one
# release; retire in v0.18.

def to_tool_result(env: Any, *, legacy_dual: bool | None = None) -> Any:
    """Convert an envelope dict into a FastMCP :class:`ToolResult`.

    The MCP client sees ``structuredContent = env`` and an empty
    ``content`` array. ``isError`` mirrors ``env['ok'] is False`` so the
    SDK's own retry logic behaves.

    When FastMCP is not installed (unit-test envs where the shim is
    unavailable), falls back to :func:`json.dumps` — preserving the
    pre-A-1 wire shape so downstream tests that expect a string keep
    passing.

    ``legacy_dual=True`` (or ``SUSPX_MCP_LEGACY_DUAL_CONTENT=1`` in the
    process env) emits both a text-content copy of the envelope AND
    ``structured_content``, matching the pre-A-1 dual-emit shape for MCP
    clients that don't yet read ``structuredContent``.
    """
    if legacy_dual is None:
        legacy_dual = _legacy_dual_active()

    if not _HAS_FASTMCP or _ToolResult is None or _TextContent is None:
        # Unit tests without fastmcp — degrade to the pre-A-1 string.
        return json.dumps(env, indent=2, default=str)

    if not isinstance(env, dict):
        # Defensive: callers should only pass envelope dicts. Anything
        # else round-trips through JSON so FastMCP still gets a value it
        # can wrap.
        return json.dumps(env, indent=2, default=str)

    is_error = env.get("ok") is False

    if legacy_dual:
        text = json.dumps(env, indent=2, default=str)
        try:
            return _ToolResult(
                content=[_TextContent(type="text", text=text)],
                structured_content=env,
                is_error=is_error,
            )
        except Exception:  # noqa: BLE001 - ToolResult refused our shape; log + fall back
            _log.warning(
                "to_tool_result: legacy dual-content build failed; "
                "falling back to JSON string",
                exc_info=True,
            )
            return text

    try:
        return _ToolResult(
            content=[],
            structured_content=env,
            is_error=is_error,
        )
    except Exception:  # noqa: BLE001 - ToolResult refused our shape; log + fall back
        _log.warning(
            "to_tool_result: single-encode build failed; "
            "falling back to JSON string",
            exc_info=True,
        )
        return json.dumps(env, indent=2, default=str)
