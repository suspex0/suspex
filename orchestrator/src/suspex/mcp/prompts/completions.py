"""Server-side argument completion for the suspex0 MCP server.

One handler answers every ``completion/complete`` request. It suggests
values from live session/ledger state only — it never executes a tool
call, never touches the network, and never raises into the transport
(any internal error is swallowed to "no candidates").

Version note: fastmcp 4.x exposes ``FastMCP.add_completion_handler`` /
``@mcp.completion``; fastmcp 3.x has neither, so
:func:`register_completion` reports False and the capability is simply
not advertised. The handler itself is written against duck-typed
``ref`` / ``argument`` objects and the ``mcp`` Completion model, so it
works under both.
"""

from __future__ import annotations

import logging

_log = logging.getLogger(__name__)

try:  # fastmcp 4.x ships the MCP types as a standalone module
    from mcp_types import Completion
except ImportError:  # fastmcp 3.x / mcp SDK
    from mcp.types import Completion

MAX_COMPLETION_VALUES = 100

# Prompt names this handler recognizes (registered in investigations.py).
PROMPT_NAMES = frozenset({
    "kernel_recon",
    "crash_triage",
    "attack_surface_enum",
    "investigate_finding",
    "bounded_dump_capture",
    "driver_decompile_triage",
    "debug_session",
    "plugin_automation",
})

VIEW_KINDS = ("kernel", "user")


# --------------------------------------------------------------- sources ----

def _machine_names(ctx) -> list[str]:
    """Connected machine labels + configured ``machines:`` /
    ``targets:`` names (both resolve as labels via
    ``Config.target_for``)."""
    out: list[str] = []
    try:
        out.extend(ctx.session.machines().keys())
    except Exception:  # noqa: BLE001 — completion is best-effort
        pass
    for attr in ("machines", "targets"):
        try:
            out.extend((getattr(ctx.cfg, attr, {}) or {}).keys())
        except Exception:  # noqa: BLE001
            pass
    return out


def _view_names(ctx) -> list[str]:
    """'<machine>.<kind>' view keys for every known machine."""
    return [f"{m}.{k}" for m in _machine_names(ctx) for k in VIEW_KINDS]


def _retained(ctx, kind: str) -> list[str]:
    """Names from the last retained inventory of *kind*, if any tool
    keeps one. No current tool does — the hook accepts a dict keyed by
    kind on the Context or Session so a future inventory cache can feed
    it without changing this handler. An EMPTY result means "nothing
    retained", NOT that the module/symbol/device does not exist."""
    for holder in (ctx, getattr(ctx, "session", None)):
        store = getattr(holder, "_retained_inventories", None)
        if isinstance(store, dict):
            return [str(r) for r in (store.get(kind) or [])]
    return []


def _finding_ids(ctx) -> list[str]:
    """Ledger finding ids, most recent first."""
    try:
        rows = ctx.ledger.list_findings(None, None)
    except Exception:  # noqa: BLE001 — a broken ledger must not break completion
        return []
    return [str(f.id) for f in reversed(rows)]


def _evidence_ids(ctx) -> list[str]:
    """Evidence row ids. Prefers a bulk ``list_evidence`` surface (Part 3's
    evidence_list data) when the ledger grows one; otherwise walks recent
    findings' evidence rows. Ids are filtered to the ``ev_`` prefix only
    when the ledger actually uses it — legacy evidence ids are bare hex."""
    led = ctx.ledger
    try:
        bulk = getattr(led, "list_evidence", None)
        if callable(bulk):
            rows = list(bulk())
        else:
            rows = []
            for f in led.list_findings(None, None)[-200:]:
                rows.extend(led.evidence_for(f.id))
    except Exception:  # noqa: BLE001
        return []
    ids = [str(getattr(r, "id", r)) for r in rows]
    prefixed = [i for i in ids if i.startswith("ev_")]
    return prefixed if prefixed else ids


_SOURCES = {
    "machine": _machine_names,
    "view": _view_names,
    "module": lambda ctx: _retained(ctx, "module"),
    "symbol": lambda ctx: _retained(ctx, "symbol"),
    "device": lambda ctx: _retained(ctx, "device"),
    "finding_id": _finding_ids,
    "evidence_id": _evidence_ids,
}


# -------------------------------------------------------------- shaping ----

def finalize(candidates, prefix: str = "",
             cap: int = MAX_COMPLETION_VALUES):
    """Case-insensitive prefix filter + dedupe + code-point sort + cap.

    Dedupe is case-insensitive (first-seen spelling wins — a machine
    configured as "LAB2" and connected as "lab2" must not suggest both).
    Returns a plain ``list[str]`` when everything fits, or a
    ``Completion(values[:cap], total=<all matches>, has_more=True)``
    when the match list had to be truncated.
    """
    p = (prefix or "").lower()
    seen: dict[str, str] = {}
    for c in candidates:
        s = str(c)
        key = s.lower()
        if key not in seen and key.startswith(p):
            seen[key] = s
    vals = sorted(seen.values())
    if len(vals) > cap:
        return _completion(vals[:cap], total=len(vals), has_more=True)
    return vals


def _completion(values: list[str], *, total: int, has_more: bool) -> Completion:
    # Field name moved between MCP SDK generations ("hasMore" vs
    # "has_more"); build whatever this install's model accepts.
    fields = getattr(Completion, "model_fields", {}) or {}
    kw: dict = {"values": values, "total": total}
    if "has_more" in fields:
        kw["has_more"] = has_more
    else:
        kw["hasMore"] = has_more
    return Completion(**kw)


# ------------------------------------------------------------- handler ----

def make_completion_handler(ctx):
    """Build the ``completion/complete`` handler closed over *ctx*."""

    def complete(ref, argument, context=None):  # context is unused
        try:
            return _complete(ctx, ref, argument)
        except Exception:  # noqa: BLE001 — never raise into the transport
            _log.debug("completion failed", exc_info=True)
            return None

    return complete


def _complete(ctx, ref, argument):
    ref_name = getattr(ref, "name", "") or ""
    if ref_name not in PROMPT_NAMES:
        return None
    source = _SOURCES.get(getattr(argument, "name", "") or "")
    if source is None:
        return None
    return finalize(source(ctx), getattr(argument, "value", "") or "")


def register_completion(mcp, handler) -> bool:
    """Wire *handler* as the server's completion handler.

    Returns True when the installed fastmcp supports server-side
    completions (4.x ``add_completion_handler`` / ``completion``), False
    when it does not (3.x) — callers treat False as "capability not
    advertised", never as an error.
    """
    adder = getattr(mcp, "add_completion_handler", None)
    if callable(adder):
        adder(handler)
        return True
    deco = getattr(mcp, "completion", None)
    if callable(deco):
        deco(handler)
        return True
    return False
