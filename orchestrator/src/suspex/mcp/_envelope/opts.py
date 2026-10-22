"""Envelope options + kind/limit resolution helpers.

Split out of ``_envelope.py`` (Phase 2b modular split). Holds the
per-call ``EnvelopeOpts`` / ``PageOpts`` dataclasses, the ``KIND_OVERRIDES``
+ ``DEFAULT_LIMITS`` / ``LIMIT_ALIASES`` tables, and the two
``resolve_*`` helpers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# `kind` — the shape discriminator. Default is the action name (so
# `mem_rw(action="modules")` -> kind="modules"). Where multiple actions
# emit the same shape, KIND_OVERRIDES pins a canonical name so agents can
# branch on `kind` alone.
# ---------------------------------------------------------------------------

KIND_OVERRIDES: dict[tuple[str, str], str] = {
    # Byte-buffer reads share one shape across the three tools.
    ("mem_rw",         "read"):     "read",
    ("debug_manage",   "read"):     "read",
    ("emulate_manage", "mem_read"): "read",
    # Byte-buffer writes.
    ("mem_rw",         "write"):     "write",
    ("debug_manage",   "write"):     "write",
    ("emulate_manage", "mem_write"): "write",
    # Register banks.
    ("debug_manage",   "regs"):     "regs",
    ("emulate_manage", "regs"):     "regs",
    ("emulate_manage", "set_regs"): "regs",
    # Disasm listings.
    ("mem_rw",         "disasm"): "disasm",
    # Assembler roundtrips.
    ("mem_rw",         "assemble"): "assemble",
    # Backtraces.
    ("debug_manage",   "stacktrace"): "backtrace",
}


# Verbosity levels accepted by callers. "raw" skips every finalize step.
VERBOSITY_LEVELS = ("compact", "normal", "full", "raw")


# ---------------------------------------------------------------------------
# Options dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EnvelopeOpts:
    """Per-call finalize options. Threaded from the tool call site through
    `_guard` -> `finalize` -> `_spill.maybe_spill`."""
    verbosity: str = "normal"       # "compact" | "normal" | "full" | "raw"
    max_bytes: int = 0              # 0 -> use SUSPX_MCP_MAX_BYTES; -1 -> no spill
    max_items: int = 0              # 0 -> use SUSPX_MCP_MAX_ITEMS
    fields: list[str] = field(default_factory=list)
    filter: Any = ""
    include_ascii: bool = False
    include_int: bool = False
    include_decoded: bool = False


@dataclass
class PageOpts:
    """Per-list paging + projection options — accepted by every list-returning
    action once Layer 3 lands. `limit=0` means "per-action default"; the global
    cap `SUSPX_MCP_MAX_ITEMS` applies on top.

    Old per-tool cap names (`max_results`, `max_frames`, `max_matches`,
    `max_ins`, `count`, `samples`, `bytes`, `tail_bytes`) alias to `limit`
    for one release, then are removed.
    """
    limit: int = 0
    offset: int = 0
    cursor: str = ""
    fields: list[str] = field(default_factory=list)
    filter: Any = ""
    summary: bool = False
    verbosity: str = "normal"
    include_ascii: bool = False
    include_int: bool = False
    include_decoded: bool = False

    def as_envelope_opts(self) -> EnvelopeOpts:
        return EnvelopeOpts(
            verbosity=self.verbosity,
            fields=list(self.fields),
            filter=self.filter,
            include_ascii=self.include_ascii,
            include_int=self.include_int,
            include_decoded=self.include_decoded,
        )


# ---------------------------------------------------------------------------
# Kind resolution
# ---------------------------------------------------------------------------

def resolve_kind(tool: str, action: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    return KIND_OVERRIDES.get((tool, action), action)


# ---------------------------------------------------------------------------
# Paging defaults + aliases (Layer 3)
# ---------------------------------------------------------------------------

# Per-action default limits — used when the caller passes limit=0. Values
# picked from the "New default" column of the plan's paging table. Any
# action not in this table falls back to `default_limit`.
DEFAULT_LIMITS: dict[tuple[str, str], int] = {
    ("mem_rw", "modules"):       64,
    ("mem_rw", "vad"):           128,
    ("mem_rw", "handles"):       128,
    ("mem_rw", "process_list"):  64,
    ("mem_rw", "pool_scan"):     64,
    ("mem_rw", "pattern_scan"):  64,
    ("mem_rw", "disasm"):        64,
    ("debug_manage", "threads"): 32,
    ("debug_manage", "stacktrace"): 32,
    ("debug_manage", "regions"): 64,
    ("emulate_manage", "events"): 128,
    ("file_manage", "grep_artifact"): 100,
    ("knowledge_manage", "list"): 64,
    ("knowledge_manage", "search"): 64,
    ("knowledge_manage", "artifacts"): 64,
    ("findings_manage", "list"): 64,  # deprecated alias kept for one release
    ("script_manage", "history"): 64,
    ("reg_manage", "enum"):      128,
}


# Old per-tool cap kwarg names that alias to `limit` on their tool+action.
# Layer 3 hard-cutover on the response shape; request kwargs keep the old
# names alive for one release so existing callers keep working.
LIMIT_ALIASES: dict[str, str] = {
    "max_results": "limit",
    "max_matches": "limit",
    "max_frames":  "limit",
    "max_ins":     "limit",
    "count":       "limit",
    "samples":     "limit",
    "tail_bytes":  "limit",
}


def resolve_limit(tool: str, action: str, requested: int,
                  *, default_limit: int = 64, global_cap: int = 0) -> int:
    """Compute the effective row cap for a list-returning action:
       0 (caller unset) -> DEFAULT_LIMITS[tool, action] or default_limit
       > 0             -> respect requested, still bounded by global_cap.
    """
    if requested and requested > 0:
        eff = int(requested)
    else:
        eff = DEFAULT_LIMITS.get((tool, action), default_limit)
    if global_cap > 0:
        eff = min(eff, global_cap)
    return max(1, eff)
