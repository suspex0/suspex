"""Suspex0 low-level SDK (phase 2): typed, composable primitives over the
agent gRPC sessions so agent-authored scripts/plugins automate lab tests
without touching gRPC plumbing.

Views: the session can hold a kernel view (suspex_agent + driver) and a
usermode view (umagent). Primitives take ``view=""`` (primary kernel view);
pass ``view="user"`` to route through usermode APIs only.

Helpers: pattern scan with mask, field Reader built on any read(addr, size)
callable, and PE header math (parse headers straight from memory reads).
"""

from __future__ import annotations

# Re-exported from ``suspex.symbols`` for backward compatibility.
from ..symbols import SymbolError, ensure_pdb, resolve_rvas  # noqa: F401
from .apis.codegen import CodegenApi
from .apis.dbg import DbgApi
from .apis.emu import EmuApi
from .apis.findings import FindingsApi
from .apis.mem import MemApi
from .apis.mods import ModsApi
from .apis.procs import ProcsApi
from .apis.symbols import SymbolsApi
from .apis.yara import YaraApi
from .pe import PeInfo, parse_pe, rva_to_offset
from .reader import (
    PAGE_READWRITE,
    PRIMARY_VIEW,
    ReadFn,
    Reader,
    SuspexError,
    buffer_reader,
)
from .scan import (
    _scan_range_impl,
    parse_mask,
    pattern_scan,
    scan_range_with_stats,
)
from .sdk import SuspexSDK
from .view import MemoryView

__all__ = [
    "PAGE_READWRITE",
    "PRIMARY_VIEW",
    "CodegenApi",
    "DbgApi",
    "EmuApi",
    "FindingsApi",
    "MemApi",
    "MemoryView",
    "ModsApi",
    "PeInfo",
    "ProcsApi",
    "ReadFn",
    "Reader",
    "SuspexError",
    "SuspexSDK",
    "SymbolError",
    "SymbolsApi",
    "YaraApi",
    "_scan_range_impl",
    "buffer_reader",
    "ensure_pdb",
    "parse_mask",
    "parse_pe",
    "pattern_scan",
    "resolve_rvas",
    "rva_to_offset",
    "scan_range_with_stats",
]
