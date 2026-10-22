"""Emulation-session backend for the ``emulate_manage`` MCP tool.

Two engines are wired here:

* ``speakeasy`` (default) — Mandiant's Speakeasy. Windows-focused, ships
  a fake ntdll/kernel32/user32 veneer with hookable API stubs. Best for
  shellcode + PE analysis.
* ``unicorn`` — bare Unicorn Engine. No Windows veneer, no image loader,
  no hooked APIs — just raw CPU + memory. Escape hatch when Speakeasy
  isn't available on the current Python (native-binding version churn)
  or when the caller wants pure-CPU emulation.

Both engines are lazily loaded so the orchestrator's import graph does
not break when the ``codegen`` extra isn't installed.

The public surface is :class:`EmuSession` (created via :func:`create_session`
and looked up through the module-level :data:`EMU_SESSIONS` registry) plus
a few free helpers the MCP layer calls. Every method is designed to be
called from an ``asyncio`` context — long CPU-bound bursts run via
``asyncio.to_thread`` to keep the event loop responsive.
"""

from __future__ import annotations

from .base import (
    EMU_SESSIONS,
    EVENT_RING_DEFAULT,
    SESSION_TTL_S,
    _Engine,
    _next_id,
    _shutdown_sessions,
)
from .session import (
    EmuSession,
    close_session,
    create_session,
    get_session,
    list_sessions,
    reap_idle,
    seed_from_target,
)
from .speakeasy_engine import _SpeakeasyEngine
from .unicorn_engine import _UnicornEngine

__all__ = [
    "EMU_SESSIONS",
    "EVENT_RING_DEFAULT",
    "SESSION_TTL_S",
    "EmuSession",
    "_Engine",
    "_SpeakeasyEngine",
    "_UnicornEngine",
    "_next_id",
    "_shutdown_sessions",
    "close_session",
    "create_session",
    "get_session",
    "list_sessions",
    "reap_idle",
    "seed_from_target",
]
