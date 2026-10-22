"""suspex0 MCP guided prompts (Part 4).

Eight workflow prompts that wrap the existing tool surface — pure DX, no
new tools and no behavior changes. ``register(mcp, ctx)`` is called at the
end of :func:`suspex.mcp.tools.build_server`.
"""

from __future__ import annotations

import logging

from . import completions as _completions
from .investigations import (
    attack_surface_enum,
    bounded_dump_capture,
    crash_triage,
    debug_session,
    driver_decompile_triage,
    investigate_finding,
    kernel_recon,
    plugin_automation,
)

_log = logging.getLogger(__name__)

PROMPT_FUNCS = (
    kernel_recon,
    crash_triage,
    attack_surface_enum,
    investigate_finding,
    bounded_dump_capture,
    driver_decompile_triage,
    debug_session,
    plugin_automation,
)


def register(mcp, ctx) -> None:
    """Register the guided prompts + the argument-completion handler."""
    for fn in PROMPT_FUNCS:
        mcp.prompt(fn)
    registered = _completions.register_completion(
        mcp, _completions.make_completion_handler(ctx))
    if not registered:
        # fastmcp 3.x has no server-side completion API (the
        # completion/complete handler lands in 4.x). Prompts still
        # register; the completions capability is simply not advertised.
        _log.info("fastmcp lacks a server completion API; "
                  "completion/complete not registered")


__all__ = ["register", "PROMPT_FUNCS"]
