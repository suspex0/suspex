"""Runnable entrypoint: ``python -m idalib_shim``.

Bootstraps the stdio MCP server exactly like the pre-split
``idalib_stdio_shim.py`` did — same env dump, same backend tool
inventory sample, same atexit registration for session cleanup.
"""
from __future__ import annotations

import atexit
import os

import anyio
from mcp.server.stdio import stdio_server

from . import listing as _listing
from .backend import _backend_names, _dump_startup_env
from .listing import server
from .logging import _log
from .sessions import _cleanup


atexit.register(_cleanup)


async def main() -> None:
    _log(f"shim: starting pid={os.getpid()}")
    _dump_startup_env()
    # ``BACKEND_TOOLS`` lives in listing.py; mutate the list in place so
    # every module that already holds a ``from listing import BACKEND_TOOLS``
    # (including the top-level facade) sees the update without rebinding.
    fresh = _backend_names()
    _listing.BACKEND_TOOLS.clear()
    _listing.BACKEND_TOOLS.extend(fresh)
    _log(f"shim: backend tool inventory: {len(_listing.BACKEND_TOOLS)} tools")
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
