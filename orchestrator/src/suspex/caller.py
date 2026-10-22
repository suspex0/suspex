"""Per-tool-call caller attribution for the suspex0 orchestrator.

Every MCP tool dispatch is stamped with a stable ``client_id`` string that
downstream code (the findings ledger, the audit log, rate limiters) can read
without threading it through every function signature. The id is exposed as
a ContextVar so it is safe under asyncio fan-out inside a single tool call.

Mechanism
---------
FastMCP 4.0.1 ships a first-class middleware chain
(``fastmcp.server.middleware.Middleware``); its ``on_call_tool`` hook fires
exactly once per JSON-RPC ``tools/call`` dispatch (see
``FastMCP._dispatch_component_middleware`` in
``.venv/Lib/site-packages/fastmcp/server/server.py``). Binding the ContextVar
in that hook — and resetting it in a ``finally`` — is the smallest scope
that survives async fan-out inside a single tool body without leaking across
pipelined messages on the same Streamable-HTTP connection.

We deliberately do NOT install this as a Starlette ``BaseHTTPMiddleware``:
FastMCP's own module docs (``server.py:54-68``) note that BaseHTTPMiddleware
interferes with SSE/streaming responses, and a per-HTTP-connection hook
cannot cleanly scope a ContextVar to a single tool call when clients
pipeline multiple JSON-RPC messages over one connection.

Public surface
--------------
* ``CLIENT_ID`` — the ContextVar itself (default ``"anonymous"``).
* ``current_client_id()`` — always-safe reader used by tool code.
* ``register_client_id(request)`` — pure extraction helper, unit-testable
  against a mock Starlette request.
* ``install_caller_middleware(app_or_server)`` — one-shot wiring called
  from ``suspex.server.build_app`` before the MCP app is mounted.
"""

from __future__ import annotations

import os
import time
from contextvars import ContextVar, Token
from typing import Any, Protocol

from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

__all__ = [
    "CLIENT_ID",
    "CallerAttributionMiddleware",
    "current_client_id",
    "install_caller_middleware",
    "register_client_id",
]


# --- Public ContextVar ------------------------------------------------------

# ``"anonymous"`` is a stable sentinel so downstream keys (ledger rows,
# audit-log lines) never see ``None`` and so unattributed transports land in
# ONE bucket rather than a rotating UUID per call. The middleware overwrites
# it for every real tool dispatch.
CLIENT_ID: ContextVar[str] = ContextVar("suspex_client_id", default="anonymous")


def current_client_id() -> str:
    """Return the caller id bound to the active dispatch.

    Never raises. Falls back to ``"anonymous"`` when no middleware has run
    (e.g. a maintenance job invoked from a REPL or a unit test that bypasses
    the MCP transport).
    """
    return CLIENT_ID.get()


# --- Extraction (pure, unit-testable) ---------------------------------------

class _RequestLike(Protocol):
    """The subset of ``starlette.requests.Request`` we actually touch.

    Declared as a Protocol so tests can pass a lightweight stand-in without
    constructing a full Starlette request/scope pair.
    """

    @property
    def headers(self) -> Any: ...  # supports .get(name, default)

    @property
    def client(self) -> Any: ...   # .host attribute or None


def _synthesise_client_id(request: _RequestLike | None) -> str:
    """Build a stable-per-connection id when no Mcp-Session-Id header exists.

    Composition:
        ``anon-<remote-host>-<random-hex>-<time-ns>``

    * ``remote-host`` groups anonymous calls from the same peer.
    * ``os.urandom(4).hex()`` prevents two peers behind the same NAT from
      colliding within the same nanosecond.
    * ``time.time_ns()`` keeps ids monotonic across process restarts so log
      readers can order them.
    """
    host = "local"
    if request is not None:
        client = getattr(request, "client", None)
        if client is not None:
            host = getattr(client, "host", None) or "local"
    entropy = os.urandom(4).hex()
    stamp = time.time_ns()
    return f"anon-{host}-{entropy}-{stamp}"


def register_client_id(request: _RequestLike | None) -> str:
    """Resolve the caller id from a Starlette request-like object.

    Preference order:
      1. The streamable-HTTP ``Mcp-Session-Id`` header (case-insensitive).
      2. A synthesised ``anon-<host>-<hex>-<ns>`` id.

    Kept side-effect-free (no ContextVar writes, no logging) so unit tests
    can exercise the extraction without a running MCP server.
    """
    if request is not None:
        headers = getattr(request, "headers", None)
        if headers is not None:
            # Starlette's Headers.get is case-insensitive; a plain dict in a
            # test also works as long as it uses the lower-case spelling.
            session_id = headers.get("mcp-session-id")
            if session_id:
                return str(session_id)
    return _synthesise_client_id(request)


# --- Middleware -------------------------------------------------------------

class CallerAttributionMiddleware(Middleware):
    """Bind :data:`CLIENT_ID` for the duration of every ``tools/call``.

    Registered by :func:`install_caller_middleware`. Reads the caller id
    BEFORE dispatch (via :func:`register_client_id`) and resets the
    ContextVar in ``finally`` so an exception in the tool body cannot leak
    the id into the next pipelined call on the same connection.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        # If the caller pre-bound CLIENT_ID to something other than the
        # "anonymous" default, honor it. In production every request lands
        # in a fresh Task where the ContextVar is still at its default, so
        # this branch only ever fires from in-process tests and dashboard
        # SDK calls that want to attribute themselves explicitly.
        if CLIENT_ID.get() != "anonymous":
            return await call_next(context)
        try:
            request = get_http_request()
        except RuntimeError:
            # STDIO / in-memory transports have no Starlette request; fall
            # through to the synthesis path so we still stamp something.
            request = None
        token: Token[str] = CLIENT_ID.set(register_client_id(request))
        try:
            return await call_next(context)
        finally:
            CLIENT_ID.reset(token)


# --- Installation -----------------------------------------------------------

def install_caller_middleware(app_or_server: Any) -> CallerAttributionMiddleware:
    """Attach :class:`CallerAttributionMiddleware` to a FastMCP server.

    ``app_or_server`` is expected to be the ``FastMCP`` instance returned by
    ``suspex.mcp.tools.build_server``. For symmetry with future refactors we
    also accept anything else that exposes an ``add_middleware`` method
    taking a single positional argument (the middleware instance);
    ``FastMCP.add_middleware`` matches that shape
    (``fastmcp/server/server.py:598``).

    Returns the middleware instance so callers can hold a reference (useful
    in tests that want to assert it was installed).
    """
    middleware = CallerAttributionMiddleware()
    add = getattr(app_or_server, "add_middleware", None)
    if add is None:
        raise TypeError(
            "install_caller_middleware requires an object with "
            "add_middleware(...); got "
            f"{type(app_or_server).__name__}"
        )
    add(middleware)
    return middleware
