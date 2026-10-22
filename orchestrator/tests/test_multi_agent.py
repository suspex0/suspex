"""Multi-agent coordination tests — Phase 5b facade.

The original file has been split into topic-focused modules:

  - _multi_fakes.py        — _FakeHeaders/_FakeClient/_FakeRequest,
                             _FakeAgentClient, _RichFakeAgentClient,
                             fake_agent_class fixture, _build_ctx_and_server,
                             _call_as
  - test_multi_clientid.py — caller.register_client_id / current_client_id
  - test_multi_registry.py — ClientRegistry register/list/reap
  - test_multi_leases.py   — LeaseManager acquire/release/wait/timeout
  - test_multi_ownership.py — OwnershipRegistry claim/annotate/release
  - test_multi_session.py  — Session refcount + owner + release_by_owner
  - test_multi_wire.py     — MCP wire: whoami / list_peers / bp ownership
  - test_multi_scan.py     — MCP wire: scan lifecycle, pool-scan guard, refcount

This module remains as a thin re-export facade so any external caller that
imports names from ``tests.test_multi_agent`` still finds them.
"""

from __future__ import annotations

from _multi_fakes import (
    _FakeAgentClient,
    _FakeClient,
    _FakeHeaders,
    _FakeRequest,
    _RichFakeAgentClient,
    _build_ctx_and_server,
    _call_as,
    fake_agent_class,
)

__all__ = [
    "_FakeAgentClient",
    "_FakeClient",
    "_FakeHeaders",
    "_FakeRequest",
    "_RichFakeAgentClient",
    "_build_ctx_and_server",
    "_call_as",
    "fake_agent_class",
]
