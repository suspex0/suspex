"""caller.py — client-id registration + binding scope.

Split out of test_multi_agent.py; shared fakes live in _multi_fakes.
"""

from __future__ import annotations

import asyncio

from suspex.caller import CLIENT_ID, current_client_id, register_client_id

from _multi_fakes import _FakeRequest


def test_register_client_id_prefers_header() -> None:
    req = _FakeRequest({"Mcp-Session-Id": "peer-A"}, host="1.2.3.4")
    assert register_client_id(req) == "peer-A"


def test_register_client_id_case_insensitive_header() -> None:
    req = _FakeRequest({"mcp-session-id": "peer-B"})
    assert register_client_id(req) == "peer-B"


def test_register_client_id_synthesises_when_no_header() -> None:
    req = _FakeRequest({}, host="10.0.0.5")
    cid = register_client_id(req)
    assert cid.startswith("anon-10.0.0.5-")


def test_register_client_id_synthesises_local_when_no_request() -> None:
    cid = register_client_id(None)
    assert cid.startswith("anon-local-")


def test_current_client_id_default_is_anonymous() -> None:
    # Fresh contextvar in a fresh loop returns the sentinel.
    async def go() -> str:
        return current_client_id()
    assert asyncio.run(go()) == "anonymous"


def test_client_id_binding_scope() -> None:
    async def go() -> tuple[str, str]:
        token = CLIENT_ID.set("peer-X")
        try:
            inside = current_client_id()
        finally:
            CLIENT_ID.reset(token)
        outside = current_client_id()
        return inside, outside
    inside, outside = asyncio.run(go())
    assert inside == "peer-X"
    assert outside == "anonymous"
