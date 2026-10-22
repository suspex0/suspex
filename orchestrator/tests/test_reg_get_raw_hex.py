"""v0.17 A-3: ``reg_manage get`` ``raw_hex=True`` opt-in.

Default response shape is now driven by the REG_ type — one canonical
``value`` field per type — instead of always emitting the full four-way
render (``hex`` + ``str`` + ``qword`` + ``multi_sz``). Callers that
want every rendering back (forensic dumps, legacy scripts) pass
``raw_hex=True``.

Coverage:

  * REG_SZ / REG_EXPAND_SZ  → ``value: <str>``
  * REG_DWORD / REG_QWORD   → ``value: <int>``
  * REG_MULTI_SZ            → ``value: [<str>...]``
  * REG_BINARY (and other)  → ``hex: "..."``
  * ``raw_hex=True``        → historical wide shape restored
"""

from __future__ import annotations

import asyncio

import pytest

from suspex.agent_client import AgentClient


class _RegGetResp:
    """Duck-type of the RegGetResponse protobuf message."""

    def __init__(self, *, ok: bool = True, error: str = "",
                 rtype: int = 0, data: bytes = b"",
                 data_str: str = "", data_qword: int = 0,
                 data_multi_sz: list[str] | None = None):
        self.status = type("_S", (), {"ok": ok, "error": error})()
        self.type = rtype
        self.data = data
        self.data_str = data_str
        self.data_qword = data_qword
        self.data_multi_sz = data_multi_sz or []


class _FakeRegistry:
    """Minimal ``registry`` stub with a ``Get`` coroutine target."""

    def __init__(self, response: _RegGetResp):
        self._resp = response

    async def Get(self, req):  # noqa: N802 - mirrors gRPC stub casing
        return self._resp


def _client_with(resp: _RegGetResp) -> AgentClient:
    """Build an ``AgentClient`` skeleton that only wires the registry
    surface — enough for ``reg_get`` to run without a live agent."""
    c = AgentClient.__new__(AgentClient)
    c.registry = _FakeRegistry(resp)

    async def _call(stub, req):
        return await stub(req)

    c._call = _call  # type: ignore[attr-defined]
    return c


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Shape-driven defaults
# ---------------------------------------------------------------------------

def test_reg_get_sz_default_returns_str_value():
    resp = _RegGetResp(rtype=1, data=b"hello world\0",
                       data_str="hello world")
    r = _run(_client_with(resp).reg_get("HKLM", "Software\\Foo", "Val"))
    assert r == {"type": 1, "size": 12, "value": "hello world"}
    # Redundant renderings are stripped by default.
    assert "hex" not in r
    assert "qword" not in r
    assert "multi_sz" not in r


def test_reg_get_expand_sz_default_returns_str_value():
    resp = _RegGetResp(rtype=2, data=b"%SystemRoot%",
                       data_str="%SystemRoot%")
    r = _run(_client_with(resp).reg_get("HKLM", "Env", "Path"))
    assert r["type"] == 2
    assert r["value"] == "%SystemRoot%"


def test_reg_get_dword_default_returns_int_value():
    resp = _RegGetResp(rtype=4, data=b"\x2a\x00\x00\x00",
                       data_qword=42)
    r = _run(_client_with(resp).reg_get("HKLM", "Sys\\Foo", "Start"))
    assert r == {"type": 4, "size": 4, "value": 42}


def test_reg_get_qword_default_returns_int_value():
    resp = _RegGetResp(rtype=11, data=b"\x00" * 8,
                       data_qword=0x1122334455667788)
    r = _run(_client_with(resp).reg_get("HKLM", "Sys\\Foo", "BigVal"))
    assert r == {"type": 11, "size": 8, "value": 0x1122334455667788}


def test_reg_get_dword_be_default_returns_int_value():
    resp = _RegGetResp(rtype=5, data=b"\x00\x00\x00\x2a",
                       data_qword=42)
    r = _run(_client_with(resp).reg_get("HKLM", "Sys\\Foo", "BE"))
    assert r == {"type": 5, "size": 4, "value": 42}


def test_reg_get_multi_sz_default_returns_list_value():
    resp = _RegGetResp(rtype=7, data=b"a\0b\0\0",
                       data_multi_sz=["alpha", "beta"])
    r = _run(_client_with(resp).reg_get("HKLM", "Deps", "List"))
    assert r["type"] == 7
    assert r["value"] == ["alpha", "beta"]


def test_reg_get_binary_default_returns_hex():
    resp = _RegGetResp(rtype=3, data=bytes.fromhex("deadbeef"))
    r = _run(_client_with(resp).reg_get("HKLM", "Bin", "V"))
    assert r == {"type": 3, "size": 4, "hex": "deadbeef"}
    # No decoded fields for REG_BINARY.
    assert "value" not in r
    assert "str" not in r
    assert "qword" not in r


def test_reg_get_unknown_type_falls_back_to_hex():
    """REG_NONE (0), REG_LINK (6), or any future / unknown type: hex is
    the only lossless rendering."""
    resp = _RegGetResp(rtype=0, data=b"\xaa\xbb")
    r = _run(_client_with(resp).reg_get("HKLM", "None", "V"))
    assert r == {"type": 0, "size": 2, "hex": "aabb"}


# ---------------------------------------------------------------------------
# raw_hex=True — historical wide shape
# ---------------------------------------------------------------------------

def test_reg_get_raw_hex_true_returns_full_shape():
    resp = _RegGetResp(
        rtype=1, data=b"foo\0", data_str="foo",
        data_qword=0, data_multi_sz=[],
    )
    r = _run(_client_with(resp).reg_get(
        "HKLM", "K", "V", raw_hex=True,
    ))
    assert r == {
        "type": 1, "size": 4,
        "hex": "666f6f00",
        "str": "foo",
        "qword": 0,
        "multi_sz": [],
    }


def test_reg_get_raw_hex_true_for_dword():
    resp = _RegGetResp(
        rtype=4, data=b"\x01\x00\x00\x00", data_qword=1, data_str="",
    )
    r = _run(_client_with(resp).reg_get("HKLM", "K", "V", raw_hex=True))
    # Wide shape emits all four rendering fields even for REG_DWORD.
    assert r["type"] == 4
    assert r["hex"] == "01000000"
    assert r["qword"] == 1
    assert r["str"] == ""
    assert r["multi_sz"] == []


def test_reg_get_raw_hex_false_keyword_equivalent_to_default():
    """Explicit ``raw_hex=False`` matches the default."""
    resp = _RegGetResp(rtype=1, data=b"x\0", data_str="x")
    a = _run(_client_with(resp).reg_get("HKLM", "K", "V"))
    b = _run(_client_with(_RegGetResp(rtype=1, data=b"x\0", data_str="x"))
             .reg_get("HKLM", "K", "V", raw_hex=False))
    assert a == b


# ---------------------------------------------------------------------------
# Failure surface
# ---------------------------------------------------------------------------

def test_reg_get_bubbles_agent_error():
    resp = _RegGetResp(ok=False, error="access denied")
    with pytest.raises(RuntimeError, match="access denied"):
        _run(_client_with(resp).reg_get("HKLM", "K", "V"))


def test_reg_get_bubbles_agent_error_under_raw_hex():
    resp = _RegGetResp(ok=False, error="value not found gle=2")
    with pytest.raises(RuntimeError, match="value not found"):
        _run(_client_with(resp).reg_get("HKLM", "K", "V", raw_hex=True))


def test_reg_get_without_registry_raises():
    c = AgentClient.__new__(AgentClient)
    c.registry = None
    with pytest.raises(RuntimeError, match="registry service unavailable"):
        _run(c.reg_get("HKLM", "K", "V"))
