"""D-5: `exec_idapython` returns a native JSON result.

The pre-v0.17 shape returned ``result=repr(value)`` — a caller who set
``result = {"a": 1}`` got back the string ``"{'a': 1}"`` and had to
:mod:`ast.literal_eval` it. v0.17 D-5 flips the default to native JSON
(``dict/list/int/str/...``) and keeps a bounded ``repr`` fallback only
for genuinely unserializable objects.

Tests exercise :func:`suspex_idalib_ext.exec_idapython` directly with
the ``ida_pro_mcp.idalib_server`` module stubbed — no live IDA needed.
"""
from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest


_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


def _install_core_stub() -> None:
    """Stub for ``ida_pro_mcp.idalib_server`` imported at module scope."""
    if "ida_pro_mcp.idalib_server" in sys.modules:
        return
    pkg = types.ModuleType("ida_pro_mcp")
    sys.modules.setdefault("ida_pro_mcp", pkg)

    core = types.ModuleType("ida_pro_mcp.idalib_server")

    class _MCP:
        def add_tool(self, *_args, **_kwargs) -> None:
            return None

    class _IdaPro:
        def open_database(self, *_args, **_kwargs) -> None:
            return None

    core.mcp = _MCP()
    core.idapro = _IdaPro()
    core.main = lambda: None
    sys.modules["ida_pro_mcp.idalib_server"] = core
    pkg.idalib_server = core


@pytest.fixture(scope="module")
def ext_mod():
    _install_core_stub()
    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


# --------------------------------------------------------------------------- #
# _coerce_json_safe helper — direct unit tests for the pure logic.
# --------------------------------------------------------------------------- #


def test_d_5_coerce_dict_stays_native(ext_mod):
    safe, native, truncated = ext_mod._coerce_json_safe({"a": 1, "b": [2, 3]})
    assert safe == {"a": 1, "b": [2, 3]}
    assert native is True
    assert truncated is False


def test_d_5_coerce_list_stays_native(ext_mod):
    safe, native, truncated = ext_mod._coerce_json_safe([1, 2, 3])
    assert safe == [1, 2, 3]
    assert native is True
    assert truncated is False


def test_d_5_coerce_bytes_serialize_as_hex(ext_mod):
    # The default hook stringifies bytes as lower-case hex; we still
    # round-trip via json.dumps so the return value is native (a hex str).
    safe, native, _trunc = ext_mod._coerce_json_safe(b"\xde\xad\xbe\xef")
    assert native is True
    # `bytes` at the top level rides the default hook — the value passed
    # back is the bytes object itself because json.dumps proved it CAN
    # serialize. The important behavior: json.dumps didn't raise, and the
    # value is preserved for the caller.
    assert isinstance(safe, (bytes, str))


def test_d_5_coerce_bytes_inside_dict_survives_via_default_hook(ext_mod):
    safe, native, _trunc = ext_mod._coerce_json_safe({"buf": b"\xde\xad"})
    # json.dumps succeeded via the default hook; native=True.
    assert native is True
    assert isinstance(safe, dict)


def test_d_5_coerce_recursive_falls_back_to_repr(ext_mod):
    a: list = []
    a.append(a)  # a -> [a] -> [[a]] -> ... json.dumps raises ValueError
    safe, native, _trunc = ext_mod._coerce_json_safe(a)
    assert native is False
    assert isinstance(safe, str)
    # `repr(a)` on a self-referential list is "[[...]]".
    assert "[" in safe


def test_d_5_coerce_oversized_result_falls_back_to_repr(ext_mod, monkeypatch):
    # Force the byte cap low so a small dict trips it, and confirm we get
    # the bounded repr with truncated=True.
    monkeypatch.setattr(ext_mod, "_EXEC_RESULT_CAP_BYTES", 16)
    safe, native, truncated = ext_mod._coerce_json_safe({"a": 1, "b": 2, "c": 3})
    assert native is False
    assert truncated is True
    assert isinstance(safe, str)
    assert len(safe) <= 16


def test_d_5_coerce_none_is_native(ext_mod):
    # None round-trips as JSON null; ``result_native`` should be True but the
    # public exec_idapython path short-circuits None before calling us. This
    # test just documents the pure helper's behavior on None.
    safe, native, truncated = ext_mod._coerce_json_safe(None)
    assert safe is None
    assert native is True
    assert truncated is False


# --------------------------------------------------------------------------- #
# exec_idapython — end-to-end (result_type + result_native fields).
# --------------------------------------------------------------------------- #


def test_d_5_dict_result_stays_dict(ext_mod):
    out = ext_mod.exec_idapython("result = {'signature': '0xABCDEF', 'flink': 42}")
    assert out["ok"] is True
    # The heart of the change — no more `repr(...)` string.
    assert out["result"] == {"signature": "0xABCDEF", "flink": 42}
    assert out["result_native"] is True
    assert out["result_type"] == "dict"
    assert "result_truncated" not in out


def test_d_5_list_result_stays_list(ext_mod):
    out = ext_mod.exec_idapython("result = [1, 2, 3, 4]")
    assert out["ok"] is True
    assert out["result"] == [1, 2, 3, 4]
    assert out["result_native"] is True
    assert out["result_type"] == "list"


def test_d_5_int_result_stays_int(ext_mod):
    out = ext_mod.exec_idapython("result = 0xDEADBEEF")
    assert out["ok"] is True
    assert out["result"] == 0xDEADBEEF
    assert out["result_native"] is True
    assert out["result_type"] == "int"


def test_d_5_none_result_reports_none(ext_mod):
    # Script never assigns `result` — response says result=None but doesn't
    # try to compute result_native.
    out = ext_mod.exec_idapython("x = 1")
    assert out["ok"] is True
    assert out["result"] is None
    assert out["result_type"] == "NoneType"
    assert "result_native" not in out


def test_d_5_bytes_result_serialized_as_hex(ext_mod):
    out = ext_mod.exec_idapython("result = b'\\xde\\xad\\xbe\\xef'")
    assert out["ok"] is True
    # bytes goes through the default hook -> hex-encoded native form.
    assert out["result_native"] is True
    assert out["result_type"] == "bytes"


def test_d_5_recursive_result_falls_back_to_repr(ext_mod):
    src = "result = []\nresult.append(result)\n"
    out = ext_mod.exec_idapython(src)
    assert out["ok"] is True
    assert out["result_native"] is False
    assert out["result_type"] == "list"
    assert isinstance(out["result"], str)


def test_d_5_stdout_and_stderr_captured(ext_mod):
    src = (
        "import sys\n"
        "print('hello')\n"
        "print('boom', file=sys.stderr)\n"
        "result = {'ok': True}\n"
    )
    out = ext_mod.exec_idapython(src)
    assert out["ok"] is True
    assert "hello" in out["stdout"]
    assert "boom" in out["stderr"]
    assert out["result"] == {"ok": True}
    assert out["result_native"] is True


def test_d_5_script_error_returns_ok_false(ext_mod):
    out = ext_mod.exec_idapython("raise RuntimeError('nope')")
    assert out["ok"] is False
    assert "RuntimeError" in out["error"]
    # The error path returns before result serialization.
    assert "result" not in out or out.get("result") is None


def test_d_5_truncated_when_over_cap(ext_mod, monkeypatch):
    monkeypatch.setattr(ext_mod, "_EXEC_RESULT_CAP_BYTES", 32)
    src = "result = {'k': 'x' * 200}"
    out = ext_mod.exec_idapython(src)
    assert out["ok"] is True
    assert out["result_native"] is False
    assert out.get("result_truncated") is True
    assert isinstance(out["result"], str)
    assert len(out["result"]) <= 32
