"""C2-4: `list_functions_filter` — IDA-side name-filtered enumeration.

The vanilla ``list_functions`` requires the caller to paginate through
the whole function list and filter client-side; ``list_functions_filter``
runs the substring match inside the extension so a 15 000-function
kernel driver returns only the survivors.
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


# --- fake ida_funcs -----------------------------------------------------


class _FakeFunc:
    def __init__(self, start_ea: int):
        self.start_ea = start_ea
        self.end_ea = start_ea + 0x20


_FUNCS: list[tuple[int, str]] = []


def _install_ida_funcs_stub() -> None:
    ifn = types.ModuleType("ida_funcs")

    def get_func_qty() -> int:
        return len(_FUNCS)

    def getn_func(i: int):
        if 0 <= i < len(_FUNCS):
            return _FakeFunc(_FUNCS[i][0])
        return None

    def get_func_name(ea: int) -> str:
        for start, name in _FUNCS:
            if start == ea:
                return name
        return ""

    def get_func(ea: int):
        for start, _ in _FUNCS:
            if start <= ea < start + 0x20:
                return _FakeFunc(start)
        return None

    def add_func(ea: int) -> bool:  # noqa: ARG001 - needed for module init
        return False

    ifn.get_func_qty = get_func_qty
    ifn.getn_func = getn_func
    ifn.get_func_name = get_func_name
    ifn.get_func = get_func
    ifn.add_func = add_func
    sys.modules["ida_funcs"] = ifn


def _install_core_stub() -> None:
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
    _install_ida_funcs_stub()
    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


@pytest.fixture(autouse=True)
def _reset(ext_mod):  # noqa: ARG001 - fixture dep for import ordering
    _FUNCS.clear()
    yield
    _FUNCS.clear()


def _populate(*names: str) -> None:
    base = 0x140001000
    for i, n in enumerate(names):
        _FUNCS.append((base + i * 0x20, n))


# --- name filter --------------------------------------------------------


def test_c2_4_name_filter_substring(ext_mod):
    _populate("DriverEntry", "IoCallDriver", "IoCompleteRequest",
              "ExAllocatePool")
    out = ext_mod.list_functions_filter(name_filter="Driver")
    assert out["ok"] is True
    names = [r["name"] for r in out["functions"]]
    assert names == ["DriverEntry", "IoCallDriver"]
    assert out["total_matched"] == 2


def test_c2_4_name_filter_case_insensitive(ext_mod):
    _populate("DriverEntry", "IoCallDriver", "IoCompleteRequest")
    out = ext_mod.list_functions_filter(name_filter="iocall")
    assert out["ok"] is True
    assert [r["name"] for r in out["functions"]] == ["IoCallDriver"]


def test_c2_4_empty_filter_returns_all(ext_mod):
    _populate("A", "B", "C")
    out = ext_mod.list_functions_filter(name_filter="")
    assert out["ok"] is True
    assert [r["name"] for r in out["functions"]] == ["A", "B", "C"]
    assert out["total_matched"] == 3


# --- pagination + count -------------------------------------------------


def test_c2_4_pagination_returns_page(ext_mod):
    _populate("Sub_A", "Sub_B", "Sub_C", "Sub_D", "Sub_E")
    out = ext_mod.list_functions_filter(name_filter="Sub_",
                                        offset=2, count=2)
    assert out["ok"] is True
    assert [r["name"] for r in out["functions"]] == ["Sub_C", "Sub_D"]
    assert out["truncated"] is True
    assert out["total_matched"] == 5


def test_c2_4_count_zero_uses_default_cap(ext_mod):
    _populate(*[f"fn_{i:03d}" for i in range(400)])
    out = ext_mod.list_functions_filter(name_filter="", count=0)
    # Default cap is 200; the filter path must not overshoot.
    assert out["count"] == 200
    assert out["total_matched"] == 400
    assert out["truncated"] is True


def test_c2_4_offset_past_end_is_empty(ext_mod):
    _populate("A", "B", "C")
    out = ext_mod.list_functions_filter(name_filter="", offset=99)
    assert out["ok"] is True
    assert out["functions"] == []
    assert out["truncated"] is False


def test_c2_4_response_shape_includes_echo(ext_mod):
    """The response should carry the offset + count + name_filter it
    used — cheap round-trip echo so a caller can verify pagination
    without a follow-up call."""
    _populate("DriverEntry", "SomeOther")
    out = ext_mod.list_functions_filter(name_filter="Driver",
                                        offset=0, count=10)
    assert out["name_filter"] == "Driver"
    assert out["offset"] == 0
    assert out["count"] == 1
    assert out["functions"][0]["address"].startswith("0x")


def test_c2_4_no_matches_returns_empty(ext_mod):
    _populate("Alpha", "Beta")
    out = ext_mod.list_functions_filter(name_filter="NoSuch")
    assert out["ok"] is True
    assert out["functions"] == []
    assert out["total_matched"] == 0
    assert out["truncated"] is False
