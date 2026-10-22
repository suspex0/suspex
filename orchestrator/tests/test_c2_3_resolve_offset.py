"""C2-3a: `resolve_offset(struct, offset)` reverse lookup.

The extension module `orchestrator/suspex_idalib_ext.py` imports
`ida_pro_mcp.idalib_server` at module scope, which is only present in
the IDA-embedded venv. Tests stub the IDA modules in ``sys.modules``
before importing so pytest can exercise the resolver logic without a
live IDA install.
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


class _FakeType:
    """Just enough of ``ida_typeinf.tinfo_t`` for the resolver.

    Backed by a plain-Python spec dict:
      {"size": int, "kind": "udt"|"enum"|"primitive",
       "type_repr": str,
       "members": [{"name": str, "offset": int, "size": int,
                    "type_repr": str, "inner": _FakeType|None}]}
    """

    def __init__(self, spec: dict | None = None):
        self._spec = spec
        self._resolved_name: str | None = None

    def get_named_type(self, til, name: str) -> bool:  # noqa: ARG002
        spec = _NAMED_TYPES.get(name)
        if spec is None:
            return False
        self._spec = spec
        self._resolved_name = name
        return True

    def is_udt(self) -> bool:
        return bool(self._spec and self._spec.get("kind", "udt") == "udt")

    def is_enum(self) -> bool:
        return bool(self._spec and self._spec.get("kind") == "enum")

    def get_size(self) -> int:
        return int(self._spec.get("size", 0)) if self._spec else 0

    def _print(self) -> str:
        return self._spec.get("type_repr", "<fake>") if self._spec else "<fake>"

    def get_udt_details(self, udt) -> bool:
        if not self._spec or not self.is_udt():
            return False
        udt.load(self._spec.get("members", []))
        return True


class _FakeMember:
    def __init__(self, name: str, offset: int, size: int,
                 type_repr: str, inner: _FakeType | None):
        self.name = name
        # begin() returns bit offset; size is a bit size in the real API.
        self._begin = offset * 8
        self.size = size * 8
        self.type = inner if inner is not None else _FakeType(
            {"kind": "primitive", "size": size, "type_repr": type_repr}
        )
        self.cmt = ""
        self._type_repr = type_repr

    def begin(self) -> int:
        return self._begin


class _FakeUDT(list):
    """Stand-in for ``ida_typeinf.udt_type_data_t`` — populates via load()."""

    def load(self, members_spec: list[dict]) -> None:
        self.clear()
        for m in members_spec:
            self.append(_FakeMember(
                name=m["name"], offset=m["offset"], size=m["size"],
                type_repr=m.get("type_repr", m["name"]),
                inner=_FakeType(m["inner"]) if m.get("inner") else None,
            ))


_NAMED_TYPES: dict[str, dict] = {}


def _install_ida_typeinf_stub() -> types.ModuleType:
    mod = types.ModuleType("ida_typeinf")
    mod.tinfo_t = _FakeType
    mod.udt_type_data_t = _FakeUDT
    sys.modules["ida_typeinf"] = mod
    return mod


def _install_core_stub() -> types.ModuleType:
    """Stub for ``ida_pro_mcp.idalib_server`` imported at module scope."""
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
    return core


@pytest.fixture(scope="module")
def ext_mod():
    _install_core_stub()
    _install_ida_typeinf_stub()
    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


@pytest.fixture(autouse=True)
def _reset_named_types(ext_mod):  # noqa: ARG001 - fixture dep for order
    """Every test starts with a clean type registry."""
    _NAMED_TYPES.clear()
    yield
    _NAMED_TYPES.clear()


def _register_flat(name: str, size: int, members: list[dict]) -> None:
    _NAMED_TYPES[name] = {
        "kind": "udt", "size": size, "type_repr": name, "members": members,
    }


def test_c2_3_resolve_offset_hits_primitive_member(ext_mod):
    _register_flat("_KTHREAD", 0x100, [
        {"name": "Header", "offset": 0x00, "size": 0x18,
         "type_repr": "_DISPATCHER_HEADER"},
        {"name": "SListFaultAddress", "offset": 0x18, "size": 0x08,
         "type_repr": "void *"},
        {"name": "QuantumTarget", "offset": 0x20, "size": 0x08,
         "type_repr": "unsigned __int64"},
    ])
    out = ext_mod.resolve_offset("_KTHREAD", "0x20")
    assert out["ok"] is True
    assert out["member_name"] == "QuantumTarget"
    assert out["path"] == "_KTHREAD.QuantumTarget"
    assert out["exact"] is True
    assert out["remaining_offset_int"] == 0
    assert out["requested_offset_int"] == 0x20


def test_c2_3_resolve_offset_mid_member_returns_remainder(ext_mod):
    _register_flat("_KTHREAD", 0x100, [
        {"name": "Padding", "offset": 0x00, "size": 0x10,
         "type_repr": "char[16]"},
        {"name": "Buffer",  "offset": 0x10, "size": 0x40,
         "type_repr": "char[64]"},
    ])
    out = ext_mod.resolve_offset("_KTHREAD", "0x18")
    assert out["ok"] is True
    assert out["member_name"] == "Buffer"
    assert out["remaining_offset_int"] == 0x08
    assert out["exact"] is False


def test_c2_3_resolve_offset_recurses_into_nested_udt(ext_mod):
    _NAMED_TYPES["_KTHREAD"] = {
        "kind": "udt", "size": 0x400, "type_repr": "_KTHREAD",
        "members": [
            {"name": "Pcb", "offset": 0x0, "size": 0x200,
             "type_repr": "_KPROCESS",
             "inner": {"kind": "udt", "size": 0x200, "type_repr": "_KPROCESS",
                       "members": [
                           {"name": "Header", "offset": 0x0, "size": 0x18},
                           {"name": "ProfileListHead", "offset": 0x18,
                            "size": 0x10},
                           {"name": "DirectoryTableBase", "offset": 0x28,
                            "size": 0x8, "type_repr": "unsigned __int64"},
                       ]}},
            {"name": "TrailingPad", "offset": 0x200, "size": 0x200,
             "type_repr": "char[512]"},
        ],
    }
    out = ext_mod.resolve_offset("_KTHREAD", "0x28")
    assert out["ok"] is True
    assert out["path"] == "_KTHREAD.Pcb.DirectoryTableBase"
    assert out["member_offset_int"] == 0x28
    assert out["remaining_offset_int"] == 0
    assert out["exact"] is True


def test_c2_3_resolve_offset_past_end_typed_error(ext_mod):
    _register_flat("_TINY", 0x10, [
        {"name": "a", "offset": 0x0, "size": 0x8, "type_repr": "u64"},
        {"name": "b", "offset": 0x8, "size": 0x8, "type_repr": "u64"},
    ])
    out = ext_mod.resolve_offset("_TINY", "0x40")
    assert out["ok"] is False
    assert out["kind"] == "offset_out_of_range"
    assert out["struct_name"] == "_TINY"
    assert out["struct_size"] == 0x10


def test_c2_3_resolve_offset_unknown_struct_typed_error(ext_mod):
    out = ext_mod.resolve_offset("_NEVER_HEARD_OF_YOU", "0x10")
    assert out["ok"] is False
    assert out["kind"] == "struct_not_found"
    assert "hint" in out


def test_c2_3_resolve_offset_bad_offset_string(ext_mod):
    _register_flat("_KTHREAD", 0x100, [
        {"name": "a", "offset": 0x0, "size": 0x8, "type_repr": "u64"},
    ])
    out = ext_mod.resolve_offset("_KTHREAD", "not-a-number")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_3_resolve_offset_decimal_offset(ext_mod):
    _register_flat("_KTHREAD", 0x100, [
        {"name": "a", "offset": 0x0, "size": 0x8, "type_repr": "u64"},
        {"name": "b", "offset": 0x8, "size": 0x8, "type_repr": "u64"},
    ])
    # Decimal 8 must resolve to member `b`.
    out = ext_mod.resolve_offset("_KTHREAD", "8")
    assert out["ok"] is True
    assert out["member_name"] == "b"
