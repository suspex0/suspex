"""C2-3b: `type_info(name)` — struct + enum introspection.

Stubs the IDA modules used by the extension so the tinfo/classic-enum
branches can be exercised without a live IDA session.
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


# --- fake typeinfo ------------------------------------------------------


class _FakeType:
    """Enough of ``tinfo_t`` to route struct / enum / typedef branches."""

    def __init__(self, spec: dict | None = None):
        self._spec = spec

    def get_named_type(self, til, name: str) -> bool:  # noqa: ARG002
        spec = _NAMED_TYPES.get(name)
        if spec is None:
            return False
        self._spec = spec
        return True

    def is_udt(self) -> bool:
        return bool(self._spec and self._spec.get("kind") == "udt")

    def is_enum(self) -> bool:
        return bool(self._spec and self._spec.get("kind") == "enum")

    def get_size(self) -> int:
        return int(self._spec.get("size", 0)) if self._spec else 0

    def _print(self) -> str:
        return self._spec.get("type_repr", "<fake>") if self._spec else "<fake>"

    def get_udt_details(self, udt) -> bool:
        if not self.is_udt():
            return False
        udt.load(self._spec.get("members", []))
        return True

    def get_enum_details(self, ei) -> bool:
        if not self.is_enum():
            return False
        # Simulate a rare failure via the `broken:true` flag on the spec.
        if self._spec.get("broken"):
            return False
        ei.load(self._spec.get("members", []))
        return True


class _FakeMember:
    def __init__(self, name: str, offset: int, size: int, type_repr: str,
                 inner: dict | None = None):
        self.name = name
        self._begin = offset * 8
        self.size = size * 8
        self.type = _FakeType(inner) if inner else _FakeType(
            {"kind": "primitive", "size": size, "type_repr": type_repr}
        )
        self.cmt = ""

    def begin(self) -> int:
        return self._begin


class _FakeUDT(list):
    def load(self, members_spec: list[dict]) -> None:
        self.clear()
        for m in members_spec:
            self.append(_FakeMember(
                name=m["name"], offset=m["offset"], size=m["size"],
                type_repr=m.get("type_repr", m["name"]),
                inner=m.get("inner"),
            ))


class _FakeEnumMember:
    def __init__(self, name: str, value: int):
        self.name = name
        self.value = value


class _FakeEnumData(list):
    def load(self, members_spec: list[dict]) -> None:
        self.clear()
        for m in members_spec:
            self.append(_FakeEnumMember(m["name"], m["value"]))


_NAMED_TYPES: dict[str, dict] = {}
_CLASSIC_ENUMS: dict[str, dict] = {}


def _install_ida_typeinf_stub() -> None:
    mod = types.ModuleType("ida_typeinf")
    mod.tinfo_t = _FakeType
    mod.udt_type_data_t = _FakeUDT
    mod.enum_type_data_t = _FakeEnumData
    sys.modules["ida_typeinf"] = mod


def _install_ida_enum_stub() -> None:
    mod = types.ModuleType("ida_enum")
    mod.BADADDR = 0xFFFFFFFFFFFFFFFF

    def get_enum(name: str):
        info = _CLASSIC_ENUMS.get(name)
        return info["eid"] if info else mod.BADADDR

    def get_enum_width(eid: int):
        for info in _CLASSIC_ENUMS.values():
            if info["eid"] == eid:
                return info.get("width", 4)
        return 0

    def get_enum_member_name(cid: int):
        for info in _CLASSIC_ENUMS.values():
            for m in info["members"]:
                if m["cid"] == cid:
                    return m["name"]
        return ""

    def for_all_enum_members(eid: int, cb):
        for info in _CLASSIC_ENUMS.values():
            if info["eid"] != eid:
                continue
            for m in info["members"]:
                cb(m["cid"], m["value"], 0)

    mod.get_enum = get_enum
    mod.get_enum_width = get_enum_width
    mod.get_enum_member_name = get_enum_member_name
    mod.for_all_enum_members = for_all_enum_members
    sys.modules["ida_enum"] = mod


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
    _install_ida_typeinf_stub()
    _install_ida_enum_stub()
    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


@pytest.fixture(autouse=True)
def _reset(ext_mod):  # noqa: ARG001 - fixture dep for import ordering
    _NAMED_TYPES.clear()
    _CLASSIC_ENUMS.clear()
    yield
    _NAMED_TYPES.clear()
    _CLASSIC_ENUMS.clear()


# --- struct branch ------------------------------------------------------


def test_c2_3_type_info_struct_returns_terse_summary(ext_mod):
    _NAMED_TYPES["_EPROCESS"] = {
        "kind": "udt", "size": 0x8E0, "type_repr": "_EPROCESS",
        "members": [
            {"name": "Pcb", "offset": 0x0, "size": 0x2E0},
            {"name": "ProcessLock", "offset": 0x2E0, "size": 0x8},
            {"name": "UniqueProcessId", "offset": 0x440, "size": 0x8},
        ],
    }
    out = ext_mod.type_info("_EPROCESS")
    assert out["ok"] is True
    assert out["kind"] == "struct"
    assert out["size"] == 0x8E0
    assert out["member_count"] == 3
    assert out["first_members"] == ["Pcb", "ProcessLock", "UniqueProcessId"]
    assert "hint" in out


def test_c2_3_type_info_struct_first_members_capped_at_10(ext_mod):
    """A wide struct should still fit inside a 10-name preview list."""
    members = [
        {"name": f"m{i:02d}", "offset": i * 8, "size": 8}
        for i in range(30)
    ]
    _NAMED_TYPES["_WIDE"] = {
        "kind": "udt", "size": 30 * 8, "type_repr": "_WIDE",
        "members": members,
    }
    out = ext_mod.type_info("_WIDE")
    assert out["ok"] is True
    assert len(out["first_members"]) == 10
    assert out["member_count"] == 30


# --- enum via tinfo -----------------------------------------------------


def test_c2_3_type_info_enum_tinfo_path(ext_mod):
    _NAMED_TYPES["NL_NEIGHBOR_STATE"] = {
        "kind": "enum", "size": 4, "type_repr": "NL_NEIGHBOR_STATE",
        "members": [
            {"name": "NlnsUnreachable", "value": 0},
            {"name": "NlnsIncomplete",  "value": 1},
            {"name": "NlnsProbe",       "value": 2},
            {"name": "NlnsDelay",       "value": 3},
            {"name": "NlnsStale",       "value": 4},
            {"name": "NlnsReachable",   "value": 5},
            {"name": "NlnsPermanent",   "value": 6},
        ],
    }
    out = ext_mod.type_info("NL_NEIGHBOR_STATE")
    assert out["ok"] is True
    assert out["kind"] == "enum"
    assert out["size"] == 4
    assert out["member_count"] == 7
    names = {m["name"] for m in out["members"]}
    assert "NlnsProbe" in names
    values = {m["value"] for m in out["members"]}
    assert 0 in values and 6 in values


def test_c2_3_type_info_enum_details_failure_returns_typed_error(ext_mod):
    _NAMED_TYPES["_BAD_ENUM"] = {
        "kind": "enum", "size": 4, "type_repr": "_BAD_ENUM",
        "broken": True, "members": [],
    }
    out = ext_mod.type_info("_BAD_ENUM")
    assert out["ok"] is False
    assert out["kind"] == "enum_details_unavailable"


# --- enum via classic ida_enum ------------------------------------------


def test_c2_3_type_info_enum_classic_path(ext_mod):
    _CLASSIC_ENUMS["OLD_ENUM"] = {
        "eid": 0x1000, "width": 4,
        "members": [
            {"cid": 0x1001, "name": "A", "value": 1},
            {"cid": 0x1002, "name": "B", "value": 2},
        ],
    }
    out = ext_mod.type_info("OLD_ENUM")
    assert out["ok"] is True
    assert out["kind"] == "enum"
    assert out["size"] == 4
    assert out["member_count"] == 2
    assert [m["name"] for m in out["members"]] == ["A", "B"]


# --- typedef fallback + not-found ---------------------------------------


def test_c2_3_type_info_typedef_returns_type_repr(ext_mod):
    # Not udt, not enum, but the named-type resolver returns True.
    _NAMED_TYPES["PVOID"] = {
        "kind": "primitive", "size": 8, "type_repr": "void *",
    }
    out = ext_mod.type_info("PVOID")
    assert out["ok"] is True
    assert out["kind"] == "typedef"
    assert out["size"] == 8
    assert out["type"] == "void *"


def test_c2_3_type_info_unknown_returns_typed_error(ext_mod):
    out = ext_mod.type_info("_NEVER_HEARD_OF")
    assert out["ok"] is False
    assert out["kind"] == "type_not_found"
    assert "hint" in out
