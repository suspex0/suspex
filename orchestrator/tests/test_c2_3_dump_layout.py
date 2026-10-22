"""C2-3c: `dump_layout` — extension-side writer for the PDB cache.

The writer lives inside ``suspex_idalib_ext.py`` and runs in the
idalib-embedded interpreter. Tests stub ``ida_typeinf`` so the
writer can be exercised without a live IDA session, and route the
cache dir at the (real) ``~/.suspex0/pdb_layouts`` path via
``monkeypatch`` on ``expanduser`` so tests never touch the shared
cache.
"""
from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path

import pytest

from suspex import pdb_layout_cache as pdb


_ORCH_DIR = Path(__file__).resolve().parents[1]
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))


# --- IDA typeinf stub, same shape as test_c2_3_type_info -----------


class _FakeType:
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
        ei.load(self._spec.get("members", []))
        return True


class _FakeMember:
    def __init__(self, name: str, offset: int, size: int,
                 type_repr: str):
        self.name = name
        self._begin = offset * 8
        self.size = size * 8
        self.type = _FakeType({"kind": "primitive", "size": size,
                                "type_repr": type_repr})
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
_ORDINALS: list[str] = []


def _install_ida_typeinf_stub() -> None:
    mod = types.ModuleType("ida_typeinf")
    mod.tinfo_t = _FakeType
    mod.udt_type_data_t = _FakeUDT
    mod.enum_type_data_t = _FakeEnumData

    def get_ordinal_qty(til=None):  # noqa: ARG001
        return len(_ORDINALS)

    def get_numbered_type_name(til, ordinal=None):
        # Support both call shapes.
        if ordinal is None:
            ordinal = til
        if 1 <= ordinal <= len(_ORDINALS):
            return _ORDINALS[ordinal - 1]
        return ""

    mod.get_ordinal_qty = get_ordinal_qty
    mod.get_numbered_type_name = get_numbered_type_name
    sys.modules["ida_typeinf"] = mod


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


@pytest.fixture
def ext_mod(tmp_path, monkeypatch):
    """Load the extension with a redirected ~/.suspex0/pdb_layouts.

    ``_pdb_cache_dir`` in the extension uses
    ``os.path.expanduser('~')`` to find home; patch that to
    ``tmp_path`` so the writer never touches the real cache dir.
    """
    _install_core_stub()
    _install_ida_typeinf_stub()

    # Redirect ~ before importing so _pdb_cache_dir picks up tmp_path.
    monkeypatch.setattr("os.path.expanduser",
                        lambda p: str(tmp_path) if p == "~" else p)

    if "suspex_idalib_ext" in sys.modules:
        return importlib.reload(sys.modules["suspex_idalib_ext"])
    return importlib.import_module("suspex_idalib_ext")


@pytest.fixture(autouse=True)
def _reset():
    _NAMED_TYPES.clear()
    _ORDINALS.clear()
    yield
    _NAMED_TYPES.clear()
    _ORDINALS.clear()


def _register_struct(name: str, size: int, members: list[dict]) -> None:
    _NAMED_TYPES[name] = {
        "kind": "udt", "size": size, "type_repr": name,
        "members": members,
    }
    _ORDINALS.append(name)


def _register_enum(name: str, size: int, members: list[dict]) -> None:
    _NAMED_TYPES[name] = {
        "kind": "enum", "size": size, "type_repr": name,
        "members": members,
    }
    _ORDINALS.append(name)


# --- basic write path ---------------------------------------------------


def test_c2_3_dump_layout_writes_full_cache(ext_mod, tmp_path):
    _register_struct("_EPROCESS", 0x100, [
        {"name": "Pcb", "offset": 0x0, "size": 0x80, "type_repr": "_KPROCESS"},
        {"name": "Lock", "offset": 0x80, "size": 0x8, "type_repr": "u64"},
    ])
    _register_enum("KWAIT_REASON", 4, [
        {"name": "Executive", "value": 0},
        {"name": "FreePage", "value": 1},
    ])
    out = ext_mod.dump_layout(module="ntoskrnl.exe",
                              build_id="F1E2A3B4", types="")
    assert out["ok"] is True
    assert out["types_dumped"] == 1
    assert out["enums_dumped"] == 1
    assert out["missing"] == []

    # The cache lives under the redirected home.
    expected = tmp_path / ".suspex0" / "pdb_layouts"
    files = sorted(p.name for p in expected.glob("*.json"))
    assert files == ["ntoskrnl.exe__F1E2A3B4.json"]

    written = json.loads((expected / files[0]).read_text(encoding="utf-8"))
    assert written["module"] == "ntoskrnl.exe"
    assert written["build_id"] == "F1E2A3B4"
    assert "_EPROCESS" in written["types"]
    assert "KWAIT_REASON" in written["enums"]


def test_c2_3_dump_layout_respects_types_allowlist(ext_mod, tmp_path):
    _register_struct("_EPROCESS", 0x100, [
        {"name": "a", "offset": 0x0, "size": 0x8},
    ])
    _register_struct("_KTHREAD", 0x100, [
        {"name": "b", "offset": 0x0, "size": 0x8},
    ])
    out = ext_mod.dump_layout(
        module="ntoskrnl.exe", build_id="F1E2A3B4",
        types=json.dumps(["_EPROCESS"]),
    )
    assert out["ok"] is True
    written = json.loads(
        (tmp_path / ".suspex0" / "pdb_layouts"
         / "ntoskrnl.exe__F1E2A3B4.json").read_text(encoding="utf-8")
    )
    assert list(written["types"].keys()) == ["_EPROCESS"]
    assert "_KTHREAD" not in written["types"]


def test_c2_3_dump_layout_reports_missing_names(ext_mod, tmp_path):
    _register_struct("_KTHREAD", 0x100, [
        {"name": "b", "offset": 0x0, "size": 0x8},
    ])
    out = ext_mod.dump_layout(
        module="m", build_id="b",
        types=json.dumps(["_KTHREAD", "_NEVER"]),
    )
    assert out["ok"] is True
    assert out["missing"] == ["_NEVER"]


def test_c2_3_dump_layout_rejects_bad_types_json(ext_mod):
    out = ext_mod.dump_layout(module="m", build_id="b",
                              types="not json")
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_3_dump_layout_accepts_bare_string_type(ext_mod, tmp_path):
    """``types='"_KTHREAD"'`` (a bare JSON string) — a common typo shape."""
    _register_struct("_KTHREAD", 0x100, [
        {"name": "b", "offset": 0x0, "size": 0x8},
    ])
    out = ext_mod.dump_layout(module="m", build_id="b",
                              types=json.dumps("_KTHREAD"))
    assert out["ok"] is True
    written = json.loads(
        (tmp_path / ".suspex0" / "pdb_layouts"
         / "m__b.json").read_text(encoding="utf-8")
    )
    assert "_KTHREAD" in written["types"]


def test_c2_3_dump_layout_roundtrip_matches_orchestrator_reader(
        ext_mod, tmp_path):
    """The file the extension writes must be readable by the
    orchestrator-side ``pdb_layout_cache`` module — that's the whole
    point of the cache handshake."""
    _register_struct("_EPROCESS", 0x8E0, [
        {"name": "Pcb", "offset": 0x0, "size": 0x2E0, "type_repr": "_KPROCESS"},
        {"name": "UniqueProcessId", "offset": 0x440, "size": 0x8,
         "type_repr": "void *"},
    ])
    out = ext_mod.dump_layout(module="ntoskrnl.exe",
                              build_id="F1E2A3B4",
                              types=json.dumps(["_EPROCESS"]))
    assert out["ok"] is True

    cache_dir = tmp_path / ".suspex0" / "pdb_layouts"
    info = pdb.struct_info("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                           cache_dir=cache_dir)
    assert info["ok"] is True
    assert info["size"] == 0x8E0
    assert "Pcb" in info["first_members"]


def test_c2_3_dump_layout_atomic_write_no_tmp_left(ext_mod, tmp_path):
    """After a successful dump the cache dir should hold ONLY the
    final ``.json`` file — no stray ``.tmp`` sibling from the
    tmp+rename path."""
    _register_struct("_A", 0x10, [
        {"name": "a", "offset": 0x0, "size": 0x8},
    ])
    ext_mod.dump_layout(module="m", build_id="b",
                        types=json.dumps(["_A"]))
    cache_dir = tmp_path / ".suspex0" / "pdb_layouts"
    tmps = list(cache_dir.glob(".pdb_layout.*.tmp"))
    assert tmps == []
