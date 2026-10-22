"""C2-3c: `pdb_layout_cache` — struct/enum layout lookups without IDA.

The module reads JSON cache files written by the extension's
``dump_layout`` tool. Tests build synthetic caches in a ``tmp_path``
directory and pass ``cache_dir=`` through so the real
``~/.suspex0/pdb_layouts/`` is untouched.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from suspex import pdb_layout_cache as pdb


def _write_layout(cache_dir: Path, module: str, build_id: str,
                  payload: dict) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = pdb.cache_path(module, build_id, cache_dir=cache_dir)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def _eprocess_layout(build_id: str = "F1E2A3B4") -> dict:
    """A trimmed _EPROCESS / _KPROCESS layout for the cache tests."""
    return {
        "module": "ntoskrnl.exe",
        "build_id": build_id,
        "types": {
            "_KPROCESS": {
                "size": 0x2E0,
                "members": [
                    {"name": "Header", "offset": 0x0,
                     "size": 0x18, "type": "_DISPATCHER_HEADER"},
                    {"name": "ProfileListHead", "offset": 0x18,
                     "size": 0x10, "type": "_LIST_ENTRY"},
                    {"name": "DirectoryTableBase", "offset": 0x28,
                     "size": 0x8, "type": "unsigned __int64"},
                ],
            },
            "_EPROCESS": {
                "size": 0x8E0,
                "members": [
                    {"name": "Pcb", "offset": 0x0,
                     "size": 0x2E0, "type": "_KPROCESS"},
                    {"name": "ProcessLock", "offset": 0x2E0,
                     "size": 0x8, "type": "_EX_PUSH_LOCK"},
                    {"name": "UniqueProcessId", "offset": 0x440,
                     "size": 0x8, "type": "void *"},
                ],
            },
        },
        "enums": {
            "NL_NEIGHBOR_STATE": {
                "size": 4,
                "members": [
                    {"name": "NlnsUnreachable", "value": 0},
                    {"name": "NlnsProbe", "value": 2},
                    {"name": "NlnsReachable", "value": 5},
                ],
            },
        },
    }


# --- cache_path / list_cached_layouts / _safe_component --------------


def test_c2_3_pdb_cache_path_sanitizes_module_and_build(tmp_path):
    p = pdb.cache_path("nt/os krnl", "build/../id", cache_dir=tmp_path)
    # No slashes, spaces, or parent traversal survives.
    assert str(p).startswith(str(tmp_path))
    assert "/" not in p.name and "\\" not in p.name
    assert "os_krnl" in p.name
    assert "build_.._id" in p.name


def test_c2_3_pdb_cache_list_returns_installed(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    _write_layout(tmp_path, "tcpip.sys", "11223344",
                  {"module": "tcpip.sys", "build_id": "11223344",
                   "types": {}, "enums": {}})
    rows = pdb.list_cached_layouts(cache_dir=tmp_path)
    modules = {r["module"] for r in rows}
    assert {"ntoskrnl.exe", "tcpip.sys"}.issubset(modules)


def test_c2_3_pdb_cache_list_empty_when_missing(tmp_path):
    """Non-existent cache dir yields an empty list — no exception."""
    missing = tmp_path / "nowhere"
    assert pdb.list_cached_layouts(cache_dir=missing) == []


# --- struct_info --------------------------------------------------------


def test_c2_3_pdb_cache_struct_info_hit(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.struct_info("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                          cache_dir=tmp_path)
    assert out["ok"] is True
    assert out["kind"] == "struct"
    assert out["size"] == 0x8E0
    assert out["member_count"] == 3
    assert out["first_members"] == ["Pcb", "ProcessLock",
                                    "UniqueProcessId"]


def test_c2_3_pdb_cache_struct_info_miss_returns_typed_error(tmp_path):
    """Cache exists but the requested struct is not in it."""
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.struct_info("ntoskrnl.exe", "F1E2A3B4",
                          "_NEVER_HEARD_OF", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "type_not_found"
    assert "hint" in out


def test_c2_3_pdb_cache_miss_returns_typed_error(tmp_path):
    """No cache file at all — ``pdb_layout_missing`` with installed hint."""
    out = pdb.struct_info("ntoskrnl.exe", "NOPE",
                          "_EPROCESS", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "pdb_layout_missing"
    assert "installed_builds" in out
    assert "hint" in out


def test_c2_3_pdb_cache_missing_hint_lists_matching_installed(tmp_path):
    """The `installed_builds` hint should list every cached build for
    the SAME module — an analyst who typos the build id sees the
    correct one right there."""
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.struct_info("ntoskrnl.exe", "MISS",
                          "_EPROCESS", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "pdb_layout_missing"
    ids = [row["build_id"] for row in out["installed_builds"]]
    assert "F1E2A3B4" in ids


# --- resolve_member -----------------------------------------------------


def test_c2_3_pdb_resolve_member_at_exact_offset(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             0x2E0, cache_dir=tmp_path)
    assert out["ok"] is True
    assert out["path"] == "_EPROCESS.ProcessLock"
    assert out["exact"] is True
    assert out["remaining_offset_int"] == 0


def test_c2_3_pdb_resolve_member_inside_nested_udt(tmp_path):
    """Offset 0x28 into _EPROCESS lands in _KPROCESS.DirectoryTableBase
    because ``Pcb`` is a nested cached type."""
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             0x28, cache_dir=tmp_path)
    assert out["ok"] is True
    assert out["path"] == "_EPROCESS.Pcb.DirectoryTableBase"
    assert out["remaining_offset_int"] == 0


def test_c2_3_pdb_resolve_member_stops_at_uncached_type(tmp_path):
    """An inner UDT that isn't itself cached returns a `note` field
    with the path prefix that WAS resolved."""
    layout = {
        "module": "ntoskrnl.exe", "build_id": "F1E2A3B4",
        "types": {
            "_EPROCESS": {
                "size": 0x100,
                "members": [
                    {"name": "Pcb", "offset": 0x0,
                     "size": 0x80, "type": "_KPROCESS"},
                ],
            },
            # _KPROCESS deliberately NOT cached.
        },
        "enums": {},
    }
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4", layout)
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             0x20, cache_dir=tmp_path)
    # Not an error — resolver returns partial success with `note`.
    assert out["ok"] is True
    # It landed on Pcb, could not recurse into _KPROCESS.
    # The recursion returns None member_name + path == "_EPROCESS.Pcb".
    assert out["path"].startswith("_EPROCESS.Pcb")
    assert "note" in out


def test_c2_3_pdb_resolve_member_past_end_errors(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             0x9000, cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "offset_out_of_range"
    assert out["struct_name"] == "_EPROCESS"


def test_c2_3_pdb_resolve_member_negative_offset(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             -1, cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_3_pdb_resolve_member_bad_offset_type(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4", "_EPROCESS",
                             "not-a-number", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "invalid_parameter"


def test_c2_3_pdb_resolve_member_missing_cache(tmp_path):
    out = pdb.resolve_member("ntoskrnl.exe", "MISS",
                             "_EPROCESS", 0x10, cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "pdb_layout_missing"


def test_c2_3_pdb_resolve_member_unknown_struct(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.resolve_member("ntoskrnl.exe", "F1E2A3B4",
                             "_NOPE", 0x10, cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "type_not_found"


# --- enum_info ----------------------------------------------------------


def test_c2_3_pdb_enum_info_hit(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.enum_info("ntoskrnl.exe", "F1E2A3B4",
                        "NL_NEIGHBOR_STATE", cache_dir=tmp_path)
    assert out["ok"] is True
    assert out["kind"] == "enum"
    assert out["size"] == 4
    values = {m["value"] for m in out["members"]}
    assert {0, 2, 5}.issubset(values)


def test_c2_3_pdb_enum_info_miss(tmp_path):
    _write_layout(tmp_path, "ntoskrnl.exe", "F1E2A3B4",
                  _eprocess_layout("F1E2A3B4"))
    out = pdb.enum_info("ntoskrnl.exe", "F1E2A3B4",
                        "NOT_AN_ENUM", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "type_not_found"


# --- malformed cache ----------------------------------------------------


def test_c2_3_pdb_cache_malformed_json_typed_error(tmp_path):
    p = pdb.cache_path("ntoskrnl.exe", "F1E2A3B4", cache_dir=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json}", encoding="utf-8")
    out = pdb.struct_info("ntoskrnl.exe", "F1E2A3B4",
                          "_EPROCESS", cache_dir=tmp_path)
    # A parse failure surfaces via LayoutCacheError inside load(),
    # which the tool re-raises as `pdb_layout_missing`. Alternatively
    # the wrapper could adopt a distinct `invalid_layout` slug —
    # the current behaviour is documented here so a refactor doesn't
    # silently change it.
    assert out["ok"] is False
    assert out["kind"] == "pdb_layout_missing"


def test_c2_3_pdb_cache_layout_missing_types_key(tmp_path):
    """Cache file exists but has no ``types`` key — surface `invalid_layout`."""
    p = pdb.cache_path("ntoskrnl.exe", "F1E2A3B4", cache_dir=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"module": "ntoskrnl.exe",
                             "build_id": "F1E2A3B4"}),
                 encoding="utf-8")
    out = pdb.struct_info("ntoskrnl.exe", "F1E2A3B4",
                          "_EPROCESS", cache_dir=tmp_path)
    assert out["ok"] is False
    assert out["kind"] == "invalid_layout"


# --- default cache dir --------------------------------------------------


def test_c2_3_pdb_cache_default_dir_is_home_suspex(tmp_path, monkeypatch):
    """Default cache dir must live under ~/.suspex0/ — verified via
    monkeypatching Path.home so real state isn't touched."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    # Recompute a cache path with the patched home.
    from importlib import reload
    reload(pdb)
    p = pdb.cache_path("m", "b")
    assert str(p).startswith(str(tmp_path / ".suspex0" / "pdb_layouts"))
    # Restore real module so downstream tests keep the un-patched view.
    reload(pdb)
