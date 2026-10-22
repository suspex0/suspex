"""Unit test for the iat_diff plugin — imports run.py directly and feeds it
a fake sdk. Doesn't need the plugin runner subprocess or a live agent."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_PATH = (Path(__file__).resolve().parents[2]
               / "plugins" / "iat_diff" / "run.py")


def _load_plugin():
    spec = importlib.util.spec_from_file_location("iat_diff_run", PLUGIN_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class _FakeMods:
    def __init__(self, entries: list[dict]) -> None:
        self._entries = entries
        self.last_call: dict | None = None

    async def imports(self, pid: int, module: str, *, kernel: bool = False,
                      view: str = "") -> list[dict]:
        self.last_call = {"pid": pid, "module": module, "kernel": kernel, "view": view}
        return self._entries


def _sdk(entries: list[dict]) -> tuple[SimpleNamespace, _FakeMods]:
    mods = _FakeMods(entries)
    return SimpleNamespace(mods=mods), mods


async def test_iat_diff_all_clean_is_info() -> None:
    mod = _load_plugin()
    sdk, mods = _sdk([
        {"dll": "kernel32.dll", "name": "CreateFileW", "hooked": False,
         "iat_slot": 0x100, "resolved": 0x200, "resolved_module": "KERNEL32.DLL"},
        {"dll": "user32.dll", "name": "MessageBoxW", "hooked": False,
         "iat_slot": 0x108, "resolved": 0x300, "resolved_module": "USER32.DLL"},
    ])
    result = await mod.run(sdk, {"pid": 1234, "module": "notepad.exe"})
    assert result["ok"] is True
    assert result["severity"] == "info"
    assert result["totals"] == {"imports": 2, "hooked": 0}
    assert result["hooked"] == []
    assert mods.last_call == {"pid": 1234, "module": "notepad.exe",
                              "kernel": False, "view": "user"}


async def test_iat_diff_hooked_is_high() -> None:
    mod = _load_plugin()
    sdk, _ = _sdk([
        {"dll": "kernel32.dll", "name": "CreateFileW", "hooked": False,
         "iat_slot": 0x100, "resolved": 0x200, "resolved_module": "KERNEL32.DLL"},
        {"dll": "kernel32.dll", "name": "WriteFile", "hooked": True,
         "iat_slot": 0x108, "resolved": 0xDEADBEEF, "resolved_module": ""},
    ])
    result = await mod.run(sdk, {"pid": 1234, "module": "notepad.exe"})
    assert result["severity"] == "high"
    assert result["totals"] == {"imports": 2, "hooked": 1}
    assert len(result["hooked"]) == 1
    assert result["hooked"][0]["name"] == "WriteFile"
    assert result["hooked"][0]["resolved_module"] == "<unmapped>"


async def test_iat_diff_ordinal_import_renders_as_hash_prefix() -> None:
    mod = _load_plugin()
    sdk, _ = _sdk([
        {"dll": "user32.dll", "name": "", "ordinal": 42, "hooked": True,
         "iat_slot": 0x100, "resolved": 0xBAD, "resolved_module": ""},
    ])
    result = await mod.run(sdk, {"pid": 1, "module": "app.exe", "view": "kernel"})
    assert result["hooked"][0]["name"] == "#42"


async def test_iat_diff_view_and_kernel_pass_through() -> None:
    mod = _load_plugin()
    sdk, mods = _sdk([])
    await mod.run(sdk, {"pid": 0, "module": "ntdll.dll", "view": "kernel",
                        "kernel": True})
    assert mods.last_call == {"pid": 0, "module": "ntdll.dll",
                              "kernel": True, "view": "kernel"}
