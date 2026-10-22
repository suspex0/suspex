"""Offline unit tests for the ``craft_test`` reference plugin.

Loads the plugin file directly and feeds it a fake SDK — no plugin
runner subprocess, no live agent. The codegen/emu SDK facades pass
through to the real ``suspex.codegen`` and ``suspex.emulate`` modules
under the hood; when the codegen extra is not installed, the tests
skip.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from suspex import codegen as cg
from suspex.sdk import CodegenApi, EmuApi

PLUGIN_PATH = (Path(__file__).resolve().parents[2]
               / "plugins" / "craft_test" / "run.py")


pytestmark = pytest.mark.skipif(
    not (cg.capstone_available() and cg.keystone_available()
         and cg.unicorn_available()),
    reason="codegen extra not installed",
)


def _load_plugin():
    spec = importlib.util.spec_from_file_location("craft_test_run", PLUGIN_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sdk() -> SimpleNamespace:
    """Fake SDK carrying the real codegen/emu facades. No target."""
    return SimpleNamespace(codegen=CodegenApi(), emu=EmuApi())


async def test_assemble_disasm_emulate_roundtrip() -> None:
    plugin = _load_plugin()
    sdk = _sdk()
    result = await plugin.run(sdk, {
        "code": "mov rax, 0x2345; ret",
        "arch": "x64",
        "entry": 0x1000,
        "emulate": True,
        "emu_engine": "unicorn",
    })
    assert result["ok"] is True
    assert result["assembly"]["size"] > 0
    assert result["disasm"][0]["mnemonic"] == "mov"
    assert result["emu"]["engine"] == "unicorn"
    assert result["emu"]["final_regs"]["rax"] == 0x2345
    assert result["severity"] == "info"


async def test_no_emulate_skips_engine() -> None:
    plugin = _load_plugin()
    sdk = _sdk()
    result = await plugin.run(sdk, {
        "code": "ret",
        "arch": "x64",
        "entry": 0x1000,
        "emulate": False,
    })
    assert result["ok"] is True
    assert "emu" not in result
    assert result["disasm"][0]["mnemonic"] == "ret"


async def test_bad_asm_returns_named_stage() -> None:
    plugin = _load_plugin()
    sdk = _sdk()
    result = await plugin.run(sdk, {
        "code": "this is not asm",
        "arch": "x64",
        "entry": 0x1000,
        "emulate": True,
    })
    assert result["ok"] is False
    assert result["stage"] == "assemble"
    assert "assemble failed" in result["summary"]


async def test_x86_smoke() -> None:
    plugin = _load_plugin()
    sdk = _sdk()
    result = await plugin.run(sdk, {
        "code": "mov eax, 0xabcd; ret",
        "arch": "x86",
        "entry": 0x401000,
        "emulate": True,
        "emu_engine": "unicorn",
    })
    assert result["ok"] is True
    assert result["emu"]["final_regs"]["eax"] == 0xabcd
