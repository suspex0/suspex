"""code_integrity plugin test — fake kernel serving a mapped PE image;
disk side reads a fixture file. iat_diff-style harness."""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import _pefixture as fx

PLUGIN_PATH = (Path(__file__).resolve().parents[2]
               / "plugins" / "code_integrity" / "run.py")

pytestmark = pytest.mark.asyncio

BASE = 0xFFFFF80000000000
SIZE = 0x4000


def _load():
    spec = importlib.util.spec_from_file_location(
        "code_integrity_run", PLUGIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _map_image(file_data: bytes) -> bytes:
    """Re-layout a file-layout fixture into image layout (sections at RVA)."""
    img = bytearray(SIZE)
    img[:0x200] = file_data[:0x200]
    for rva, off in fx.SEC_RAW.items():
        img[rva:rva + fx.SEC_FILE] = file_data[off:off + fx.SEC_FILE]
    return bytes(img)


def _sdk(image: bytes):
    async def read(pid, addr, size, space="user", view=""):
        off = addr - BASE
        if off < 0 or off + size > len(image):
            raise RuntimeError(f"unmapped {addr:#x}")
        return image[off:off + size]
    async def _mods(pid=0, kernel=False, view=""):
        return [{"name": "fix.sys", "base": BASE, "size": SIZE,
                 "path": "\\SystemRoot\\fix.sys"}]
    mods = SimpleNamespace(list=_mods)
    return SimpleNamespace(mem=SimpleNamespace(read=read), mods=mods)


def _two_funcs() -> bytes:
    # fn1 @ +0: call fn2; ret.  fn2 @ +0x10: xor eax,eax; ret
    return (b"\xE8" + struct.pack("<i", 0x10 - 5) + b"\xC3"
            + b"\xCC" * (0x10 - 6)
            + b"\x31\xC0\xC3")


async def test_identical_images(tmp_path) -> None:
    pytest.importorskip("capstone")
    mod = _load()
    file_pe = fx.build_pe(
        code=_two_funcs(),
        pdata=[(fx.TEXT_RVA, fx.TEXT_RVA + 6),
               (fx.TEXT_RVA + 0x10, fx.TEXT_RVA + 0x13)])
    live = _map_image(file_pe)
    sdk = _sdk(live)
    disk = tmp_path / "fix.sys"
    disk.write_bytes(file_pe)
    res = await mod.run(sdk, {"module": "fix.sys",
                              "disk_path": str(disk)})
    assert res["ok"] is True
    assert res["severity"] == "info", res["changed"]
    assert res["changed"] == []


async def test_inline_patch_detected(tmp_path) -> None:
    pytest.importorskip("capstone")
    mod = _load()
    file_pe = fx.build_pe(
        code=_two_funcs(),
        pdata=[(fx.TEXT_RVA, fx.TEXT_RVA + 6),
               (fx.TEXT_RVA + 0x10, fx.TEXT_RVA + 0x13)])
    live = bytearray(_map_image(file_pe))
    # hot-patch fn2: xor eax,eax -> mov eax,1 (B8 01 00 00 00)
    live[fx.TEXT_RVA + 0x10:fx.TEXT_RVA + 0x15] = b"\xB8\x01\x00\x00\x00"
    sdk = _sdk(bytes(live))
    disk = tmp_path / "fix.sys"
    disk.write_bytes(file_pe)
    res = await mod.run(sdk, {"module": "fix.sys",
                              "disk_path": str(disk)})
    assert res["ok"] is True
    assert res["severity"] == "high"
    assert any(c["verdict"] == "body_mismatch" for c in res["changed"])


async def test_missing_baseline(tmp_path) -> None:
    mod = _load()
    sdk = _sdk(_map_image(fx.build_pe()))
    res = await mod.run(sdk, {"module": "fix.sys"})
    assert res["ok"] is False
    assert res["kind"] == "baseline_unavailable"
