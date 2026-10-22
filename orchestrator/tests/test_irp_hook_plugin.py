"""irp_hook_check plugin test — fake kernel memory serving a synthetic
_DRIVER_OBJECT; no live target needed (test_iat_diff_plugin.py pattern).
"""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_PATH = (Path(__file__).resolve().parents[2]
               / "plugins" / "irp_hook_check" / "run.py")

pytestmark = pytest.mark.asyncio

OBJ = 0xFFFF8A0000000000
DRV_BASE = 0xFFFFF80000000000
DRV_SIZE = 0x10000


def _load():
    spec = importlib.util.spec_from_file_location("irp_hook_run",
                                                  PLUGIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _kernel_image(major_handlers: dict[int, int] | None = None,
                  fastio: dict[int, int] | None = None,
                  name: str = "\\Driver\\Fixt") -> dict[int, bytes]:
    """Sparse kernel memory: {va: bytes}."""
    mem: dict[int, bytes] = {}
    # _DRIVER_OBJECT
    buf = bytearray(0x70 + 28 * 8)
    struct.pack_into("<Q", buf, 0x18, DRV_BASE)            # DriverStart
    struct.pack_into("<I", buf, 0x20, DRV_SIZE)            # DriverSize
    name_b = name.encode("utf-16le")
    name_va = 0xFFFF8A0000001000
    struct.pack_into("<H", buf, 0x38, len(name_b))         # DriverName.len
    struct.pack_into("<Q", buf, 0x38 + 8, name_va)
    fastio_va = 0xFFFF8A0000002000 if fastio is not None else 0
    struct.pack_into("<Q", buf, 0x50, fastio_va)
    for i in range(28):
        handler = (major_handlers or {}).get(i, DRV_BASE + 0x2000 + i * 0x40)
        struct.pack_into("<Q", buf, 0x70 + i * 8, handler)
    mem[OBJ] = bytes(buf)
    mem[name_va] = name_b + b"\x00" * 64  # wstr() reads 64B chunks
    if fastio is not None:
        fbuf = bytearray(28 * 8)
        struct.pack_into("<I", fbuf, 0, 28 * 8)
        for i in range(1, 28):
            v = (fastio or {}).get(i, DRV_BASE + 0x4000 + i * 0x10)
            struct.pack_into("<Q", fbuf, i * 8, v)
        mem[fastio_va] = bytes(fbuf)
    return mem


def _sdk(mem: dict[int, bytes]):
    async def read(pid, addr, size, space="user", view=""):
        # serve overlapping ranges by locating the containing span
        for va, blob in mem.items():
            if va <= addr and addr + size <= va + len(blob):
                off = addr - va
                return blob[off:off + size]
        raise RuntimeError(f"unmapped {addr:#x}+{size:#x}")
    return SimpleNamespace(mem=SimpleNamespace(read=read))


async def test_clean_driver_no_findings() -> None:
    mod = _load()
    mem = _kernel_image(fastio={})
    sdk = _sdk(mem)
    res = await mod.run(sdk, {"driver_object": hex(OBJ)})
    assert res["ok"] is True
    assert res["severity"] == "info"
    assert res["driver_name"] == "\\Driver\\Fixt"
    assert res["verdict_counts"].get("redirected_out", 0) == 0
    # without a static baseline, in-module pointers are unresolved_static
    assert res["verdict_counts"]["unresolved_static"] == 28 + 27


async def test_hooked_slot_flagged() -> None:
    mod = _load()
    mem = _kernel_image(
        major_handlers={14: 0xDEADBEEF0000},  # IRP_MJ_DEVICE_CONTROL out
        fastio={10: 0xBADBADBAD000},          # FastIoDeviceControl out
    )
    sdk = _sdk(mem)
    res = await mod.run(sdk, {"driver_object": hex(OBJ)})
    assert res["severity"] == "high"
    hooked = [r for r in res["major_function"]
              if r["verdict"] == "redirected_out"]
    assert hooked and hooked[0]["name"] == "IRP_MJ_DEVICE_CONTROL"
    assert any(r["verdict"] == "redirected_out" for r in res["fastio"])


async def test_static_baseline_match(tmp_path) -> None:
    pytest.importorskip("capstone")
    mod = _load()
    # Build a static driver whose DriverEntry stores a handler into
    # MajorFunction[14] (offset 0x70 + 14*8 = 0xE0).
    sys.path.insert(0, str(Path(__file__).parent))
    import _pefixture as fx  # noqa: E402
    # mov rbx, rcx ; lea rax, [rip+disp] ; mov [rbx+0xE0], rax ; ret
    handler_off = 0x40
    prefix = (b"\x48\x8B\xD9"                                   # mov rbx,rcx
              b"\x48\x8D\x05" + struct.pack("<i",              # lea rax,[rip+x]
                  handler_off - (3 + 7))
              + b"\x48\x89\x83" + struct.pack("<i", 0xE0)       # mov [rbx+0xE0],rax
              + b"\xC3")
    code = prefix + b"\xCC" * (0x40 - len(prefix)) + b"\xC3"
    data = fx.build_pe(code=code, subsystem=1)
    mod_path = tmp_path / "fix.sys"
    mod_path.write_bytes(data)

    handler_live = DRV_BASE + fx.TEXT_RVA + handler_off
    mem = _kernel_image(major_handlers={14: handler_live})
    sdk = _sdk(mem)
    res = await mod.run(sdk, {"driver_object": hex(OBJ),
                              "module_path": str(mod_path)})
    assert res["ok"] is True
    if res["static_baseline"]:
        row14 = next(r for r in res["major_function"] if r["slot"] == 14)
        assert row14["verdict"] == "matched", res
