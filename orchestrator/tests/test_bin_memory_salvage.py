"""``bin_manage source='memory'`` partial-read salvage tests.

Two driver behaviors are covered:

- **v1.3+**: a partial read completes ``STATUS_SUCCESS`` with a short
  ``*Done`` — user mode gets the valid prefix plus ``first_bad_offset``
  marking the hole.
- **older builds**: the PARTIAL walk completed with the warning NTSTATUS
  ``STATUS_PARTIAL_COPY`` — which user mode sees as a *failed*
  ``DeviceIoControl`` (``gle=299``) with the partial bytes dropped by
  the I/O manager.

Either way a single big read cannot salvage a module with paged-out
pages; the loader keeps prefixes, bisects failures to page granularity,
zero-fills the refused pages, and reports them under ``salvage.holes``.
"""
from __future__ import annotations

import pytest

from _multi_fakes import (_RichFakeAgentClient, _build_ctx_and_server,
                          _call_as)
from _pefixture import build_pe, TEXT_RVA, SEC_RAW

pytest.importorskip("capstone")

_MOD_BASE = 0x140000000


def _image_layout(file_img: bytes) -> bytes:
    """Re-lay a file-layout fixture into memory image layout (rva==off),
    which is what a live module read returns."""
    img = bytearray(0x4000)  # fixture SizeOfImage
    img[:0x200] = file_img[:0x200]                     # headers
    for rva, raw in SEC_RAW.items():
        img[rva:rva + 0x200] = file_img[raw:raw + 0x200]
    return bytes(img)


_IMG = _image_layout(build_pe(code=b"\x58\xC3" + b"\x90" * (0x200 - 2)))
_GADGET_VA = _MOD_BASE + TEXT_RVA          # pop rax; ret


def _i(v) -> int:
    """Rows come back hexified by the envelope ('0x1000') — parse both."""
    return int(v, 0) if isinstance(v, str) else int(v)


class _HoledMemFake(_RichFakeAgentClient):
    """Reads fail with the driver's gle=299 whenever the range touches a
    paged-out page (the driver stops its walk and the bytes are lost)."""

    holes: tuple[int, ...] = (0x3000,)      # module offsets, page-aligned

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.read_calls: list[tuple[int, int]] = []

    async def mem_modules(self, pid, kernel=False, *a, **kw):
        return [{"name": "holed.sys", "base": _MOD_BASE, "size": len(_IMG),
                 "path": "\\SystemRoot\\holed.sys"}]

    def _touches_hole(self, off: int, size: int) -> bool:
        end = off + size
        return any(off < h + 0x1000 and end > h for h in self.holes)

    async def mem_read(self, pid, addr, size, space="user", **kw):
        off = int(addr) - _MOD_BASE
        size = int(size)
        self.read_calls.append((off, size))
        if off < 0 or off + size > len(_IMG) or self._touches_hole(off, size):
            raise RuntimeError("driver: DeviceIoControl gle=299")
        data = _IMG[off:off + size]
        if kw.get("want_meta"):
            return data, {"read_bytes": len(data), "first_bad_offset": 0}
        return data


class _PrefixMemFake(_HoledMemFake):
    """The v1.3+ driver: returns the valid prefix up to the first hole
    (with ``first_bad_offset``) instead of failing; only a range that
    *starts* inside a hole still errors."""

    async def mem_read(self, pid, addr, size, space="user", **kw):
        off = int(addr) - _MOD_BASE
        size = int(size)
        self.read_calls.append((off, size))
        if off < 0 or off + size > len(_IMG) or off in self.holes:
            raise RuntimeError("driver: DeviceIoControl gle=299")
        stop = off + size
        for h in self.holes:
            if off < h < stop:
                stop = h          # walk stops at the first refused page
        data = _IMG[off:stop]
        if kw.get("want_meta"):
            meta = {"read_bytes": len(data),
                    "first_bad_offset": len(data) if stop < off + size else 0}
            return data, meta
        return data


async def _run(tmp_path, monkeypatch, fake_cls, args: dict) -> tuple[dict, object]:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    monkeypatch.setattr("suspex.session.AgentClient", fake_cls)
    await _call_as("peer-A", server, "target_manage", {"action": "connect"})
    out = await _call_as("peer-A", server, "bin_manage", args)
    client = next(iter(ctx.session.clients.values()))
    return out, client


async def test_salvages_holes_and_reports_them(tmp_path, monkeypatch):
    out, client = await _run(tmp_path, monkeypatch, _HoledMemFake, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "category": "load", "limit": 4,
    })
    assert out["ok"] is True, out
    # The resident .text page still yields its gadget at the live VA.
    vas = {_i(r["va"]) for r in out["items"]}
    assert _GADGET_VA in vas
    # The paged-out page is reported, not silently missing.
    salv = out["salvage"]
    assert _i(salv["bytes_missing"]) == 0x1000
    assert len(salv["holes"]) == 1
    hole = salv["holes"][0]
    assert _i(hole["offset"]) == 0x3000
    assert _i(hole["size"]) == 0x1000
    assert _i(hole["va"]) == _MOD_BASE + 0x3000
    assert "zero-filled" in salv["note"]


async def test_adjacent_holes_merged(tmp_path, monkeypatch):
    class _Two(_HoledMemFake):
        holes = (0x2000, 0x3000)   # adjacent pages

    out, _ = await _run(tmp_path, monkeypatch, _Two, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "limit": 1,
    })
    assert out["ok"] is True, out
    holes = out["salvage"]["holes"]
    assert len(holes) == 1
    assert _i(holes[0]["size"]) == 0x2000
    assert _i(holes[0]["offset"]) == 0x2000
    assert _i(out["salvage"]["bytes_missing"]) == 0x2000


async def test_clean_module_skips_salvage(tmp_path, monkeypatch):
    class _Clean(_HoledMemFake):
        holes = ()

    out, client = await _run(tmp_path, monkeypatch, _Clean, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "limit": 1,
    })
    assert out["ok"] is True, out
    assert "salvage" not in out
    # Fast path: exactly one read for the whole image, no bisecting.
    assert len(client.read_calls) == 1
    assert client.read_calls[0] == (0, len(_IMG))


async def test_salvage_bisects_only_failing_chunk(tmp_path, monkeypatch):
    out, client = await _run(tmp_path, monkeypatch, _HoledMemFake, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "limit": 1,
    })
    assert out["ok"] is True, out
    # Fast path (1) + one salvage chunk (1) + bisect levels for the hole.
    # 0x4000 fits in a single 1 MiB chunk: 1 + log2(0x4000/0x1000) * 2.
    assert len(client.read_calls) < 12


async def test_all_pages_failed_is_an_error(tmp_path, monkeypatch):
    class _Dead(_HoledMemFake):
        async def mem_read(self, pid, addr, size, space="user", **kw):
            self.read_calls.append((int(addr) - _MOD_BASE, int(size)))
            raise RuntimeError("driver: DeviceIoControl gle=299")

    out, _ = await _run(tmp_path, monkeypatch, _Dead, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True,
    })
    assert out["ok"] is False
    assert out["kind"] == "read_failed"


async def test_prefix_driver_salvage_and_merge(tmp_path, monkeypatch):
    """Fixed driver: fast-path returns the prefix, salvage keeps it and
    bisects the hole — exercises the fast-prefix merge over the mutable
    salvage buffer."""
    out, client = await _run(tmp_path, monkeypatch, _PrefixMemFake, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "category": "load", "limit": 4,
    })
    assert out["ok"] is True, out
    vas = {_i(r["va"]) for r in out["items"]}
    assert _GADGET_VA in vas
    salv = out["salvage"]
    assert _i(salv["bytes_missing"]) == 0x1000
    hole = salv["holes"][0]
    assert _i(hole["offset"]) == 0x3000
    assert _i(hole["va"]) == _MOD_BASE + 0x3000


async def test_prefix_driver_page_inside_hole(tmp_path, monkeypatch):
    """A read starting inside the hole still hard-fails on the fixed
    driver (moved=0 -> real error) — bisection must isolate it."""

    class _Two(_PrefixMemFake):
        holes = (0x2000, 0x3000)

    out, _ = await _run(tmp_path, monkeypatch, _Two, {
        "action": "gadgets", "source": "memory", "module": "holed.sys",
        "kernel": True, "limit": 1,
    })
    assert out["ok"] is True, out
    holes = out["salvage"]["holes"]
    assert len(holes) == 1
    assert _i(holes[0]["size"]) == 0x2000
    assert _i(holes[0]["offset"]) == 0x2000


async def test_funcs_reports_salvage(tmp_path, monkeypatch):
    out, _ = await _run(tmp_path, monkeypatch, _HoledMemFake, {
        "action": "funcs", "source": "memory", "module": "holed.sys",
        "kernel": True,
    })
    assert out["ok"] is True, out
    assert _i(out["salvage"]["bytes_missing"]) == 0x1000
