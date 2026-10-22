"""SDK facade tests against fake clients (no network)."""

from __future__ import annotations

import pytest

from suspex.findings import FindingsLedger
from suspex.sdk import (Reader, SuspexError, SuspexSDK, buffer_reader, parse_mask,
                        pattern_scan, rva_to_offset)
from suspex.sdk import parse_pe

MODULES = [
    {"name": "ntoskrnl.exe", "base": "2752491520", "size": "8388608", "kernel": True},
    {"name": "C:\\Windows\\System32\\ci.dll", "base": "5364654080", "size": "1048576",
     "kernel": True},
]


class FakeClient:
    def __init__(self, mem: dict[int, bytes]):
        self.mem = mem
        self.imports: dict[tuple[int, str], list[dict]] = {}
        self.exports: dict[tuple[int, str], list[dict]] = {}
        self.heaps: dict[int, list[dict]] = {}
        # capture the args we're called with so tests can assert dispatch
        self.last_imports_call: tuple | None = None
        self.last_exports_call: tuple | None = None
        self.last_heaps_call: tuple | None = None

    async def mem_read(self, pid: int, address: int, size: int, space: str = "user",
                       allow_fault: bool = False) -> bytes:
        page = address & ~0xFFF
        blob = self.mem.get(page)
        if blob is None:
            raise RuntimeError(f"unreadable {hex(address)}")
        off = address - page
        return blob[off : off + size]

    async def mem_modules(self, pid: int, kernel: bool = False) -> list[dict]:
        return MODULES

    async def mem_imports(self, pid: int, module: str, kernel: bool = False) -> list[dict]:
        self.last_imports_call = (pid, module, kernel)
        return self.imports.get((pid, module), [])

    async def mem_exports(self, pid: int, module: str, kernel: bool = False) -> list[dict]:
        self.last_exports_call = (pid, module, kernel)
        return self.exports.get((pid, module), [])

    async def mem_heaps(self, pid: int, want_blocks: bool = False,
                        max_blocks: int = 0) -> list[dict]:
        self.last_heaps_call = (pid, want_blocks, max_blocks)
        return self.heaps.get(pid, [])


class MutableClient(FakeClient):
    """FakeClient whose backing memory can change between reads (memdiff)."""

    def poke(self, address: int, data: bytes) -> None:
        page = address & ~0xFFF
        blob = bytearray(self.mem.get(page, bytes(0x1000)))
        off = address - page
        blob[off : off + len(data)] = data
        self.mem[page] = bytes(blob)

    async def debug_regions(self, pid: int = 0) -> list[dict]:
        return [{"base": hex(p), "size": len(b), "state": 0x1000, "protect": 0x04,
                 "type": 0x20000, "module": ""} for p, b in self.mem.items()]


def test_parse_mask() -> None:
    pat, mask = parse_mask("4D 5A ?? 00")
    assert pat == b"\x4d\x5a\x00\x00"
    assert mask == "xx?x"


def test_parse_mask_nibble_wildcards() -> None:
    """'6?' pins the high nibble, '?F' the low — the pattern byte carries
    the fixed nibble and the mask char is 'H'/'L'."""
    pat, mask = parse_mask("4D 6? ?F ??")
    assert pat == b"\x4d\x60\x0f\x00"
    assert mask == "xHL?"

    pat, mask = parse_mask("F? ?f")
    assert pat == b"\xf0\x0f"
    assert mask == "HL"


def test_parse_mask_rejects_bad_tokens() -> None:
    for pat in ("4D GG 5A", "4D 123", "4D ?x"):
        with pytest.raises(SuspexError):
            parse_mask(pat)


def test_pattern_scan_exact_and_mask() -> None:
    data = b"ABCD ABCD ABCX ABCD"
    assert pattern_scan(data, b"ABCD") == [0, 5, 15]
    assert pattern_scan(data, b"ABC?", "xxx?") == [0, 5, 10, 15]
    with pytest.raises(SuspexError):
        pattern_scan(data, b"ABC", "xxxx")


def test_pattern_scan_nibble_masks() -> None:
    # '6?' (mask H): high nibble pinned at 6, low free.
    data = bytes([0x61, 0x6F, 0x70, 0x60])
    assert pattern_scan(data, b"\x60", "H") == [0, 1, 3]
    # '?F' (mask L): low nibble pinned at F.
    data = bytes([0x0F, 0x1F, 0x10, 0xFF])
    assert pattern_scan(data, b"\x0F", "L") == [0, 1, 3]
    # Mixed mask through the parsed form.
    data = bytes([0x4D, 0x63, 0xAF, 0x00,
                  0x4D, 0x99, 0xAF, 0x00,   # fails '6?' at byte 1
                  0x4D, 0x6A, 0xAF, 0x00])  # hit
    pat, mask = parse_mask("4D 6? ?F 00")
    assert pattern_scan(data, pat, mask) == [0, 8]


async def test_agent_pattern_scan_nibble_postfilter() -> None:
    """Whole-space scans with '6?'/'?F' downgrade the wire mask to '?' and
    re-verify candidates client-side via mem_read — correct on any agent
    vintage."""
    from suspex.sdk.scan import agent_pattern_scan

    class _C:
        def __init__(self):
            self.seen_mask = ""
            self.mem = {}

        async def mem_scan(self, pid, pattern, mask, base, size,
                           max_results, space):
            self.seen_mask = mask
            return [0x1000, 0x2000]

        async def mem_read(self, pid, addr, n, space, **kw):
            return self.mem[addr]

    c = _C()
    # 0x6? nibble hit at 0x1000 only — 0x2000's byte fails the nibble.
    c.mem[0x1000] = b"\x4d\x6f\x8f\x00"
    c.mem[0x2000] = b"\x4d\x70\x8f\x00"
    pat, mask = parse_mask("4D 6? ?F 00")
    hits = await agent_pattern_scan(c, 0, pat, mask, 0, 0, 64, "kernel")
    assert c.seen_mask == "x??x"     # H/L downgraded on the wire
    assert hits == [0x1000]          # nibble verified client-side


def test_reader_over_buffer() -> None:
    buf = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]) + b"hi\x00" + "wé".encode("utf-16-le") + b"\x00\x00"

    async def go() -> None:
        r = buffer_reader(buf)
        assert await r.u8(0) == 0x11
        assert await r.u16(1) == 0x3322
        assert await r.u32(2) == 0x66554433
        assert await r.u64(0) == int.from_bytes(buf[:8], "little")
        assert await r.cstr(8) == "hi"
        assert await r.wstr(11) == "wé"

    import asyncio

    asyncio.run(go())


def test_reader_range_check() -> None:
    async def go() -> None:
        r = buffer_reader(b"abc", base=0x1000)
        with pytest.raises(SuspexError):
            await r.u32(0x1002)

    import asyncio

    asyncio.run(go())


def test_parse_pe_and_rva() -> None:
    # minimal PE32+ image: DOS header, PE at 0x40, one section
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    buf[0x44:0x46] = (0x8664).to_bytes(2, "little")  # machine
    buf[0x46:0x48] = (1).to_bytes(2, "little")  # num sections
    buf[0x54:0x56] = (0xF0).to_bytes(2, "little")  # opt header size
    opt = 0x58
    buf[opt : opt + 2] = (0x20B).to_bytes(2, "little")  # PE32+
    buf[opt + 24 : opt + 32] = (0x140000000).to_bytes(8, "little")  # image base
    buf[opt + 56 : opt + 60] = (0x3000).to_bytes(4, "little")  # size of image
    sec = opt + 0xF0
    buf[sec : sec + 6] = b".text\0"
    buf[sec + 8 : sec + 12] = (0x2000).to_bytes(4, "little")  # vsize
    buf[sec + 12 : sec + 16] = (0x1000).to_bytes(4, "little")  # va
    buf[sec + 16 : sec + 20] = (0x2000).to_bytes(4, "little")  # raw size
    buf[sec + 20 : sec + 24] = (0x400).to_bytes(4, "little")  # raw ptr

    async def go() -> None:
        info = await parse_pe(buffer_reader(bytes(buf)), 0)
        assert info.machine == 0x8664
        assert info.image_base == 0x140000000
        assert info.size_of_image == 0x3000
        assert info.sections[0]["name"] == ".text"
        assert rva_to_offset(0x1234, info.sections) == 0x400 + 0x234
        assert rva_to_offset(0x9000, info.sections) is None

    import asyncio

    asyncio.run(go())


def _sdk(mem: dict[int, bytes]) -> SuspexSDK:
    return SuspexSDK(clients={"kernel": FakeClient(mem)})


async def test_mods_find() -> None:
    sdk = _sdk({})
    m = await sdk.mods.find("ntoskrnl.exe", kernel=True)
    assert m is not None and m["name"] == "ntoskrnl.exe"
    m = await sdk.mods.find("ci.dll", kernel=True)
    assert m is not None
    assert await sdk.mods.find("nope.dll", kernel=True) is None


async def test_mods_imports_dispatch_and_shape() -> None:
    client = FakeClient({})
    client.imports[(1234, "notepad.exe")] = [
        {"dll": "kernel32.dll", "name": "CreateFileW", "iat_slot": 0x100,
         "resolved": 0x200, "resolved_module": "KERNEL32.DLL", "hooked": False},
        {"dll": "kernel32.dll", "name": "WriteFile", "iat_slot": 0x108,
         "resolved": 0xDEAD, "resolved_module": "", "hooked": True},
    ]
    sdk = SuspexSDK(clients={"kernel": client})
    rows = await sdk.mods.imports(1234, "notepad.exe")
    assert client.last_imports_call == (1234, "notepad.exe", False)
    assert len(rows) == 2
    assert sum(1 for r in rows if r["hooked"]) == 1


async def test_mods_exports_dispatch() -> None:
    client = FakeClient({})
    client.exports[(0, "ntdll.dll")] = [
        {"name": "NtOpenFile", "ordinal": 0x2A, "rva": 0x1000,
         "address": 0x7FF000001000, "forwarder": ""},
    ]
    sdk = SuspexSDK(clients={"kernel": client})
    rows = await sdk.mods.exports(0, "ntdll.dll", kernel=True)
    assert client.last_exports_call == (0, "ntdll.dll", True)
    assert rows[0]["name"] == "NtOpenFile"


async def test_mem_heaps_dispatch() -> None:
    client = FakeClient({})
    client.heaps[999] = [
        {"handle": 0x140000, "base": 0x140000, "flags": 2,
         "committed": 0x10000, "reserved": 0x8000, "blocks": []},
    ]
    sdk = SuspexSDK(clients={"kernel": client})
    rows = await sdk.mem.heaps(999, want_blocks=True, max_blocks=32)
    assert client.last_heaps_call == (999, True, 32)
    assert rows[0]["base"] == 0x140000


async def test_mem_imports_via_user_view() -> None:
    # ModsApi.imports(view="user") must route to the "user" client, not kernel.
    kernel = FakeClient({})
    user = FakeClient({})
    user.imports[(7, "app.exe")] = [{"dll": "a.dll", "name": "X", "hooked": False}]
    sdk = SuspexSDK(clients={"kernel": kernel, "user": user})
    rows = await sdk.mods.imports(7, "app.exe", view="user")
    assert kernel.last_imports_call is None
    assert user.last_imports_call == (7, "app.exe", False)
    assert rows[0]["name"] == "X"


async def test_mem_view_dispatch_and_missing_view() -> None:
    sdk = _sdk({})
    assert sdk.mem.view().name == "kernel"
    with pytest.raises(SuspexError, match="user"):
        sdk.mem.view("user")


async def test_scan_range_chunking() -> None:
    page = bytes(0x1000)
    needle = b"\xde\xad\xbe\xef"
    blob = bytearray(page)
    blob[0x10:0x14] = needle
    blob[0xFE0:0xFE4] = needle  # near the end: exercises the overlap path
    mem = {0x1000: bytes(blob)}
    sdk = _sdk(mem)
    hits = await sdk.mem.scan_range(0, 0x1000, 0x1000, needle, chunk=0x800)
    assert hits == [0x1010, 0x1FE0]


async def test_scan_range_dedup_overlap() -> None:
    # pattern longer than the gap between copies must not double-report
    blob = bytearray(0x100)
    blob[0x10:0x18] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    sdk = _sdk({0x1000: bytes(blob)})
    hits = await sdk.mem.scan_range(0, 0x1000, 0x100, bytes.fromhex("0102030405060708"),
                                    chunk=0x40)
    assert hits == [0x1010]


async def test_parity_requires_both_views() -> None:
    sdk = _sdk({})
    with pytest.raises(SuspexError, match="both"):
        await sdk.parity(1)


async def test_findings_api(tmp_path) -> None:
    led = FindingsLedger(tmp_path / "f.db")
    sdk = SuspexSDK(clients={}, ledger=led)
    fid = sdk.findings.record("info", "t", "d", refs="test")
    eid = sdk.findings.evidence(fid, "note", "content")
    assert fid and eid
    assert [f.id for f in led.list_findings(None, None)] == [fid]
    led.close()


async def test_findings_api_without_ledger_raises() -> None:
    sdk = SuspexSDK(clients={})
    with pytest.raises(SuspexError, match="ledger"):
        sdk.findings.record("info", "t", "d")


async def test_scan_range_skips_holes() -> None:
    # second page missing: scan must continue into the third, not abort
    mem = {0x1000: bytes(0x1000), 0x3000: bytes.fromhex("deadbeef") + bytes(0x1000 - 4)}
    sdk = _sdk(mem)
    hits = await sdk.mem.scan_range(0, 0x1000, 0x3000, bytes.fromhex("deadbeef"),
                                    chunk=0x1000)
    assert hits == [0x3000]


async def test_snapshot_and_diff() -> None:
    client = MutableClient({0x1000: b"A" * 0x1000})
    sdk = SuspexSDK(clients={"kernel": client})
    snap = await sdk.mem.snapshot(0, [(0x1000, 0x1000)])
    assert len(snap) == 1
    assert list(snap.values())[0]["bytes"] == b"A" * 0x1000
    # no change -> empty diff
    assert await sdk.mem.diff(snap, 0) == []
    # mutate one dword -> exactly one changed range with offsets
    client.poke(0x1042, b"\x01\x02\x03\x04")
    changes = await sdk.mem.diff(snap, 0)
    assert len(changes) == 1
    assert changes[0]["range"] == "0x1000:0x1000"
    assert hex(0x42) in changes[0].get("changed_offsets", [])


async def test_snapshot_all_regions() -> None:
    client = MutableClient({0x1000: b"B" * 0x1000, 0x5000: b"C" * 0x800})
    sdk = SuspexSDK(clients={"kernel": client})
    snap = await sdk.mem.snapshot(0)  # no ranges: walk regions
    assert len(snap) == 2


def test_yara_module_graceful_without_dep() -> None:
    from suspex import yara as yara_mod

    if yara_mod.yara_available():
        hits = yara_mod.yara_scan_blob(b"suspex0-yara-selftest", """
            rule marker {
                strings: $a = "suspex0-yara-selftest"
                condition: $a
            }
        """)
        assert hits and hits[0]["rule"] == "marker"
    else:
        assert yara_mod.yara_available() is False
        with pytest.raises(RuntimeError, match="yara-python"):
            yara_mod.compile_source("rule x { condition: true }")
