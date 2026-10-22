"""Offline tests for the driver_trace_scan plugin
(plugins/driver_trace_scan).

Feeds a synthetic kernel-memory image (MmUnloadedDrivers array, PiDDB flat
list, ci HASH_BUCKET_ENTRY chain) through a fake SDK and asserts the walkers
parse layouts, probe strides, flag stale names, and degrade gracefully on a
broken chain - no target contact, no driver.
"""
from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

from suspex.sdk import SuspexError

_PLUGIN_RUN = (Path(__file__).resolve().parents[2] / "plugins"
               / "driver_trace_scan" / "run.py")

_NT_BASE = 0xFFFF800000400000
_CI_BASE = 0xFFFF800000500000
_ARENA = 0xFFFF800002000000  # wide-string buffer arena
_STRIDE = 0x28

# PiDDB synthetic: classic 0x20-byte RTL_BALANCED_LINKS (Parent/Left/Right/
# Balance) with the entry payload at +0x20 (verified live on 26200: count at
# table+0x2C, payload VA == the VA the flat list chains)
_N1 = _NT_BASE + 0x13000
_N2 = _NT_BASE + 0x13100
_N3 = _NT_BASE + 0x13200
_E1 = _N1 + 0x20
_E2 = _N2 + 0x20
_E3 = _N3 + 0x20


def _load_plugin():
    spec = importlib.util.spec_from_file_location("driver_trace_scan_run", _PLUGIN_RUN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeMem:
    """Sparse kernel memory; unreadable addresses raise SuspexError like the
    real agent surface (Reader.wstr settles for partial decodes on it).
    Regions are keyed by start address - putting at an existing start replaces."""

    def __init__(self) -> None:
        self.regions: dict[int, bytes] = {}

    def put(self, start: int, data: bytes) -> None:
        self.regions[start] = bytes(data)

    async def read(self, pid, addr, size, space="user", view="", allow_fault=False):
        for s, d in self.regions.items():
            if s <= addr and addr + size <= s + len(d):
                off = addr - s
                return d[off:off + size]
        raise SuspexError(f"INVALID_ADDRESS at {addr:#x} size {size:#x}")


class _FakeMods:
    def __init__(self, mods: dict) -> None:
        self.mods = mods

    async def find(self, name, pid=0, kernel=False, view=""):
        return self.mods.get(str(name).lower())


class _FakeSymbols:
    def __init__(self, rvas: dict) -> None:
        self.rvas = rvas  # {binary filename lower: {symbol: rva}}

    def resolve(self, binary_path: str, names: list[str]) -> dict:
        table = self.rvas.get(Path(binary_path).name.lower(), {})
        found = {n: table[n] for n in names if n in table}
        if not found:
            raise RuntimeError(f"SymbolError: none of {names} in {binary_path}")
        return found


class _FakeSDK:
    def __init__(self, mem: _FakeMem, mods: dict, rvas: dict, build: int = 26200):
        self.mem = mem
        self.mods = _FakeMods(mods)
        self.symbols = _FakeSymbols(rvas)
        self.nt_build = build


def _ustr_hdr(name: str, buf_addr: int) -> bytes:
    raw = name.encode("utf-16-le")
    return struct.pack("<HH4xQ", len(raw), len(raw) + 2, buf_addr)


def _build_sdk(mm_deref: bool = True, piddb_tampered: bool = False):
    """Synthetic kernel image covering all three structures."""
    mod = _load_plugin()
    mem = _FakeMem()
    next_buf = _ARENA

    def wbuf(s: str) -> int:
        nonlocal next_buf
        addr = next_buf
        # pad to the arena slot size: wstr reads 64-byte chunks, so the whole
        # chunk from the buffer start must stay inside one mapped region
        mem.put(addr, s.encode("utf-16-le") + b"\x00\x00" + b"\xEE" * (0x100 - len(s) * 2 - 2))
        next_buf += 0x100
        return addr

    # --- nt!MmUnloadedDrivers: 50-slot array; symbol is a POINTER on 24H2+ ---
    arr = _NT_BASE + 0x10000

    def mm_slot(name: str | None, start: int, end: int, t: int) -> bytes:
        b = bytearray(_STRIDE)
        if name is not None:
            b[0:16] = _ustr_hdr(name, wbuf(name))
        struct.pack_into("<QQQ", b, 0x10, start, end, t)
        return bytes(b)

    slots = (mm_slot("acpi.sys", 0xFFFF800001000000, 0xFFFF800001002000, 0x11AA22BB)
             + b"\x00" * _STRIDE
             + mm_slot("suspex_probe.sys", 0xFFFF800001100000, 0xFFFF800001103000, 0x22BB33CC)
             + b"\x00" * (_STRIDE * 47))
    if mm_deref:
        mem.put(_NT_BASE + 0x1000, struct.pack("<Q", arr))  # MmUnloadedDrivers (ptr)
    else:
        arr = _NT_BASE + 0x1000  # older builds: the symbol IS the array
    mem.put(arr, slots)
    mem.put(_NT_BASE + 0xFF8, struct.pack("<I", 3))         # MmLastUnloadedDriver

    # --- nt!PiDDBCacheTable (AVL) + nt!PiDDBCacheList (flat chain) over the
    #     SAME payloads. Live-verified 26200 layout: classic 0x20-byte
    #     RTL_BALANCED_LINKS, entry payload at +0x20; entry = List@0x00,
    #     pad qword@0x10, DriverName@0x18, TS@0x28, Status@0x2C;
    #     NumberGenericTableElements at table+0x2C. ---
    table = _NT_BASE + 0x2000
    head = _NT_BASE + 0x2100

    def avl_node(left: int, right: int, payload: bytes) -> bytes:
        b = bytearray(0x50)
        struct.pack_into("<QQQ", b, 0x00, table, left, right)
        b[0x18] = 0  # Balance + pad
        b[0x20:0x50] = payload
        return bytes(b)

    def piddb_entry(flink: int, blink: int, name: str | None, ts: int,
                    status: int) -> bytes:
        b = bytearray(0x30)
        struct.pack_into("<QQ", b, 0x00, flink, blink)   # List (flat chain)
        struct.pack_into("<Q", b, 0x10, 0x99)            # build-specific extra qword
        if name is not None:
            b[0x18:0x28] = _ustr_hdr(name, wbuf(name))
        struct.pack_into("<II", b, 0x28, ts, status)
        return bytes(b)

    if piddb_tampered:
        # tampered: n3 lives in the tree only (unlinked from the flat list,
        # count decremented) and e2 was sanitized in place (zeroed name + ts)
        mem.put(_N1, avl_node(0, _N3, piddb_entry(_E2, head, "acpi.sys", 0x5A000001, 0)))
        mem.put(_N2, avl_node(0, 0, piddb_entry(head, _E1, None, 0, 0)))
        mem.put(_N3, avl_node(0, 0, piddb_entry(0, 0, "orphan.sys", 0x5A000003, 0)))
    else:
        mem.put(_N1, avl_node(0, 0, piddb_entry(_E2, head, "acpi.sys", 0x5A000001, 0)))
        mem.put(_N2, avl_node(0, 0,
                              piddb_entry(head, _E1, "suspex_ghost.sys",
                                          0x5A000002, 0xC0000603)))
    mem.put(table + 0x08, struct.pack("<QQ", _N1, _N2))  # BalancedRoot children
    mem.put(table + 0x24, struct.pack("<I", 0))          # (0x18-node count slot: empty)
    mem.put(table + 0x2C, struct.pack("<I", 2))          # NumberGenericTableElements
    mem.put(head, struct.pack("<QQ", _E1, _E2))

    # --- nt!PsLoadedModuleList: InLoadOrderLinks of KLDR_DATA_TABLE_ENTRY ---
    ldr_head = _NT_BASE + 0x2200
    l1 = _NT_BASE + 0x12000
    l2 = _NT_BASE + 0x12100

    def ldr_entry(flink: int, blink: int, dll_base: int, ep: int, size: int,
                  full: str | None, base: str | None) -> bytes:
        # 0x80 bytes: the scanner reads a _LDR_ENTRY_WINDOW=0x80 window per
        # entry (SectionPointer sits at +0x70); a 0x70-byte region makes the
        # sparse fake memory raise on the window read.
        b = bytearray(0x80)
        struct.pack_into("<QQ", b, 0x00, flink, blink)
        struct.pack_into("<QQI", b, 0x30, dll_base, ep, size)
        for at, nm in ((0x48, full), (0x58, base)):
            if nm is not None:
                b[at:at + 16] = _ustr_hdr(nm, wbuf(nm))
        return bytes(b)

    mem.put(ldr_head, struct.pack("<QQ", l1, l2))
    mem.put(l1, ldr_entry(l2, ldr_head, 0xFFFF800001000000, 0xFFFF800001001000,
                          0x5000, r"\SystemRoot\System32\drivers\acpi.sys",
                          "acpi.sys"))
    # BaseDllName zeroed (cleaned) - name falls back to FullDllName's filename
    mem.put(l2, ldr_entry(ldr_head, l1, 0xFFFF800001100000, 0xFFFF800001101000,
                          0x3000, r"\??\C:\Windows\Temp\suspex_hidden.sys", None))

    # --- ci!g_KernelHashBucketList: singly-linked HASH_BUCKET_ENTRY chain ---
    g_list = _CI_BASE + 0x3000
    c1 = _CI_BASE + 0x4000
    c2 = _CI_BASE + 0x4040

    def ci_entry(nxt: int, name: str, certhash: bytes) -> bytes:
        b = bytearray(0x30)
        struct.pack_into("<Q", b, 0x00, nxt)
        b[0x08:0x18] = _ustr_hdr(name, wbuf(name))
        b[0x18:0x2C] = certhash
        return bytes(b)

    mem.put(g_list, struct.pack("<Q", c1))
    mem.put(c1, ci_entry(c2, "acpi.sys", b"\xAA" * 20))
    mem.put(c2, ci_entry(0, "suspex_mapped.sys", b"\xBB" * 20))

    sdk = _FakeSDK(
        mem,
        mods={
            "ntoskrnl.exe": {"base": _NT_BASE, "size": 0x800000},
            "ci.dll": {"base": _CI_BASE, "size": 0x200000},
        },
        rvas={
            "ntoskrnl.exe": {
                "MmUnloadedDrivers": 0x1000,
                "MmLastUnloadedDriver": 0xFF8,
                "PiDDBCacheTable": 0x2000,
                "PiDDBCacheList": 0x2100,
                "PsLoadedModuleList": 0x2200,
            },
            "ci.dll": {"g_KernelHashBucketList": 0x3000},
        },
    )
    return mod, sdk


_PARAMS = {"recipe": "all", "source": "auto", "name_filter": "suspex",
           "max_entries": 100, "binary_path_nt": "", "binary_path_ci": ""}


async def test_all_structures_enumerated_and_flagged() -> None:
    mod, sdk = _build_sdk()
    res = await mod.run(sdk, dict(_PARAMS))

    assert res["ok"] is True
    assert res["stale_total"] == 4
    assert res["severity"] == "warning"

    ldr = res["results"]["ps_loaded_module_list"]
    assert ldr["status"] == "scanned"
    assert [e["name"] for e in ldr["entries"]] == ["acpi.sys", "suspex_hidden.sys"]
    assert ldr["entries"][0]["size_of_image"] == 0x5000
    assert ldr["entries"][1]["base_dll_name"] == ""     # zeroed by a cleaner
    assert ldr["entries"][1]["full_dll_name"] == r"\??\C:\Windows\Temp\suspex_hidden.sys"
    assert ldr["meta"]["broken"] is None
    assert len(ldr["stale"]) == 1

    mm = res["results"]["mm_unloaded_drivers"]
    assert mm["status"] == "scanned"
    assert mm["meta"]["stride"] == hex(_STRIDE)
    assert mm["meta"]["dereferenced"] is True      # 24H2-style pointer global
    assert mm["meta"]["last_index"] == 3
    assert [e["name"] for e in mm["entries"]] == ["acpi.sys", "suspex_probe.sys"]
    assert mm["stale"][0]["index"] == 2
    assert "unload_time" in mm["entries"][0]       # stride >= 0x28 carries time

    pd = res["results"]["pidddb_cache_table"]
    assert pd["status"] == "scanned"
    assert pd["source"] == "pdb_list"
    assert pd["meta"]["layout"]["name_at"] == hex(0x18)   # probed 26200 layout
    assert pd["meta"]["table_elements"] == 2
    assert pd["meta"]["count_at"] == hex(0x2C)
    assert [e["name"] for e in pd["entries"]] == ["acpi.sys", "suspex_ghost.sys"]
    assert pd["entries"][1]["status"] == hex(0xC0000603)
    assert len(pd["stale"]) == 1

    ci = res["results"]["ci_hash_bucket_list"]
    assert ci["status"] == "scanned"
    assert ci["source"] == "pdb"
    assert [e["name"] for e in ci["entries"]] == ["acpi.sys", "suspex_mapped.sys"]
    assert ci["entries"][0]["certhash"] == "aa" * 20
    assert len(ci["stale"]) == 1

    sync = res["results"]["piddb_tamper_check"]
    assert sync["status"] == "scanned"
    assert sync["meta"]["verdict"] == "consistent"
    assert sync["meta"]["tampered"] is False
    assert sync["meta"]["details"]["tree_nodes"] == 2
    assert sync["severity"] == "info"


async def test_mm_direct_array_build() -> None:
    mod, sdk = _build_sdk(mm_deref=False)
    res = await mod.run(sdk, dict(_PARAMS))
    mm = res["results"]["mm_unloaded_drivers"]
    assert mm["status"] == "scanned"
    assert mm["meta"]["array_source"] == "direct"
    assert mm["meta"]["stride"] == hex(_STRIDE)
    assert [e["name"] for e in mm["entries"]] == ["acpi.sys", "suspex_probe.sys"]


async def test_piddb_broken_chain_degrades() -> None:
    mod, sdk = _build_sdk()
    # rebuild n2 with a corrupt payload Blink so the integrity check trips
    b = bytearray(sdk.mem.regions[_N2])
    struct.pack_into("<Q", b, 0x20 + 0x08, 0xDEADBEEF)
    sdk.mem.put(_N2, bytes(b))
    res = await mod.run(sdk, dict(_PARAMS))

    pd = res["results"]["pidddb_cache_table"]
    assert pd["status"] == "scanned"
    assert pd["meta"]["broken"] == "blink mismatch"
    assert len(pd["entries"]) == 1                 # e1 parsed, walk stops
    assert res["ok"] is True                       # degraded, not failed


async def test_piddb_tamper_detected() -> None:
    mod, sdk = _build_sdk(piddb_tampered=True)
    res = await mod.run(sdk, {**_PARAMS, "recipe": "piddb_tamper_check"})

    sync = res["results"]["piddb_tamper_check"]
    assert sync["status"] == "scanned"
    assert sync["meta"]["verdict"] == "TAMPERED"
    assert sync["meta"]["tampered"] is True
    assert sync["severity"] == "high"              # structural divergence
    d = sync["meta"]["details"]
    assert d["tree_nodes"] == 3 and d["list_entries"] == 2
    assert d["node_size"] == hex(0x20)
    assert d["tree_only_orphans"] == [hex(_E3)]    # unlinked from the list only
    assert d["count_mismatch"] == {"stored": 2, "actual_tree": 3}
    assert any(s["entry"] == hex(_E2) for s in d["sanitized"])
    assert res["severity"] == "high"


async def test_single_recipe_scoped() -> None:
    mod, sdk = _build_sdk()
    res = await mod.run(sdk, {**_PARAMS, "recipe": "ci_hash_bucket_list"})
    assert list(res["results"]) == ["ci_hash_bucket_list"]
    assert res["stale_total"] == 1
