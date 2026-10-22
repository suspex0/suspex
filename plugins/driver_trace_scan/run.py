"""driver_trace_scan - enumerate the kernel's driver load/unload trace
structures in one read-only pass:

  * nt!PsLoadedModuleList      InLoadOrderLinks of KLDR_DATA_TABLE_ENTRY -
                               what is loaded RIGHT NOW (a manually mapped
                               driver is typically unlinked from here)
  * nt!MmUnloadedDrivers       50-slot ring of loaded-then-unloaded drivers
                               (_MI_UNLOADED_DRIVER: Name/Start/End[/Time])
  * nt!PiDDBCacheTable         PiDDB cache of every driver image the PnP
                               manager verified this boot (RTL_AVL_TABLE +
                               the flat nt!PiDDBCacheList chain)
  * piddb_tamper_check         sync check across BOTH PiDDB structures:
                               tree/list divergence, element-count drift and
                               sanitized (zeroed name/ts) entries expose
                               post-hoc tampering of the cache
  * ci!g_KernelHashBucketList  singly-linked HASH_BUCKET_ENTRY chain of hashed
                               kernel images kept by code integrity

A manually mapped driver never appears in PsLoadedModuleList, but its
(re)load/unload activity still lands in the three structures above - this
plugin makes those traces visible for unload-hygiene checks of OUR OWN
test drivers.

Structure layouts (cross-checked against public references incl.
TheCruZ/kdmapper and a kclean-style port):
  MmUnloadedDrivers entry: Name@0x00 Start@0x10 End@0x18 CurrentTime@0x20
    (stride 0x20 on Win10/21H2, 0x28 on 22H2+; the PDB symbol may be a
     POINTER to the array on 24H2+ - probed, not assumed)
  PiDDB flat entry: List@0x00 DriverName@0x10 TS@0x20 Status@0x24 (26100)
    (26200+ gains a QWORD after List -> Name@0x18 TS@0x28 - layout probed)
  ci HASH_BUCKET_ENTRY: Next@0x00 Name@0x08 Buffer@0x10 CertHash[5]@0x18

Symbol addresses come from the build PDB via sdk.symbols.resolve; per-build
pattern recipes live in _patterns.yaml (the ci.dll PAGE pattern is a legacy
fallback and is expected absent on 26100+ - PDB is the working path).

Everything is read-only; kernel reads run with allow_fault=False so bad VAs
surface as clean errors instead of bugchecks.
"""
from __future__ import annotations

import json
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from suspex.sdk import Reader, SuspexError, parse_mask, parse_pe, pattern_scan

_PATTERNS = Path(__file__).resolve().parents[1] / "_patterns.yaml"

_KVA_MIN = 0xFFFF800000000000

# _MI_UNLOADED_DRIVER field offsets (entry-relative)
_MM_NAME_AT = 0x00
_MM_START_AT = 0x10
_MM_END_AT = 0x18
_MM_TIME_AT = 0x20
_MM_DEFAULT_STRIDES = (0x20, 0x28, 0x30)
_MM_MAX_SLOTS = 50

# PiDDB flat-entry layout candidates: (name_ustr_at, timestamp_at, status_at)
_PIDDB_LAYOUTS = ((0x10, 0x20, 0x24), (0x18, 0x28, 0x2C))
_PIDDB_ENTRY_WINDOW = 0x30

# ci HASH_BUCKET_ENTRY field offsets (entry-relative)
_CI_NAME_AT = 0x08
_CI_CERTHASH_AT = 0x18
_CI_CERTHASH_SIZE = 20
_CI_ENTRY_WINDOW = 0x30
_CI_MAX_SLOTS = 512

# KLDR_DATA_TABLE_ENTRY field offsets (entry-relative, x64; stable since Vista)
_LDR_BASE_AT = 0x30
_LDR_ENTRYPOINT_AT = 0x38
_LDR_SIZEOFIMAGE_AT = 0x40
_LDR_FULLNAME_AT = 0x48
_LDR_BASENAME_AT = 0x58
_LDR_FLAGS_AT = 0x68
_LDR_SIG_AT = 0x6E          # u1: SignatureLevel:4 | SignatureType:3 | unused:9
_LDR_SECTION_AT = 0x70      # SectionPointer -> _SECTION (NULL for boot images)
_LDR_CHECKSUM_AT = 0x78
_LDR_ENTRY_WINDOW = 0x80
_LDR_MAX_ENTRIES = 1024

# SectionPointer provenance chain, verified live on build 26200:
#   _SECTION uses the RTL_BALANCED_NODE layout -> ControlArea at +0x28
#   (older builds used the classic union layout -> ControlArea at +0x18;
#    both candidates are probed and the tail stages validate which hit)
#   _CONTROL_AREA.FilePointer @ +0x40 is an EX_FAST_REF (FILE_OBJECT = ptr & ~0xF)
#   _FILE_OBJECT.FileName @ +0x58 (UNICODE_STRING)
_SECTION_CA_OFFSETS = (0x28, 0x18, 0x30)
_SECTION_WINDOW = 0x48
_CA_FILEPTR_AT = 0x40
_CA_WINDOW = 0x50
_FO_FILENAME_AT = 0x58
_FO_WINDOW = 0x68

_PDB_NAMES = {
    "ps_loaded_module_list": ["PsLoadedModuleList"],
    "piddb_tamper_check": ["PiDDBCacheTable", "PiDDBCacheList"],
    "mm_unloaded_drivers": ["MmUnloadedDrivers", "MmLastUnloadedDriver",
                            "MmUnloadedDriversIndex"],
    "pidddb_cache_table": ["PiDDBCacheTable", "PiDDBCacheList"],
    "ci_hash_bucket_list": ["g_KernelHashBucketList"],
}

_DEFAULT_RECIPES = {
    "ps_loaded_module_list": {
        "module": "ntoskrnl.exe",
        "max_entries": _LDR_MAX_ENTRIES,
    },
    "mm_unloaded_drivers": {
        "module": "ntoskrnl.exe",
        "strides": [0x20, 0x28, 0x30],
        "max_entries": _MM_MAX_SLOTS,
    },
    "pidddb_cache_table": {
        "module": "ntoskrnl.exe",
        "layouts": [list(x) for x in _PIDDB_LAYOUTS],
        "max_entries": 4096,
    },
    "piddb_tamper_check": {
        "module": "ntoskrnl.exe",
        "layouts": [list(x) for x in _PIDDB_LAYOUTS],
        "max_entries": 4096,
    },
    "ci_hash_bucket_list": {
        "module": "ci.dll",
        "pattern": "48 8B 1D ?? ?? ?? ?? EB ?? F7 43 40 00 20 00 00",
        "mask": "xxx????x?xxxxxxx",
        "max_entries": _CI_MAX_SLOTS,
        "name_ustr_at": _CI_NAME_AT,
        "certhash_at": _CI_CERTHASH_AT,
    },
}

_SCANNERS = {}


def _scanner(name):
    def deco(fn):
        _SCANNERS[name] = fn
        return fn
    return deco


def _u64(v) -> int:
    return int(v, 0) if isinstance(v, str) else int(v)


def _overlay(dst: dict, src: dict) -> dict:
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _overlay(dst[k], v)
        else:
            dst[k] = v
    return dst


def _recipe_for(sdk, name: str) -> dict:
    raw = yaml.safe_load(_PATTERNS.read_text(encoding="utf-8")) or {}
    data = {str(k): v for k, v in raw.items()}  # YAML reads 26200: as an int key
    build = str(sdk.nt_build or 0)
    recipe = dict(_DEFAULT_RECIPES.get(name, {}))
    _overlay(recipe, (data.get(build) or {}).get(name) or {})
    _overlay(recipe, (data.get("default") or {}).get(name) or {})
    return recipe


def _sys32(module: str) -> str:
    return "C:\\Windows\\System32\\" + module


def _kr(sdk) -> Reader:
    return Reader(lambda addr, n: sdk.mem.read(0, addr, n, space="kernel",
                                               view="kernel"))


async def _try(r: Reader, addr: int, size: int) -> bytes | None:
    try:
        data = await r.read(addr, size)
    except Exception:
        return None
    return data if data and len(data) >= size else None


async def _try_u16(r, addr) -> int | None:
    raw = await _try(r, addr, 2)
    return struct.unpack("<H", raw)[0] if raw else None


async def _try_u32(r, addr) -> int | None:
    raw = await _try(r, addr, 4)
    return struct.unpack("<I", raw)[0] if raw else None


async def _try_u64(r, addr) -> int | None:
    raw = await _try(r, addr, 8)
    return struct.unpack("<Q", raw)[0] if raw else None


def _ustr(raw: bytes, at: int) -> tuple[int, int, int]:
    """(Length, MaximumLength, Buffer) of a UNICODE_STRING inside a window."""
    ln, mx = struct.unpack_from("<HH", raw, at)
    buf = struct.unpack_from("<Q", raw, at + 8)[0]
    return ln, mx, buf


def _ustr_state(ln: int, mx: int, buf: int) -> str:
    """empty | ok | bad - shape classification for a UNICODE_STRING read."""
    if ln == 0 and mx == 0 and buf == 0:
        return "empty"
    if ln > 0x1000 or ln > mx or buf < _KVA_MIN:
        return "bad"
    return "ok"


async def _name_of(r: Reader, buf: int, length: int) -> str | None:
    try:
        return await r.wstr(buf, max(1, length // 2) + 1)
    except Exception:
        return None


def _flag(e: dict, filt: str) -> bool:
    return bool(filt) and filt in str(e.get("name") or "").lower()


def _resolve_symbols(sdk, params, recipe: dict, name: str, binary_param: str):
    # union: per-build recipe names win for priority, but never drop the
    # structure's full symbol set (e.g. the 26200 recipe lists only
    # PiDDBCacheTable - PiDDBCacheList stays resolvable for the flat walk)
    wanted = list(dict.fromkeys(
        list(recipe.get("pdb") or []) + list(_PDB_NAMES[name])))
    binary = params.get(binary_param) or _sys32(str(recipe["module"]))
    rvas = sdk.symbols.resolve(binary, wanted)  # SymbolError if unavailable
    if not rvas:
        raise SuspexError(f"none of {wanted} found in the PDB for {binary}")
    return rvas


async def _kernel_module(sdk, recipe):
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    return _u64(mod["base"]), _u64(mod["size"])


# ---------------------------------------------------------------- mm ----

def _score_mm_window(window: bytes, stride: int, slots: int) -> int:
    score = 0
    for i in range(slots):
        off = i * stride
        if off + stride > len(window):
            break
        ln, mx, buf = _ustr(window, off + _MM_NAME_AT)
        if ln and _ustr_state(ln, mx, buf) == "ok":
            score += 1
    return score


@_scanner("mm_unloaded_drivers")
async def _scan_mm(sdk, params: dict, recipe: dict) -> dict:
    if params["source"] == "patterns":
        return {"status": "no_recipe",
                "note": "no verified pattern recipe for MmUnloadedDrivers - use source=auto/pdb"}
    r = _kr(sdk)
    rvas = _resolve_symbols(sdk, params, recipe, "mm_unloaded_drivers",
                            "binary_path_nt")
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    symbols = {k: hex(v + base) for k, v in rvas.items()}

    sym = base + rvas["MmUnloadedDrivers"]
    last_index = None
    for nm in ("MmLastUnloadedDriver", "MmUnloadedDriversIndex"):
        if nm in rvas:
            v = await _try_u32(r, base + rvas[nm])
            if v is not None and v <= 2 * _MM_MAX_SLOTS:
                last_index = v
            break

    strides = [_u64(s) for s in (recipe.get("strides") or _MM_DEFAULT_STRIDES)]
    max_slots = min(_u64(recipe.get("max_entries") or _MM_MAX_SLOTS),
                    _MM_MAX_SLOTS, params["max_entries"])

    # 24H2+ keeps a pointer variable at the symbol; older builds put the
    # array right there. Probe both, let valid-entry count decide.
    candidates = [("direct", sym)]
    deref = await _try_u64(r, sym)
    if deref and deref >= _KVA_MIN and deref != sym:
        candidates.append(("deref", deref))

    best = None  # (score, array, stride, kind, window)
    for kind, arr in candidates:
        for stride in strides:
            window = await _try(r, arr, stride * max_slots)
            if window is None:
                continue
            score = _score_mm_window(window, stride, max_slots)
            if best is None or score > best[0]:
                best = (score, arr, stride, kind, window)
    if best is None:
        return {"status": "not_found", "source": "pdb", "symbols": symbols,
                "note": "symbol resolved but no readable window at direct/deref VA"}

    score, array, stride, kind, window = best
    time_at = _MM_TIME_AT if stride > _MM_TIME_AT else None
    entries, empty_slots, bad_slots = [], 0, 0
    for i in range(max_slots):
        off = i * stride
        raw = window[off:off + stride]
        if len(raw) < stride:
            break
        ln, mx, buf = _ustr(raw, _MM_NAME_AT)
        state = _ustr_state(ln, mx, buf)
        if state == "empty":
            empty_slots += 1
            continue
        if state == "bad":
            bad_slots += 1
            continue
        start = struct.unpack_from("<Q", raw, _MM_START_AT)[0]
        end = struct.unpack_from("<Q", raw, _MM_END_AT)[0]
        item = {"index": i, "name": await _name_of(r, buf, ln) or "",
                "name_len": ln, "start": hex(start), "end": hex(end)}
        if time_at is not None and stride >= time_at + 8:
            item["unload_time"] = hex(struct.unpack_from("<Q", raw, time_at)[0])
        entries.append(item)

    filt = str(params["name_filter"]).lower()
    stale = [e for e in entries if _flag(e, filt)]
    meta = {"array": hex(array), "stride": hex(stride), "array_source": kind,
            "stride_score": score, "empty_slots": empty_slots,
            "bad_slots": bad_slots, "last_index": last_index,
            "dereferenced": kind == "deref"}
    return {"status": "scanned", "source": "pdb", "symbols": symbols,
            "meta": meta, "entries": entries, "stale": stale,
            "summary": f"{len(entries)} entries, stride {stride:#x} ({kind}), "
                       f"{bad_slots} bad slots"}


# ------------------------------------------------------------- pidddb ----

def _piddb_entry(raw: bytes, lay: tuple[int, ...]) -> dict:
    ln, mx, buf = _ustr(raw, lay[0])
    e = {"name_len": ln, "state": _ustr_state(ln, mx, buf)}
    if len(lay) > 1:
        e["timestamp"] = struct.unpack_from("<I", raw, lay[1])[0]
    if len(lay) > 2 and len(raw) >= lay[2] + 4:
        e["status"] = struct.unpack_from("<I", raw, lay[2])[0]
    return e


def _layout_score(raws: list[bytes], lay: tuple[int, ...]) -> tuple[int, int]:
    """(informative, shape_ok) - informative = named entry with real-looking ts.
    Fields are computed per-layout from the raw windows, never pre-parsed."""
    informative = shape_ok = 0
    for raw in raws:
        ln, mx, buf = _ustr(raw, lay[0])
        state = _ustr_state(ln, mx, buf)
        if state == "bad":
            continue
        shape_ok += 1
        ts = struct.unpack_from("<I", raw, lay[1])[0] if len(raw) >= lay[1] + 4 else 0
        if state == "ok" and ln and ts:
            informative += 1
    return informative, shape_ok


async def _walk_piddb_list(r: Reader, head: int, layouts, max_slots: int):
    flink = await _try_u64(r, head)
    if flink is None:
        return [], layouts[0], "head unreadable", 0, []

    # layout probe over the first few reachable entries
    probes = []
    cur, prev = flink, head
    for _ in range(5):
        if not cur or cur == head or cur < _KVA_MIN:
            break
        raw = await _try(r, cur, _PIDDB_ENTRY_WINDOW)
        if raw is None:
            break
        probes.append(raw)
        cur = struct.unpack_from("<Q", raw, 0)[0]
    best_lay, best_key = layouts[0], (-1, -1)
    for lay in layouts:
        key = _layout_score(probes, lay)
        if key > best_key:
            best_lay, best_key = lay, key

    lay = best_lay
    entries, walked, broken = [], 0, None
    vas: list[int] = []
    cur, prev, seen = flink, head, set()
    while cur and cur != head and walked < max_slots:
        if cur < _KVA_MIN:
            broken = "non-kernel flink"
            break
        if cur in seen:
            broken = "flink loop"
            break
        seen.add(cur)
        raw = await _try(r, cur, _PIDDB_ENTRY_WINDOW)
        if raw is None:
            broken = "unreadable entry"
            break
        back = struct.unpack_from("<Q", raw, 8)[0]
        if back != prev:
            broken = "blink mismatch"
            break
        nxt = struct.unpack_from("<Q", raw, 0)[0]
        e = _piddb_entry(raw, lay)
        ln, mx, buf = _ustr(raw, lay[0])
        item = {"entry": hex(cur),
                "name": (await _name_of(r, buf, ln) or "") if e["state"] == "ok" else "",
                "name_len": ln,
                "timestamp": hex(e.get("timestamp", 0))}
        if "status" in e:
            item["status"] = hex(e["status"])
        entries.append(item)
        vas.append(cur)
        prev, cur = cur, nxt
        walked += 1
    return entries, lay, broken, walked, vas


async def _walk_piddb_avl(r: Reader, table: int, layouts, max_slots: int):
    """Fallback when PiDDBCacheList is absent from the PDB: walk the AVL tree
    via the calibrated collector (see _collect_piddb_tree for node sizing)."""
    nodes, node_size, broken = await _collect_piddb_tree(r, table, layouts,
                                                         max_slots)
    entries = [{"node": n["node"], "name": n["name"], "timestamp": n["timestamp"]}
               for n in nodes.values()]
    return entries, node_size, broken


@_scanner("pidddb_cache_table")
async def _scan_piddb(sdk, params: dict, recipe: dict) -> dict:
    if params["source"] == "patterns":
        return {"status": "no_recipe",
                "note": "no verified pattern recipe for PiDDBCacheTable - use source=auto/pdb or the pidddb_scan plugin"}
    r = _kr(sdk)
    rvas = _resolve_symbols(sdk, params, recipe, "pidddb_cache_table",
                            "binary_path_nt")
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    symbols = {k: hex(v + base) for k, v in rvas.items()}
    layouts = [tuple(_u64(x) for x in lay)
               for lay in (recipe.get("layouts") or _PIDDB_LAYOUTS)]
    max_slots = min(_u64(recipe.get("max_entries") or 4096), params["max_entries"])

    table_va = base + rvas["PiDDBCacheTable"] if "PiDDBCacheTable" in rvas else None
    list_va = base + rvas["PiDDBCacheList"] if "PiDDBCacheList" in rvas else None

    notes: list[str] = []
    if list_va is not None:
        source = "pdb_list"
        entries, lay, broken, walked, _vas = await _walk_piddb_list(
            r, list_va, layouts, max_slots)
        meta = {"head": hex(list_va),
                "layout": {"name_at": hex(lay[0]), "timestamp_at": hex(lay[1]),
                           "status_at": hex(lay[2]) if len(lay) > 2 else None},
                "walked": walked, "broken": broken}
    elif table_va is not None:
        source = "pdb_avl"
        entries, node_size, broken = await _walk_piddb_avl(
            r, table_va, layouts, max_slots)
        notes.append("PiDDBCacheList not in PDB - used AVL tree walk")
        meta = {"table": hex(table_va), "node_size": hex(node_size),
                "broken": broken}
    else:
        raise SuspexError("neither PiDDBCacheTable nor PiDDBCacheList in PDB")

    if table_va is not None:
        for off in (0x24, 0x2C):  # NumberGenericTableElements (0x18 vs 0x20 node)
            v = await _try_u32(r, table_va + off)
            if v is not None and 0 < v <= 100000:
                meta["table_elements"] = v
                meta["count_at"] = hex(off)
                break

    filt = str(params["name_filter"]).lower()
    stale = [e for e in entries if _flag(e, filt)]
    return {"status": "scanned", "source": source, "symbols": symbols,
            "meta": meta, "entries": entries, "stale": stale, "notes": notes,
            "summary": f"{len(entries)} entries via {source}"
                       + (f", broken: {broken}" if broken else "")}


async def _collect_piddb_tree(r: Reader, table_va: int, layouts, max_slots: int,
                              list_vas: set[int] | None = None):
    """Walk the PiDDBCacheTable AVL tree; return ({payload_va: info}, node_size,
    broken). Children hang at +0x08/+0x10 in both node layouts and the entry
    payload follows the node, so payload_va == node + node_size == the VA the
    flat list chains.

    Node size CANNOT be probed by payload names alone: (0x18 header + layout
    +8) reads byte-identical fields to (0x20 header + classic layout), only the
    payload VA shifts by 8. Calibration therefore uses (a) overlap between
    payload VAs and the flat-list entry VAs when available, (b) the stored
    NumberGenericTableElements (0x2C for the classic 0x20-byte
    RTL_BALANCED_LINKS, 0x24 for a packed 0x18 RTL_BALANCED_NODE) being >= the
    observed node count. Verified live on 26200: 0x20 header, payload at
    node+0x20, count at +0x2C."""
    best = None  # (score, nodes, node_size, broken)
    for node_size in (0x20, 0x18):
        stack = []
        for off in (0x08, 0x10):  # BalancedRoot children
            v = await _try_u64(r, table_va + off)
            if v and v >= _KVA_MIN and (v & ~0x7) != (table_va & ~0x7):
                stack.append(v & ~0x7)
        probes = []
        for node in list(stack)[:5]:
            raw = await _try(r, node, node_size + _PIDDB_ENTRY_WINDOW)
            if raw is not None:
                probes.append(raw[node_size:])
        lay, best_key = layouts[0], (-1, -1)
        for cand in layouts:
            key = _layout_score(probes, cand)
            if key > best_key:
                lay, best_key = cand, key

        nodes: dict[int, dict] = {}
        broken = None
        seen: set[int] = set()
        walked = 0
        while stack and walked < max_slots:
            node = stack.pop()
            if node in seen:
                broken = broken or "node revisit"
                continue
            seen.add(node)
            raw = await _try(r, node, node_size + _PIDDB_ENTRY_WINDOW)
            if raw is None:
                broken = broken or "unreadable node"
                continue
            for off in (0x08, 0x10):
                c = struct.unpack_from("<Q", raw, off)[0] & ~0x7
                if c >= _KVA_MIN and c != (table_va & ~0x7) and c not in seen:
                    stack.append(c)
            pl = raw[node_size:]
            if len(pl) < _PIDDB_ENTRY_WINDOW:
                broken = broken or "short node"
                continue
            e = _piddb_entry(pl, lay)
            ln, mx, buf = _ustr(pl, lay[0])
            nodes[node + node_size] = {
                "node": hex(node),
                "state": e["state"],
                "timestamp": hex(e.get("timestamp", 0)),
                "name_len": ln,
                "name": (await _name_of(r, buf, ln) or "") if e["state"] == "ok" else "",
            }
            walked += 1
        count_off = 0x24 if node_size == 0x18 else 0x2C
        stored = await _try_u32(r, table_va + count_off)
        count_ok = bool(stored) and len(nodes) > 0 and stored >= len(nodes)
        overlap = (len(set(nodes) & set(list_vas)) / max(1, len(nodes))
                   if list_vas else 0.0)
        named_ok = sum(1 for n in nodes.values() if n["state"] == "ok" and n["name"])
        score = (round(overlap, 3), 1 if count_ok else 0, named_ok, len(nodes))
        if best is None or score > best[0]:
            best = (score, nodes, node_size, broken)
    return best[1], best[2], best[3]


@_scanner("piddb_tamper_check")
async def _scan_piddb_tamper(sdk, params: dict, recipe: dict) -> dict:
    """PiDDB synchronization / tamper check: cross-compare the AVL tree
    (nt!PiDDBCacheTable) against the flat chain (nt!PiDDBCacheList). Both
    structures mirror the same PiDDB_CACHE_ENTRY payloads, so list-only
    unlinks (the classic clean fingerprint), element-count drift, and
    in-place sanitized entries (zeroed TS/Name) all show up here.

    Both structures are walked to their FULL extent (recipe cap, independent
    of the max_entries listing cap): the tree and the list enumerate in
    different orders, so capped subsets would falsely diverge."""
    if params["source"] == "patterns":
        return {"status": "no_recipe",
                "note": "sync check needs PDB symbols - use source=auto/pdb"}
    r = _kr(sdk)
    rvas = _resolve_symbols(sdk, params, recipe, "pidddb_cache_table",
                            "binary_path_nt")
    if "PiDDBCacheTable" not in rvas or "PiDDBCacheList" not in rvas:
        return {"status": "no_recipe", "source": "pdb",
                "note": "need BOTH PiDDBCacheTable and PiDDBCacheList for the sync check"}
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    symbols = {k: hex(v + base) for k, v in rvas.items()}
    layouts = [tuple(_u64(x) for x in lay)
               for lay in (recipe.get("layouts") or _PIDDB_LAYOUTS)]
    sync_cap = min(_u64(recipe.get("max_entries") or 4096), 65536)

    tree = base + rvas["PiDDBCacheTable"]
    list_entries, _lay, list_broken, list_walked, list_vas = await _walk_piddb_list(
        r, base + rvas["PiDDBCacheList"], layouts, sync_cap)
    tree_nodes, node_size, tree_broken = await _collect_piddb_tree(
        r, tree, layouts, sync_cap, list_vas=set(list_vas))

    count_off = 0x24 if node_size == 0x18 else 0x2C
    stored_elements = await _try_u32(r, tree + count_off)

    tree_only = sorted(set(tree_nodes) - set(list_vas))
    list_only = sorted(set(list_vas) - set(tree_nodes))
    sanitized = []
    for va, n in tree_nodes.items():
        if n["state"] == "empty" or n["timestamp"] == "0x0":
            sanitized.append({"entry": hex(va), "reason": "zeroed name/ts"})
    for e, va in zip(list_entries, list_vas):
        if va in tree_nodes:
            continue
        if not e.get("name") or e.get("timestamp") == "0x0":
            sanitized.append({"entry": hex(va), "reason": "zeroed name/ts (list-only)"})

    count_mismatch = None
    tree_capped = len(tree_nodes) >= sync_cap  # hit the ceiling: count check moot
    if stored_elements is not None and not tree_capped \
            and stored_elements != len(tree_nodes):
        count_mismatch = {"stored": stored_elements, "actual_tree": len(tree_nodes)}

    structural = bool(tree_only or list_only or count_mismatch)
    tampered = structural or bool(sanitized) or bool(tree_broken or list_broken)
    severity = "high" if structural else ("warning" if tampered else "info")

    details = {
        "tree_nodes": len(tree_nodes),
        "list_entries": len(list_entries),
        "walk_capped": tree_capped or len(list_entries) >= sync_cap,
        "node_size": hex(node_size),
        "stored_elements": stored_elements,
        "count_mismatch": count_mismatch,
        "tree_only_orphans": [hex(v) for v in tree_only[:32]],
        "list_only_orphans": [hex(v) for v in list_only[:32]],
        "sanitized": sanitized[:32],
        "broken": {"tree": tree_broken, "list": list_broken},
    }
    reasons = []
    if tree_only:
        reasons.append(f"{len(tree_only)} tree node(s) unlinked from the list")
    if list_only:
        reasons.append(f"{len(list_only)} list entry(ies) missing from the tree")
    if count_mismatch:
        reasons.append(f"element count drift (stored {count_mismatch['stored']} "
                       f"vs {count_mismatch['actual_tree']} nodes)")
    if sanitized:
        reasons.append(f"{len(sanitized)} sanitized (zeroed name/ts) entr(y/ies)")
    if tree_broken or list_broken:
        reasons.append(f"broken chain (tree: {tree_broken}, list: {list_broken})")
    verdict = "TAMPERED" if tampered else "consistent"

    return {"status": "scanned", "source": "pdb", "symbols": symbols,
            "severity": severity,
            "meta": {"verdict": verdict, "tampered": tampered, "details": details},
            "entries": [], "stale": [],
            "summary": f"piddb sync: tree={len(tree_nodes)} "
                       f"list={len(list_entries)} elements={stored_elements} "
                       f"-> {verdict}" + (f" ({'; '.join(reasons)})" if reasons else "")}


# ----------------------------------------------------------------- ci ----

async def _ci_head_valid(r: Reader, g_va: int, allow_empty: bool = False) -> bool:
    """Validate a candidate g_KernelHashBucketList slot by shaping the first
    entry (validation rule: name must contain '.sys'; Next null or kernel VA)."""
    first = await _try_u64(r, g_va)
    if first is None:
        return False
    if first == 0:
        return allow_empty  # empty list only trusted for a PDB-sourced slot
    if first < _KVA_MIN:
        return False
    raw = await _try(r, first, _CI_ENTRY_WINDOW)
    if raw is None:
        return False
    nxt = struct.unpack_from("<Q", raw, 0)[0]
    if nxt and nxt < _KVA_MIN:
        return False
    ln, mx, buf = _ustr(raw, _CI_NAME_AT)
    if not ln or ln > 0x400 or buf < _KVA_MIN:
        return False
    name = await _name_of(r, buf, ln)
    return bool(name) and ".sys" in name.lower()


@_scanner("ci_hash_bucket_list")
async def _scan_ci(sdk, params: dict, recipe: dict) -> dict:
    r = _kr(sdk)
    base, size = await _kernel_module(sdk, recipe)
    notes: list[str] = []
    symbols: dict[str, str] = {}
    g_va = None
    source = None

    if params["source"] in ("auto", "pdb"):
        try:
            rvas = _resolve_symbols(sdk, params, recipe, "ci_hash_bucket_list",
                                    "binary_path_ci")
            if "g_KernelHashBucketList" in rvas:
                cand = base + rvas["g_KernelHashBucketList"]
                if await _ci_head_valid(r, cand, allow_empty=True):
                    g_va, source = cand, "pdb"
                    symbols["g_KernelHashBucketList"] = hex(cand)
                else:
                    notes.append("pdb slot failed first-entry validation")
        except Exception as exc:
            notes.append(f"pdb: {type(exc).__name__}: {exc}")
            if params["source"] == "pdb":
                return {"status": "no_recipe", "source": "pdb", "notes": notes,
                        "message": str(exc)}

    if g_va is None and params["source"] in ("auto", "patterns"):
        pat_hex = str(recipe.get("pattern") or "").strip()
        pat_mask = str(recipe.get("mask") or "")
        if not pat_hex or not str(recipe.get("verified", False)).lower() == "true":
            notes.append("no verified pattern recipe in _patterns.yaml")
        else:
            pat, mask = parse_mask(pat_hex)
            hits = []
            try:
                image = await sdk.mem.read(0, base, size, space="kernel",
                                           view="kernel")
                hits = [(base + off) for off in pattern_scan(image, pat, mask)]
            except Exception:
                hits = await sdk.mem.scan_range(0, base, size, pat, mask,
                                                view="kernel", max_results=8)
            for hit in hits[:8]:
                if isinstance(hit, int) and g_va is None:
                    raw = await _try(r, hit, 7)
                    if raw is None:
                        continue
                    rel = int.from_bytes(raw[3:7], "little", signed=True)
                    cand = hit + 7 + rel  # mov rbx,[rip+rel32]; rip = hit+7
                    if await _ci_head_valid(r, cand):
                        g_va, source = cand, "pattern"
                        break

    if g_va is None and params["source"] in ("auto", "patterns"):
        # validated .data slot scan (step 3): find a QWORD in ci's
        # .data whose value shapes like a HASH_BUCKET_ENTRY chain head
        notes_err = "parse_pe failed"
        info = None
        try:
            info = await parse_pe(r, base)
        except Exception as exc:
            notes_err = f"parse_pe: {type(exc).__name__}: {exc}"
        if info is not None:
            for sec in info.sections:
                if sec["name"] != ".data":
                    continue
                dva = sec["virtual_address"]
                dsz = min(sec["virtual_size"] or sec["raw_size"], 0x400000)
                window = await _try(r, base + dva, dsz)
                if window is None:
                    break
                for off in range(0, len(window) - 8, 8):
                    cand = struct.unpack_from("<Q", window, off)[0]
                    if cand < _KVA_MIN:
                        continue
                    if await _ci_head_valid(r, cand):
                        g_va, source = cand, "data_scan"
                        break
                if g_va is not None:
                    break
        else:
            notes.append(notes_err)

    if g_va is None:
        return {"status": "not_found", "source": params["source"],
                "symbols": symbols, "notes": notes,
                "summary": "g_KernelHashBucketList not located"}

    name_at = _u64(recipe.get("name_ustr_at", _CI_NAME_AT))
    certhash_at = _u64(recipe.get("certhash_at", _CI_CERTHASH_AT))
    max_slots = min(_u64(recipe.get("max_entries") or _CI_MAX_SLOTS),
                    _CI_MAX_SLOTS, params["max_entries"])

    entries, broken, walked = [], None, 0
    cur = await _try_u64(r, g_va)
    seen: set[int] = set()
    while cur and walked < max_slots:
        if cur < _KVA_MIN:
            broken = "non-kernel next"
            break
        if cur in seen:
            broken = "next loop"
            break
        seen.add(cur)
        raw = await _try(r, cur, _CI_ENTRY_WINDOW)
        if raw is None:
            broken = "unreadable entry"
            break
        nxt = struct.unpack_from("<Q", raw, 0)[0]
        ln, mx, buf = _ustr(raw, name_at)
        if ln > 0x400:
            broken = f"wild name_len {ln:#x}"
            break
        item = {"entry": hex(cur),
                "name": (await _name_of(r, buf, ln) or "") if ln and buf else "",
                "name_len": ln}
        if len(raw) >= certhash_at + _CI_CERTHASH_SIZE:
            item["certhash"] = raw[certhash_at:certhash_at + _CI_CERTHASH_SIZE].hex()
        entries.append(item)
        cur = nxt
        walked += 1

    filt = str(params["name_filter"]).lower()
    stale = [e for e in entries if _flag(e, filt)]
    return {"status": "scanned", "source": source, "symbols": symbols,
            "meta": {"head": hex(g_va), "walked": walked, "broken": broken},
            "entries": entries, "stale": stale, "notes": notes,
            "summary": f"{len(entries)} entries via {source}"
                       + (f", broken: {broken}" if broken else "")}


# ----------------------------------------------------------------- ldr ----

@_scanner("ps_loaded_module_list")
async def _scan_ldr(sdk, params: dict, recipe: dict) -> dict:
    """nt!PsLoadedModuleList: InLoadOrderLinks of KLDR_DATA_TABLE_ENTRY.
    Shows what is loaded right now - a manually mapped driver that failed
    (or skipped) its own unlink shows up here with a suspicious name, and
    cross-referencing against the other structures exposes ghosts."""
    if params["source"] == "patterns":
        return {"status": "no_recipe",
                "note": "no pattern recipe for PsLoadedModuleList - use source=auto/pdb"}
    r = _kr(sdk)
    rvas = _resolve_symbols(sdk, params, recipe, "ps_loaded_module_list",
                            "binary_path_nt")
    if "PsLoadedModuleList" not in rvas:
        raise SuspexError("PsLoadedModuleList not found in the PDB")
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    symbols = {k: hex(v + base) for k, v in rvas.items()}
    head = base + rvas["PsLoadedModuleList"]
    max_slots = min(_u64(recipe.get("max_entries") or _LDR_MAX_ENTRIES),
                    _LDR_MAX_ENTRIES, params["max_entries"])

    cur = await _try_u64(r, head)
    if cur is None:
        return {"status": "not_found", "source": "pdb", "symbols": symbols,
                "summary": "PsLoadedModuleList head unreadable"}

    entries, broken, walked = [], None, 0
    prev, seen = head, set()
    while cur and cur != head and walked < max_slots:
        if cur < _KVA_MIN:
            broken = "non-kernel flink"
            break
        if cur in seen:
            broken = "flink loop"
            break
        seen.add(cur)
        raw = await _try(r, cur, _LDR_ENTRY_WINDOW)
        if raw is None:
            broken = "unreadable entry"
            break
        back = struct.unpack_from("<Q", raw, 8)[0]
        if back != prev:
            broken = "blink mismatch"
            break
        nxt = struct.unpack_from("<Q", raw, 0)[0]

        base_name = full_name = ""
        name_lens = {_LDR_BASENAME_AT: 0, _LDR_FULLNAME_AT: 0}
        for name_at in (_LDR_BASENAME_AT, _LDR_FULLNAME_AT):
            ln, mx, buf = _ustr(raw, name_at)
            name_lens[name_at] = ln
            if _ustr_state(ln, mx, buf) == "ok" and ln and buf:
                text = (await _name_of(r, buf, ln)) or ""
                if name_at == _LDR_BASENAME_AT:
                    base_name = text
                else:
                    full_name = text
        dll_base = struct.unpack_from("<Q", raw, _LDR_BASE_AT)[0]
        item = {"entry": hex(cur),
                "name": base_name or full_name.rsplit("\\", 1)[-1],
                "base_dll_name": base_name, "full_dll_name": full_name,
                "base_name_len": name_lens[_LDR_BASENAME_AT],
                "full_name_len": name_lens[_LDR_FULLNAME_AT],
                "dll_base": hex(dll_base)}
        if len(raw) >= _LDR_ENTRYPOINT_AT + 8:
            item["entry_point"] = hex(struct.unpack_from(
                "<Q", raw, _LDR_ENTRYPOINT_AT)[0])
        if len(raw) >= _LDR_SIZEOFIMAGE_AT + 8:
            item["size_of_image"] = struct.unpack_from(
                "<I", raw, _LDR_SIZEOFIMAGE_AT)[0]
        if len(raw) >= _LDR_FLAGS_AT + 8:
            item["flags"] = hex(struct.unpack_from("<I", raw, _LDR_FLAGS_AT)[0])
            item["load_count"] = struct.unpack_from("<H", raw,
                                                    _LDR_FLAGS_AT + 4)[0]
        if len(raw) >= _LDR_SIG_AT + 2:
            sig = struct.unpack_from("<H", raw, _LDR_SIG_AT)[0]
            item["signature_level"] = sig & 0xF
            item["signature_type"] = (sig >> 4) & 0x7
        if len(raw) >= _LDR_SECTION_AT + 8:
            item["section_pointer"] = hex(struct.unpack_from(
                "<Q", raw, _LDR_SECTION_AT)[0])
            item["checksum"] = hex(struct.unpack_from(
                "<I", raw, _LDR_CHECKSUM_AT)[0])
        entries.append(item)
        prev, cur = cur, nxt
        walked += 1

    sp_nonnull = sum(1 for e in entries
                     if e.get("section_pointer") not in (None, "0x0"))
    filt = str(params["name_filter"]).lower()
    stale = [e for e in entries if _flag(e, filt)]
    return {"status": "scanned", "source": "pdb", "symbols": symbols,
            "meta": {"head": hex(head), "walked": walked, "broken": broken,
                     "section_pointer_nonnull": sp_nonnull,
                     "section_pointer_null": len(entries) - sp_nonnull},
            "entries": entries, "stale": stale,
            "summary": f"{len(entries)} modules "
                       f"(SectionPointer {sp_nonnull} non-null / "
                       f"{len(entries) - sp_nonnull} null)"
                       + (f", broken: {broken}" if broken else "")}


# ------------------------------------------------------ native inputs ----

# Set by run() from sdk.artifacts_dir — the canonical artifacts root
# passed down from the orchestrator config (cwd-independent).
_ARTIFACTS_ROOT: Path | None = None


def _native_dir() -> Path:
    p = (_ARTIFACTS_ROOT or Path.cwd() / "artifacts") / "native_inputs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _native_write(label: str, obj: dict) -> tuple[str, str]:
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    path = _native_dir() / f"{label}_{iso}.json"
    latest = _native_dir() / f"{label}_latest.json"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    try:
        latest.write_text(json.dumps(obj, indent=2, default=str),
                          encoding="utf-8")
    except OSError:
        pass
    return str(path), str(latest)


async def _piddb_avl_height(r: Reader, table_va: int, node_size: int) -> tuple[int, int]:
    """DFS max-depth over the balanced tree; returns (height, nodes_visited).
    Root level counts as depth 1, so a balanced 168-node table reports ~9."""
    seen: set[int] = set()
    stack: list[tuple[int, int]] = []
    for off in (0x08, 0x10):
        v = await _try_u64(r, table_va + off)
        if v and v >= _KVA_MIN and (v & ~0x7) != (table_va & ~0x7):
            stack.append((v & ~0x7, 1))
    maxd = 0
    while stack:
        node, d = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        if d > maxd:
            maxd = d
        raw = await _try(r, node, node_size)
        if raw is None:
            continue
        for off in (0x08, 0x10):
            c = struct.unpack_from("<Q", raw, off)[0] & ~0x7
            if c >= _KVA_MIN and c != (table_va & ~0x7) and c not in seen:
                stack.append((c, d + 1))
    return maxd, len(seen)


async def _chain_tail(r: Reader, ca_va: int) -> tuple[str, dict]:
    """CONTROL_AREA -> FILE_OBJECT -> FileName for one ControlArea candidate."""
    ca = await _try(r, ca_va, _CA_WINDOW)
    if ca is None:
        return "control_area_unreadable", {}
    fp = struct.unpack_from("<Q", ca, _CA_FILEPTR_AT)[0]
    fo = fp & ~0xF
    if fo < _KVA_MIN:
        return "file_pointer_bad", {"file_pointer": hex(fp)}
    fob = await _try(r, fo, _FO_WINDOW)
    if fob is None:
        return "file_object_unreadable", {"file_object": hex(fo)}
    ln, mx, buf = _ustr(fob, _FO_FILENAME_AT)
    st = _ustr_state(ln, mx, buf)
    if st != "ok" or not ln:
        return "filename_bad", {"file_object": hex(fo), "ustr_state": st,
                                "name_len": ln}
    name = await _name_of(r, buf, ln)
    if not name:
        return "filename_unreadable", {"file_object": hex(fo)}
    return "ok", {"control_area": hex(ca_va), "file_object": hex(fo),
                  "file_name": name}


async def _follow_section_chain(r: Reader, section_va: int) -> dict:
    """KLDR.SectionPointer -> _SECTION -> _CONTROL_AREA -> _FILE_OBJECT
    -> FileName. Tries each candidate ControlArea offset; a resolved name
    confirms which layout the build uses."""
    out = {"section": hex(section_va), "ok": False, "stage": "section"}
    sec = await _try(r, section_va, _SECTION_WINDOW)
    if sec is None:
        out["stage"] = "section_unreadable"
        return out
    cands: list[tuple[int, int]] = []
    for off in _SECTION_CA_OFFSETS:
        if off + 8 <= len(sec):
            ca = struct.unpack_from("<Q", sec, off)[0]
            if ca >= _KVA_MIN:
                cands.append((off, ca))
    if not cands:
        out["stage"] = "no_control_area_ptr"
        return out
    fails: list[dict] = []
    for off, ca_va in cands:
        stage, info = await _chain_tail(r, ca_va)
        if stage == "ok":
            out.update({"ok": True, "stage": "file_name",
                        "control_area_offset": hex(off), **info})
            return out
        fails.append({"control_area_offset": hex(off),
                      "control_area": hex(ca_va), "stage": stage, **info})
    out["stage"] = fails[0]["stage"]
    out["tried"] = fails
    return out


def _clean_name(name: str) -> str:
    """Printable-ASCII prefix of a decoded name (kernel driver names are
    pure ASCII - anything past the first non-printable char is buffer
    slack, not part of the name)."""
    out = []
    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            out.append(ch)
        else:
            break
    return "".join(out)


def _name_quality(name: str, declared_len: int = 0) -> str | None:
    """ASCII-printable check for kernel driver names. Only the DECLARED
    portion is judged: UNICODE_STRING.Length bytes are the name; decoded
    characters past that are allocator slack (wstr reads to a 64-byte
    chunk boundary), not corruption. Garbage INSIDE the declared span is
    the anomaly worth flagging."""
    if not name:
        return None
    check = name[: declared_len // 2] if declared_len else name
    for ch in check:
        o = ord(ch)
        if o < 0x20 or o > 0x7E:
            return "non_ascii_in_declared"
    return None


def _mm_nulled_slots(window: bytes, stride: int, slots: int) -> tuple[list, list]:
    """Classify MmUnloadedDrivers slots the normal walk drops: 'nulled'
    keeps image start/end but the name was scrubbed; 'bad' is a garbled
    UNICODE_STRING shape."""
    nulled, bad = [], []
    for i in range(slots):
        off = i * stride
        raw = window[off:off + stride]
        if len(raw) < stride:
            break
        ln, mx, buf = _ustr(raw, _MM_NAME_AT)
        if _ustr_state(ln, mx, buf) != "bad":
            continue
        start = struct.unpack_from("<Q", raw, _MM_START_AT)[0]
        end = struct.unpack_from("<Q", raw, _MM_END_AT)[0]
        row = {"index": i, "name_len": ln, "buf": hex(buf),
               "start": hex(start), "end": hex(end)}
        if start or end:
            nulled.append(row)
        else:
            bad.append(row)
    return nulled, bad


@_scanner("native_kernel_inputs")
async def _scan_native_inputs(sdk, params: dict, recipe: dict) -> dict:
    """Read-only native kernel-driver capture: real populated counts for the
    structures other scans list, plus provenance chains.

    Produces the C317-style block:
      loaded modules / PiDDB entries / readable PiDDB names / PiDDB AVL
      height / MmUnloadedDrivers records / loader entries by SectionPointer
      null state / a sampled KLDR->SECTION->CONTROL_AREA->FILE_OBJECT->
      FileName chain walk.

    Additionally flags what the plain scans don't track: nulled (scrubbed)
    PiDDB/MmUnloaded slots, loader entries with zeroed identity fields,
    tree<->list divergence, count drift, chain stages that fail, and
    cross-structure anomalies (loaded-but-no-PiDDB, unloaded-but-loaded)."""
    if params["source"] == "patterns":
        return {"status": "no_recipe",
                "note": "native inputs need PDB symbols - use source=auto/pdb"}
    r = _kr(sdk)
    notes: list[str] = []
    anomalies: list[dict] = []
    nulled: dict[str, list] = {"piddb": [], "mm_unloaded": [], "loader": []}
    label = str(params.get("label") or "native")
    chain_sample = min(int(params.get("chain_sample") or 16), 256)
    full = dict(params)
    full["max_entries"] = _LDR_MAX_ENTRIES

    # ------------------------------------------------ loaded modules (ldr)
    ldr_res = await _scan_ldr(sdk, full,
                              _recipe_for(sdk, "ps_loaded_module_list"))
    ldr_entries = ldr_res.get("entries") or []
    if ldr_res.get("status") != "scanned":
        notes.append(f"ps_loaded_module_list: {ldr_res.get('status')}"
                     f" {ldr_res.get('summary') or ldr_res.get('note') or ''}")
    if ldr_res.get("meta", {}).get("broken"):
        anomalies.append({"kind": "ldr_chain_broken", "severity": "high",
                          "detail": ldr_res["meta"]["broken"]})

    sp_nonnull = [e for e in ldr_entries
                  if e.get("section_pointer") not in (None, "0x0")]
    for e in ldr_entries:
        if e.get("dll_base") in (None, "0x0"):
            anomalies.append({"kind": "ldr_null_base", "severity": "warning",
                              "detail": f"{e.get('name') or e['entry']}"})
            nulled["loader"].append({"entry": e["entry"], "field": "dll_base",
                                     "name": e.get("name", "")})
        if e.get("size_of_image") == 0:
            anomalies.append({"kind": "ldr_zero_size", "severity": "warning",
                              "detail": f"{e.get('name') or e['entry']}"})
        if not (e.get("base_dll_name") or e.get("full_dll_name")):
            anomalies.append({"kind": "ldr_name_missing", "severity": "warning",
                              "detail": e["entry"]})
            nulled["loader"].append({"entry": e["entry"], "field": "name"})
        for fname, lkey in (("base_dll_name", "base_name_len"),
                            ("full_dll_name", "full_name_len")):
            q = _name_quality(str(e.get(fname) or ""),
                              int(e.get(lkey) or 0))
            if q:
                anomalies.append({"kind": "ldr_name_quality",
                                  "severity": "warning",
                                  "detail": f"{e['entry']} {fname}="
                                            f"{e.get(fname)!r} ({q})"})

    # ------------------------------------------- section provenance chains
    chains: list[dict] = []
    stage_fail: dict[str, int] = {}
    ca_offset_used: set[str] = set()
    for e in sp_nonnull[:chain_sample]:
        res = await _follow_section_chain(r, int(e["section_pointer"], 16))
        res["module"] = e.get("name", "")
        res["entry"] = e["entry"]
        if res["ok"]:
            ca_offset_used.add(res["control_area_offset"])
            fn_base = res["file_name"].rsplit("\\", 1)[-1].lower()
            ldr_base = (e.get("base_dll_name")
                        or e.get("name", "")).lower()
            res["name_match"] = bool(ldr_base) and fn_base == ldr_base
            if ldr_base and not res["name_match"]:
                anomalies.append({"kind": "chain_name_mismatch",
                                  "severity": "warning",
                                  "detail": f"{e.get('name')}: chain FileName "
                                            f"{res['file_name']!r}"})
        else:
            stage_fail[res["stage"]] = stage_fail.get(res["stage"], 0) + 1
        chains.append(res)
    chains_ok = sum(1 for c in chains if c["ok"])

    # ------------------------------------------------------------ PiDDB --
    rvas_piddb = _resolve_symbols(sdk, params,
                                  _recipe_for(sdk, "pidddb_cache_table"),
                                  "pidddb_cache_table", "binary_path_nt")
    mod = await sdk.mods.find("ntoskrnl.exe", kernel=True)
    if mod is None:
        raise SuspexError("ntoskrnl.exe not found in kernel view")
    nt_base = _u64(mod["base"])
    layouts = [tuple(_u64(x) for x in lay)
               for lay in (_recipe_for(sdk, "pidddb_cache_table").get("layouts")
                           or _PIDDB_LAYOUTS)]
    sync_cap = 65536
    tree_nodes: dict[int, dict] = {}
    list_entries: list[dict] = []
    list_vas: list[int] = []
    tree_broken = list_broken = None
    node_size = 0x20
    stored_elements = None
    piddb_height = 0
    height_nodes = 0

    table_va = (nt_base + rvas_piddb["PiDDBCacheTable"]
                if "PiDDBCacheTable" in rvas_piddb else None)
    if table_va is not None:
        if "PiDDBCacheList" in rvas_piddb:
            list_entries, _lay, list_broken, _wl, list_vas = \
                await _walk_piddb_list(r, nt_base + rvas_piddb["PiDDBCacheList"],
                                       layouts, sync_cap)
        tree_nodes, node_size, tree_broken = await _collect_piddb_tree(
            r, table_va, layouts, sync_cap, list_vas=set(list_vas))
        count_off = 0x24 if node_size == 0x18 else 0x2C
        stored_elements = await _try_u32(r, table_va + count_off)
        piddb_height, height_nodes = await _piddb_avl_height(
            r, table_va, node_size)
    else:
        notes.append("PiDDBCacheTable not resolved - piddb section skipped")

    named_ok = sum(1 for n in tree_nodes.values()
                   if n["state"] == "ok" and n["name"])
    piddb_rows: list[dict] = []
    for va, n in tree_nodes.items():
        row = {"entry": hex(va), "node": n["node"], "state": n["state"],
               "timestamp": n["timestamp"], "name_len": n.get("name_len", 0),
               "name": n["name"] or None}
        piddb_rows.append(row)
        if n["state"] != "ok" or not n["name"] or n["timestamp"] == "0x0":
            nulled["piddb"].append({"entry": hex(va), "node": n["node"],
                                    "state": n["state"],
                                    "timestamp": n["timestamp"],
                                    "name": n["name"] or None})
        q = _name_quality(n["name"], n.get("name_len", 0))
        if q:
            anomalies.append({"kind": "piddb_name_quality", "severity": "warning",
                              "detail": f"{hex(va)}: name {n['name']!r} "
                                        f"({q}, declared len {n.get('name_len')})"})
    for e, va in zip(list_entries, list_vas):
        if va in tree_nodes:
            continue
        if not e.get("name") or e.get("timestamp") == "0x0":
            nulled["piddb"].append({"entry": hex(va), "list_only": True,
                                    "timestamp": e.get("timestamp")})

    tree_only = sorted(set(tree_nodes) - set(list_vas))
    list_only = sorted(set(list_vas) - set(tree_nodes))
    if tree_only:
        anomalies.append({"kind": "piddb_tree_only", "severity": "high",
                          "detail": f"{len(tree_only)} node(s) unlinked from "
                                    f"list: {[hex(v) for v in tree_only[:8]]}"})
    if list_only:
        anomalies.append({"kind": "piddb_list_only", "severity": "high",
                          "detail": f"{len(list_only)} entrie(s) missing from "
                                    f"tree: {[hex(v) for v in list_only[:8]]}"})
    if stored_elements is not None and len(tree_nodes) \
            and stored_elements != len(tree_nodes):
        anomalies.append({"kind": "piddb_count_drift", "severity": "high",
                          "detail": f"stored {stored_elements} vs "
                                    f"{len(tree_nodes)} walked"})
    if height_nodes != len(tree_nodes):
        anomalies.append({"kind": "piddb_height_walk_divergence",
                          "severity": "warning",
                          "detail": f"height DFS reached {height_nodes} nodes "
                                    f"vs {len(tree_nodes)} payload nodes"})
    if tree_broken or list_broken:
        anomalies.append({"kind": "piddb_walk_broken", "severity": "warning",
                          "detail": f"tree:{tree_broken} list:{list_broken}"})
    if nulled["piddb"]:
        anomalies.append({"kind": "piddb_nulled", "severity": "warning",
                          "detail": f"{len(nulled['piddb'])} entr(y/ies) with "
                                    f"zeroed/unreadable name or timestamp"})

    # ---------------------------------------------------- MmUnloadedDrivers
    mm_res = await _scan_mm(sdk, full,
                            _recipe_for(sdk, "mm_unloaded_drivers"))
    mm_entries = mm_res.get("entries") or []
    if mm_res.get("status") != "scanned":
        notes.append(f"mm_unloaded_drivers: {mm_res.get('status')}"
                     f" {mm_res.get('summary') or mm_res.get('note') or ''}")
    else:
        mm_meta = mm_res.get("meta") or {}
        arr = mm_meta.get("array")
        stride = _u64(mm_meta.get("stride") or 0)
        if arr and stride:
            window = await _try(r, int(arr, 16), stride * _MM_MAX_SLOTS) or b""
            nulled["mm_unloaded"], bad_slots = _mm_nulled_slots(
                window, stride, _MM_MAX_SLOTS)
            if nulled["mm_unloaded"]:
                anomalies.append({"kind": "mm_unloaded_nulled",
                                  "severity": "warning",
                                  "detail": f"{len(nulled['mm_unloaded'])} "
                                            f"slot(s) name-scrubbed but "
                                            f"start/end set"})
            if bad_slots:
                anomalies.append({"kind": "mm_unloaded_bad_shape",
                                  "severity": "info",
                                  "detail": f"{len(bad_slots)} slot(s) with "
                                            f"garbled UNICODE_STRING"})
    for e in mm_entries:
        q = _name_quality(str(e.get("name") or ""), int(e.get("name_len") or 0))
        if q:
            anomalies.append({"kind": "mm_unloaded_name_quality",
                              "severity": "warning",
                              "detail": f"index {e.get('index')}: "
                                        f"name {e.get('name')!r} ({q})"})

    # ------------------------------------------------------- cross-checks
    loaded_names = {_clean_name(str(e.get("name") or "")).lower()
                    for e in ldr_entries if e.get("name")}
    piddb_names = {_clean_name(str(n.get("name") or "")).lower()
                   for n in tree_nodes.values() if n.get("name")}
    mm_names = {_clean_name(str(e.get("name") or "")).lower()
                for e in mm_entries if e.get("name")}
    missing_piddb = sorted(loaded_names - piddb_names)
    still_loaded = sorted(mm_names & loaded_names)
    piddb_not_loaded = sorted(piddb_names - loaded_names)
    if still_loaded:
        dump_only = all(n.startswith("dump_") for n in still_loaded)
        anomalies.append({"kind": "unloaded_still_loaded",
                          "severity": "info" if dump_only else "warning",
                          "detail": f"{len(still_loaded)} name(s) in "
                                    f"MmUnloadedDrivers AND loaded: "
                                    f"{still_loaded[:8]}"
                                    + (" (dump_* crash-stack staging - expected)"
                                       if dump_only else "")})

    native = {
        "loaded_modules": len(ldr_entries),
        "piddb_entries": len(tree_nodes),
        "piddb_readable_names": named_ok,
        "piddb_avl_height": piddb_height,
        "mm_unloaded_records": len(mm_entries),
        "ldr_section_pointer_nonnull": len(sp_nonnull),
        "ldr_section_pointer_null": len(ldr_entries) - len(sp_nonnull),
        "chain_sample": len(chains),
        "chains_ok": chains_ok,
        "chains_failed": len(chains) - chains_ok,
    }
    detail = {
        "native_inputs": native,
        "modules": ldr_entries,
        "chain_results": chains,
        "chain_stage_failures": stage_fail,
        "control_area_offsets_used": sorted(ca_offset_used),
        "piddb": {"stored_elements": stored_elements,
                  "node_size": hex(node_size),
                  "height_walk_nodes": height_nodes,
                  "tree_only": [hex(v) for v in tree_only[:32]],
                  "list_only": [hex(v) for v in list_only[:32]],
                  "broken": {"tree": tree_broken, "list": list_broken},
                  "entries": piddb_rows},
        "mm_unloaded": {**(mm_res.get("meta") or {}),
                        "entries": mm_entries},
        "nulled": nulled,
        "anomalies": anomalies,
        "cross": {"loaded_missing_piddb": missing_piddb[:64],
                  "unloaded_still_loaded": still_loaded[:64],
                  "piddb_not_loaded_count": len(piddb_not_loaded),
                  "piddb_not_loaded_sample": piddb_not_loaded[:32]},
    }
    snap = {"schema_version": 1, "label": label,
            "captured_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H-%M-%SZ"),
            "nt_build": sdk.nt_build, **detail}
    path, latest = _native_write(label, snap)

    sev = "info"
    if any(a["severity"] == "high" for a in anomalies):
        sev = "high"
    elif any(a["severity"] == "warning" for a in anomalies) \
            or sum(len(v) for v in nulled.values()):
        sev = "warning"
    summary = (f"modules={native['loaded_modules']} "
               f"(sectptr {native['ldr_section_pointer_nonnull']}/"
               f"{native['ldr_section_pointer_null']}), "
               f"piddb={native['piddb_entries']} "
               f"({named_ok} named, h={piddb_height}), "
               f"mm={native['mm_unloaded_records']}, "
               f"chains {chains_ok}/{len(chains)} ok, "
               f"nulled={sum(len(v) for v in nulled.values())}, "
               f"anomalies={len(anomalies)}")
    return {"status": "scanned", "source": "pdb",
            "severity": sev, "meta": detail,
            "entries": [], "stale": [], "notes": notes,
            "snapshot_path": path, "latest_path": latest,
            "summary": summary}


# ---------------------------------------------------------------- run ----

async def run(sdk, params: dict) -> dict:
    global _ARTIFACTS_ROOT
    _ARTIFACTS_ROOT = Path(getattr(sdk, "artifacts_dir", "")
                            or Path.cwd() / "artifacts")
    order = ["ps_loaded_module_list", "mm_unloaded_drivers",
             "pidddb_cache_table", "piddb_tamper_check", "ci_hash_bucket_list",
             "native_kernel_inputs"]
    if params["recipe"] != "all":
        order = [params["recipe"]]

    results: dict[str, dict] = {}
    notes: list[str] = []
    for name in order:
        recipe = _recipe_for(sdk, name)
        try:
            results[name] = await _SCANNERS[name](sdk, params, recipe)
        except Exception as exc:
            results[name] = {"status": "error",
                             "error": f"{type(exc).__name__}: {exc}"}

    stale_total = sum(len(v.get("stale") or []) for v in results.values())
    severities = {str(v.get("severity") or "") for v in results.values()}
    if "high" in severities:
        severity = "high"
    elif stale_total or "warning" in severities:
        severity = "warning"
    else:
        severity = "info"
    parts = []
    for name, res in results.items():
        short = {"ps_loaded_module_list": "ldr",
                 "mm_unloaded_drivers": "mm_unloaded",
                 "pidddb_cache_table": "piddb",
                 "piddb_tamper_check": "piddb_sync",
                 "ci_hash_bucket_list": "ci_hash",
                 "native_kernel_inputs": "native"}[name]
        if res.get("status") == "scanned":
            parts.append(f"{short}: {res['summary']}")
        else:
            parts.append(f"{short}: {res.get('status')}")
    for res in results.values():
        notes.extend(res.pop("notes", None) or [])

    return {
        "ok": True,
        "status": "scanned",
        "build": sdk.nt_build,
        "severity": severity,
        "summary": f"driver_trace_scan [{', '.join(order)}] - "
                   + "; ".join(parts)
                   + f" | stale({params['name_filter']!r}): {stale_total}",
        "notes": notes,
        "stale_total": stale_total,
        "results": results,
    }
