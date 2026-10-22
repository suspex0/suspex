from __future__ import annotations

from pathlib import Path

import yaml

from suspex.sdk import Reader, SuspexError

_PATTERNS = Path(__file__).resolve().parents[1] / "_patterns.yaml"

DEFAULT_PDB_NAMES = {
    "pidddb_cache_table": ["PiDDBCacheTable"],
    "mm_unloaded_drivers": ["MmUnloadedDrivers", "MmLastUnloadedDriver"],
}

# fallback layer when _patterns.yaml has no (or a partial) recipe for the
# running build — the PDB gives exact addresses, these carry module + layout
_DEFAULT_RECIPES = {
    "pidddb_cache_table": {
        # build 26200: the symbol lives in the ntoskrnl PDB (not ci.dll)
        "module": "ntoskrnl.exe",
        "pdb": ["PiDDBCacheTable"],
        "walk": {"kind": "avl_entries", "name_ustr_at": "0x18", "timestamp_at": "0x28"},
    },
    "mm_unloaded_drivers": {
        "module": "ntoskrnl.exe",
        "pdb": ["MmUnloadedDrivers", "MmLastUnloadedDriver"],
        "walk": {"kind": "array", "entry_size": "0x30", "max_entries": 50,
                 "name_ustr_at": "0x0", "start_at": "0x10", "end_at": "0x18",
                 "unload_time_at": "0x20"},
    },
}


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


def _system32_path(module: str) -> str:
    return "C:\\Windows\\System32\\" + module


async def _locate_pdb(sdk, name: str, recipe: dict, params: dict) -> dict:
    names = list(recipe.get("pdb") or DEFAULT_PDB_NAMES[name])
    binary = params.get("binary_path") or _system32_path(str(recipe["module"]))
    rvas = sdk.symbols.resolve(binary, names)  # SymbolError if unavailable
    missing = [n for n in names if n not in rvas]
    if not rvas:
        raise SuspexError(f"none of {names} found in the PDB for {binary}")
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    r = Reader(lambda addr, n: sdk.mem.read(0, addr, n, space="kernel", view="kernel"))

    if name == "mm_unloaded_drivers":
        # MmUnloadedDrivers is a pointer global; MmLastUnloadedDriver the index
        array = await r.u64(base + rvas["MmUnloadedDrivers"])
        count = 0
        if "MmLastUnloadedDriver" in rvas:
            count = await r.u32(base + rvas["MmLastUnloadedDriver"])
        return {"start": array, "count": count,
                "symbols": {k: hex(v + base) for k, v in rvas.items()}}
    return {"start": base + rvas[names[0]], "count": None,
            "symbols": {k: hex(v + base) for k, v in rvas.items()}}


async def _locate_patterns(sdk, name: str, recipe: dict, max_entries: int) -> dict | None:
    pattern = str(recipe.get("pattern") or "").strip()
    if not pattern:
        raise SuspexError("recipe has no pattern")
    mask = str(recipe.get("mask") or "")
    pat = bytes.fromhex(pattern.replace(" ", ""))
    mod = await sdk.mods.find(str(recipe["module"]), kernel=True)
    if mod is None:
        raise SuspexError(f"module {recipe['module']!r} not found in kernel view")
    base = _u64(mod["base"])
    size = _u64(mod["size"])
    hits = await sdk.mem.scan_range(0, base, size, pat, mask, view="kernel", max_results=8)
    if not hits:
        return None
    return {"start": hits[0], "count": None}


async def _walk(sdk, name: str, recipe: dict, located: dict, max_entries: int) -> tuple[list[dict], dict]:
    walk = recipe.get("walk") or {}
    r = Reader(lambda addr, n: sdk.mem.read(0, addr, n, space="kernel", view="kernel"))
    entries: list[dict] = []
    meta: dict = {}

    if walk.get("kind") == "avl_entries":
        # RTL_AVL_TABLE at the located address: BalancedRoot (0x18-byte
        # RTL_BALANCED_NODE), live entries hang off BalancedRoot.Right
        # (+0x08); node payload follows the 0x18-byte node. Node parent
        # pointers carry flag bits in the low bits.
        meta["table_elements"] = await r.u32(located["start"] + 0x24)
        start = await r.u64(located["start"] + 0x08)
        name_at = _u64(walk.get("name_ustr_at", 0x18))
        ts_at = _u64(walk.get("timestamp_at", 0x28))
        seen: set[int] = set()
        stack = [start & ~0x7]
        while stack and len(entries) < max_entries:
            cur = stack.pop()
            if not cur or cur in seen:
                continue
            seen.add(cur)
            payload = cur + 0x18
            name_addr = await r.u64(payload + name_at + 0x08)
            name_len = await r.u16(payload + name_at)
            ts = await r.u32(payload + ts_at)
            raw = await r.read(payload, 0x20)
            entry = {"node": hex(cur), "timestamp": hex(ts), "raw": raw.hex()}
            if name_addr:
                entry["name"] = await r.wstr(name_addr, min(name_len // 2 or 1, 260))
            entries.append(entry)
            for off in (0x00, 0x08):
                child = await r.u64(cur + off)
                if child & ~0x7:
                    stack.append(child & ~0x7)

    elif walk.get("kind") == "array":
        entry_size = _u64(walk.get("entry_size", 0x30))
        name_at = _u64(walk.get("name_ustr_at", 0x0))
        count = located.get("count") or _u64(walk.get("max_entries", 50))
        count = min(count, _u64(walk.get("max_entries", 50)), max_entries)
        # One batched read of the whole array — a per-field walk issues ~5
        # RPCs per entry and races pool churn (MmUnloadedDrivers entries are
        # freed/reallocated on unload; a stale pointer read surfaces as
        # gle=998 mid-walk). A single snapshot is both faster and atomic.
        try:
            blob = await r.read(located["start"], count * entry_size)
        except Exception:
            blob = b""
        for i in range(count):
            off = i * entry_size
            if off + entry_size > len(blob):
                break  # short read: array truncated mid-walk (pool churn)
            name_len = int.from_bytes(blob[off + name_at:off + name_at + 2],
                                      "little")
            if not name_len or name_len > 0x1000:
                continue
            name_addr = int.from_bytes(
                blob[off + name_at + 8:off + name_at + 16], "little")
            item = {"index": i, "name_len": name_len}
            if name_addr:
                item["name"] = await r.wstr(name_addr, name_len // 2 + 1)
            for key, field in (("start_at", "start"), ("end_at", "end"),
                               ("unload_time_at", "unload_time")):
                if not walk.get(key):
                    continue
                at = off + _u64(walk[key])
                if at + 8 <= len(blob):
                    item[field] = hex(int.from_bytes(blob[at:at + 8], "little"))
            entries.append(item)

    return entries, meta


async def run(sdk, params: dict) -> dict:
    name = params["recipe"]
    recipe = _recipe_for(sdk, name)
    source = params["source"]
    used = None
    located = None
    notes: list[str] = []

    if source in ("auto", "pdb"):
        try:
            located = await _locate_pdb(sdk, name, recipe, params)
            used = "pdb"
        except Exception as exc:
            notes.append(f"pdb: {type(exc).__name__}: {exc}")
            if source == "pdb":
                raise

    if located is None:
        if not recipe.get("verified", False) or not str(recipe.get("pattern") or "").strip():
            return {
                "ok": True,
                "status": "no_recipe",
                "source": "patterns",
                "build": sdk.nt_build,
                "notes": notes,
                "message": f"no verified pattern recipe for build {sdk.nt_build!r} in "
                           f"_patterns.yaml and PDB path unavailable - fill the recipe or "
                           f"enable pdb download",
                "severity": "info",
                "summary": f"{name}: no usable source on build {sdk.nt_build}",
            }
        located = await _locate_patterns(sdk, name, recipe, params["max_entries"])
        used = "patterns"
        if located is None:
            return {
                "ok": True,
                "status": "not_found",
                "source": "patterns",
                "build": sdk.nt_build,
                "severity": "warning",
                "summary": f"{name}: pattern no match on build {sdk.nt_build}",
            }

    entries, meta = await _walk(sdk, name, recipe, located, params["max_entries"])
    filt = str(params["name_filter"]).lower()
    stale = [e for e in entries if filt and filt in str(e.get("name", "")).lower()]

    return {
        "ok": True,
        "status": "scanned",
        "source": used,
        "build": sdk.nt_build,
        "table_base": hex(located["start"]),
        "symbols": located.get("symbols", {}),
        "notes": notes,
        "meta": meta,
        "entries": entries,
        "stale": stale,
        "severity": "warning" if stale else "info",
        "summary": f"{name}: {len(entries)} entr(y/ies) at {located['start']:#x} "
                   f"[{used}], {len(stale)} match filter {filt!r}",
    }
