"""Symbols tool registration for the suspex0 MCP server — v0.22.

``symbols_manage`` puts the orchestrator's existing PDB/dbghelp
machinery on the MCP surface. Until now it was only reachable inside
plugins via ``SymbolsApi`` (plugin_runner), so every symbol lookup cost
a plugin hop.

Two sources, one tool:

* **Live DbgHelp** (``suspex.symbols``) — ``resolve`` (names -> RVA/VA),
  ``lookup`` (RVA/VA -> nearest symbol + displacement via
  SymFromAddrW), and ``layout`` (member walk via SymGetTypeFromNameW +
  SymGetTypeInfo — the same type walk ``mem_rw read decode={'type':..}``
  uses). Public MSDL PDBs carry kernel type info, so this works on
  ntoskrnl & friends without IDA.

* **IDA-dumped cache** (``suspex.pdb_layout_cache``) — ``struct_info`` /
  ``resolve_member`` / ``enum_info`` / ``layouts`` read the JSON written
  by ``ida_manage(action='dump_layout')``. Pure compute.

Everything except the optional live-module-base lookup is orchestrator-
local: no target contact, no driver. Symbol/PDB work is read-only by
construction.

Image selection, in priority order:
  1. ``path='...'`` — a local PE file (absolute or artifacts-relative).
  2. ``module='x.sys'`` — searched under ``artifacts/dumps`` and
     ``artifacts/ingested`` (populated by file_manage dump_module /
     ingest). If missing, the error hint says which action populates it.

PDB identity binds to the exact image via the RSDS GUID/age —
``ensure`` refuses a GUID mismatch implicitly by fetching the record
named for the image's own GUID.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context

from ... import pdb_layout_cache as _plc
from ... import symbols as _sym


SYMBOL_ACTIONS = ["info", "ensure", "resolve", "lookup", "layout",
                  "struct_info", "resolve_member", "enum_info",
                  "layouts",
                  # v0.22 discoverability
                  "actions"]

_SYMBOL_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "symbols_manage(action='actions')"},
    "info": {"one_liner": "PE debug-directory PDB identity — name, GUID, "
                          "age, symsrv path (no download)",
             "key_args": "path | module",
             "example": "symbols_manage(action='info', module='ntoskrnl.exe')"},
    "ensure": {"one_liner": "cache-first PDB fetch (MSDL); reports whether "
                            "the PDB was already cached",
               "key_args": "path | module, download",
               "example": "symbols_manage(action='ensure', "
                          "module='ntoskrnl.exe')"},
    "resolve": {"one_liner": "symbol names -> RVA (and VA when base= or a "
                             "connected view supplies the module base)",
                "key_args": "path | module, names | name | "
                            "symbol='mod!Name', base | view",
                "example": "symbols_manage(action='resolve', "
                           "module='ntoskrnl.exe', "
                           "names=['PsLoadedModuleList','PiDDBCacheTable'])"},
    "lookup": {"one_liner": "RVA/VA -> nearest symbol + displacement "
                            "(SymFromAddrW); displacement > max_disp "
                            "flags confidence:'low' — nearest-match "
                            "guessing, not real coverage",
               "key_args": "path | module, rva | va, base | view",
               "example": "symbols_manage(action='lookup', "
                          "module='ntoskrnl.exe', rva='0x40a0c0')"},
    "layout": {"one_liner": "named-type member layout straight from the "
                            "PDB — offsets, sizes, nested UDTs; no IDA "
                            "session needed",
               "key_args": "path | module, type_name, depth",
               "example": "symbols_manage(action='layout', "
                          "module='ntoskrnl.exe', type_name='_EPROCESS')"},
    "struct_info": {"one_liner": "cached-layout preview: size + member "
                                 "count + first members (from "
                                 "dump_layout JSON)",
                    "key_args": "module, build_id, type_name",
                    "example": "symbols_manage(action='struct_info', "
                               "module='ntoskrnl.exe', build_id='...', "
                               "type_name='_EPROCESS')"},
    "resolve_member": {"one_liner": "cached-layout offset -> dotted member "
                                    "path (recurses into nested UDTs)",
                       "key_args": "module, build_id, type_name, offset",
                       "example": "symbols_manage(action='resolve_member', "
                                  "module='ntoskrnl.exe', build_id='...', "
                                  "type_name='_EPROCESS', offset='0x28')"},
    "enum_info": {"one_liner": "cached-layout enum members (name/value)",
                  "key_args": "module, build_id, enum_name",
                  "example": "symbols_manage(action='enum_info', "
                             "module='ntoskrnl.exe', build_id='...', "
                             "enum_name='NL_NEIGHBOR_STATE')"},
    "layouts": {"one_liner": "list cached dump_layout files "
                             "(module + build_id pairs)",
                "key_args": "none",
                "example": "symbols_manage(action='layouts')"},
}


def _err_sym(exc: Exception) -> dict:
    """Map a SymbolError/os failure to the typed envelope dict."""
    msg = str(exc)
    low = msg.lower()
    if "not a pe" in low or "bad pe signature" in low or \
            "no debug directory" in low or "no rsds" in low:
        kind = "bad_magic"
    elif "download disabled" in low or "not cached" in low:
        kind = "pdb_missing"
    elif "download failed" in low:
        kind = "pdb_download_failed"
    elif "sym" in low:  # SymInitializeW / SymLoadModuleExW / SymGetType*
        kind = "dbghelp_failed"
    else:
        kind = "error"
    return {"ok": False, "kind": kind, "error": msg}


def _resolve_image(ctx: Context, module: str, path: str) -> tuple[str, str]:
    """Module name / explicit path -> a local PE image path.

    Returns ("", "") when neither was supplied; raises SymbolError with
    an actionable message when the caller named something that doesn't
    resolve to a file.
    """
    if path:
        p = Path(path)
        if not p.is_file():
            # Canonical store resolution: 'dumps/x.sys',
            # 'artifacts/dumps/x.sys', absolute-under-root.
            from .._artifacts import resolve_artifact_path as _rap
            rp = _rap(ctx.cfg, path)
            if rp is not None and rp.is_file():
                p = rp
            elif not p.is_absolute():
                alt = ctx.cfg.artifacts_dir() / path
                if alt.is_file():
                    p = alt
        if not p.is_file():
            raise _sym.SymbolError(f"image path not found: {path}")
        return str(p), p.name
    if not module:
        return "", ""
    # An absolute or path-y module= is treated as a path.
    if os.sep in module or "/" in module or ":" in module:
        p = Path(module)
        if p.is_file():
            return str(p), p.name
        # Artifacts-store spellings ('dumps/x.sys', 'artifacts/…').
        from .._artifacts import resolve_artifact_path as _rap
        rp = _rap(ctx.cfg, module)
        if rp is not None and rp.is_file():
            return str(rp), rp.name
        raise _sym.SymbolError(f"image path not found: {module}")
    base = ctx.cfg.artifacts_dir()
    mod_low = module.lower()
    for sub in ("dumps", "ingested", ""):
        cand_dir = base / sub if sub else base
        if not cand_dir.is_dir():
            continue
        for f in sorted(cand_dir.iterdir()):
            if f.is_file() and f.name.lower() == mod_low:
                return str(f), f.name
    raise _sym.SymbolError(
        f"module {module!r} has no local image under artifacts/ — "
        f"dump it with file_manage(action='dump_module', module={module!r}, "
        "kernel=true), ingest it with file_manage(action='ingest'), or "
        "pass path=<local image>")


def _need_image(ctx: Context, module: str, path: str) -> tuple[str, str]:
    img, img_name = _resolve_image(ctx, module, path)
    if not img:
        raise _sym.SymbolError(
            "symbols_manage needs path=<local PE> or module=<dumped "
            "module name>; nothing was supplied")
    return img, img_name


async def _resolve_type_layout(ctx: Context, spec: dict,
                               *, module: str = "", path: str = ""
                               ) -> tuple[dict | None, dict | None]:
    """Resolve a named-type layout for ``mem_rw read decode={...}``.

    Returns ``(layout_dict, None)`` or ``(None, error_envelope)``.
    ``layout_dict`` = ``{members, types, size, type_name, source}`` —
    ``types`` is the cache-level map (may be None for dbghelp layouts,
    which inline nested UDTs as ``children``).

    Source selection:
      * ``build_id`` or ``source='cache'`` -> pdb_layout_cache only.
      * ``source='dbghelp'`` -> symbols.type_layout only.
      * default ``auto`` — dbghelp when an image resolves (it is bound
        to the image's own RSDS GUID, the safest match), falling back to
        a single cached layout for the module when dbghelp can't answer.
    """
    tname = str(spec.get("type") or spec.get("type_name") or "").strip()
    if not tname:
        return None, {"ok": False, "kind": "invalid_parameter",
                      "error": "decode dict needs 'type' — e.g. "
                               "decode={'type':'_EPROCESS','module':"
                               "'ntoskrnl.exe'}"}
    mod = str(spec.get("module") or module or "").strip()
    pth = str(spec.get("path") or path or "").strip()
    bid = str(spec.get("build_id") or "").strip()
    source = str(spec.get("source") or "auto").strip().lower()
    depth = max(1, int(spec.get("depth") or 2))
    ldir = spec.get("cache_dir")
    ldir_p = Path(ldir) if ldir else None

    def _from_cache() -> tuple[dict | None, dict | None]:
        if not mod:
            return None, {"ok": False, "kind": "invalid_parameter",
                          "error": "cache decode needs "
                                   "decode={'module': ...}"}
        use_bid = bid
        if not use_bid:
            rows = [r for r in _plc.list_cached_layouts(cache_dir=ldir_p)
                    if r["module"].lower() == mod.lower()]
            if not rows:
                return None, {"ok": False, "kind": "pdb_layout_missing",
                              "error": f"no cached layout for {mod!r}",
                              "hint": "pass decode={'build_id': ...} after "
                                      "ida_manage(action='dump_layout'), or "
                                      "point decode={'path': ...} at an "
                                      "image for dbghelp"}
            if len(rows) > 1:
                return None, {"ok": False, "kind": "invalid_parameter",
                              "error": f"{len(rows)} cached layouts for "
                                       f"{mod!r} — pass "
                                       "decode={'build_id': ...} to pick",
                              "installed_builds": [r["build_id"]
                                                   for r in rows]}
            use_bid = rows[0]["build_id"]
        try:
            layout = _plc.load(mod, use_bid, cache_dir=ldir_p)
        except _plc.LayoutCacheError as exc:
            return None, {"ok": False, "kind": "pdb_layout_missing",
                          "error": str(exc), "module": mod,
                          "build_id": use_bid,
                          "hint": "run ida_manage(action='dump_layout') to "
                                  "populate the cache"}
        types = layout.get("types")
        if not isinstance(types, dict):
            return None, {"ok": False, "kind": "invalid_layout",
                          "error": f"cache {mod!r}/{use_bid} missing "
                                   "'types'"}
        entry = types.get(tname)
        if not isinstance(entry, dict):
            return None, {"ok": False, "kind": "type_not_found",
                          "error": f"{tname!r} not in cached layout for "
                                   f"{mod!r}/{use_bid}"}
        return {"members": entry.get("members") or [],
                "types": types, "size": int(entry.get("size", 0)),
                "type_name": tname, "source": "pdb_layout_cache",
                "module": mod, "build_id": use_bid}, None

    async def _from_dbghelp() -> tuple[dict | None, dict | None]:
        try:
            img, img_name = _resolve_image(ctx, mod, pth)
        except _sym.SymbolError as exc:
            return None, {"ok": False, "kind": "module_not_found",
                          "error": str(exc)}
        if not img:
            return None, {"ok": False, "kind": "invalid_parameter",
                          "error": "decode needs module= / path= to find "
                                   "an image (or build_id= for the "
                                   "layout cache)"}
        cache_dir = str(ctx.cfg.pdb_cache_dir())
        servers = ctx.cfg.symbols.servers or None
        try:
            res = await asyncio.to_thread(
                _sym.type_layout, img, tname, cache_dir,
                ctx.cfg.symbols.allow_download, servers, depth)
        except _sym.SymbolError as exc:
            return None, _err_sym(exc)
        if not res.get("ok"):
            return None, res
        return {"members": res.get("members") or [], "types": None,
                "size": int(res.get("size", 0)),
                "type_name": res.get("name", tname), "source": "dbghelp",
                "image": img_name}, None

    if source == "cache" or bid:
        return _from_cache()
    if source == "dbghelp":
        return await _from_dbghelp()
    # auto — dbghelp first when an image resolves; a dbghelp-side
    # type_not_found falls through to the cache (public PDBs miss
    # private types that an IDA dump caught).
    if mod or pth:
        lay, err = await _from_dbghelp()
        if lay is not None:
            return lay, None
        if err and err.get("kind") in ("module_not_found", "type_not_found",
                                       "pdb_missing", "dbghelp_failed"):
            lay2, err2 = _from_cache()
            if lay2 is not None:
                lay2["note"] = ("dbghelp could not answer "
                                f"({err.get('kind')}); used cached layout")
                return lay2, None
            return None, err2 or err
        return None, err
    return _from_cache()


async def _live_module_base(ctx: Context, view: str, module: str,
                            pid: int = 0) -> int | None:
    """Best-effort module base from a connected view — None when no
    client or the module isn't in the list."""
    if not view:
        return None
    try:
        c = ctx.session.require_client(view)
    except Exception:
        return None
    kernel = ctx.session.view_kind_of(view) != "user"
    try:
        mods = await c.mem_modules(pid, kernel)
    except Exception:
        return None
    mod_low = module.lower()
    for m in mods:
        if str(m.get("name", "")).lower() == mod_low:
            b = m.get("base", 0)
            return int(b, 0) if isinstance(b, str) else int(b)
    return None


def register(mcp, ctx: Context) -> None:
    """Register the ``symbols_manage`` tool on *mcp*."""
    # ---------------------------------------------------------- symbols_manage --

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def symbols_manage(
            action: Annotated[str, Field(json_schema_extra={"enum": SYMBOL_ACTIONS})],
            path: str = "", module: str = "",
            name: str = "", names: list[str] | None = None,
            symbol: str = "",
            rva: int | str = 0, va: int | str = 0,
            base: int | str = 0,
            offset: int | str = 0,
            type_name: str = "", enum_name: str = "",
            build_id: str = "", depth: int = 3,
            download: bool = True, cache_dir: str = "",
            view: str = "", pid: int = 0,
            pdb_guid: str = "", pdb_age: int | str = 0,
            pdb_name: str = "", max_disp: int | str = 0x1000,
            fallback: str = "") -> str:
        """PDB-backed symbol + type queries — dbghelp on the orchestrator,
        no target contact unless you ask for a live module base. Images:
        path= beats module= (artifacts/dumps + ingested). PDB identity
        binds to the image's RSDS GUID/age — prefer dump_module output.
        Per-verb help: symbols_manage(action='actions')."""
        args = {"action": action, "module": module, "path": path}

        async def run() -> str:
            if action not in SYMBOL_ACTIONS:
                return _unknown_action("symbols_manage", action, SYMBOL_ACTIONS, _SYMBOL_ACTION_HELP)
            if action == "actions":
                return _actions_help("symbols_manage", _SYMBOL_ACTION_HELP)

            pdb_dir = str(ctx.cfg.pdb_cache_dir())
            allow_dl = bool(download) and ctx.cfg.symbols.allow_download
            servers = ctx.cfg.symbols.servers or None

            # ---- pure-cache family (no image needed) ----
            layout_dir = Path(cache_dir) if cache_dir else None
            if action == "layouts":
                rows = _plc.list_cached_layouts(cache_dir=layout_dir)
                return _j({"ok": True, "count": len(rows),
                           "layouts": rows})
            if action in ("struct_info", "resolve_member", "enum_info"):
                if not module:
                    return _j({"ok": False, "kind": "invalid_parameter",
                               "error": f"{action} needs module= and "
                                        "build_id= (build_id may be empty "
                                        "when exactly one layout is "
                                        "installed — see layouts)"})
                eff_build, build_note = _plc.resolve_build_id(
                    module, build_id, cache_dir=layout_dir)
                if build_note and not eff_build:
                    return _j({"ok": False, "kind": "pdb_layout_missing",
                               "error": build_note,
                               "module": module,
                               "installed_builds": [
                                   {"module": r["module"],
                                    "build_id": r["build_id"]}
                                   for r in _plc.list_cached_layouts(
                                       cache_dir=layout_dir)]})
                if action == "struct_info":
                    res = _plc.struct_info(
                        module, eff_build, type_name or name,
                        cache_dir=layout_dir)
                    if build_note:
                        res["build_id_note"] = build_note
                    return _j(res)
                if action == "resolve_member":
                    off = _addr(offset, name="offset")
                    res = _plc.resolve_member(
                        module, eff_build, type_name or name, off,
                        cache_dir=layout_dir)
                    if build_note:
                        res["build_id_note"] = build_note
                    return _j(res)
                res = _plc.enum_info(
                    module, eff_build, enum_name or type_name or name,
                    cache_dir=layout_dir)
                if build_note:
                    res["build_id_note"] = build_note
                return _j(res)

            # ---- image-bound family ----
            try:
                img, img_name = _need_image(ctx, module, path)
            except _sym.SymbolError as exc:
                return _j({"ok": False, "kind": "module_not_found",
                           "error": str(exc)})

            if action == "info":
                try:
                    info = _sym.read_pdb_info(img)
                except _sym.SymbolError as exc:
                    return _j(_err_sym(exc))
                return _j({"ok": True, "image": img_name,
                           "image_path": img,
                           "pdb_name": info.name,
                           "guid": info.guid, "age": info.age,
                           "store_rel": info.store_rel})

            if action == "ensure":
                override: _sym.PdbInfo | None = None
                if pdb_guid:
                    try:
                        age_i = int(str(pdb_age), 0)
                    except ValueError:
                        return _j({"ok": False, "kind": "invalid_parameter",
                                   "error": "pdb_age= must be an integer"})
                    if not pdb_name:
                        stem = Path(img_name).stem
                        pdb_name_eff = f"{stem}.pdb"
                    else:
                        pdb_name_eff = pdb_name
                    override = _sym.PdbInfo(name=pdb_name_eff,
                                            guid=pdb_guid.strip().upper(),
                                            age=age_i)
                if override is not None:
                    info = override
                else:
                    try:
                        info = _sym.read_pdb_info(img)
                    except _sym.SymbolError as exc:
                        return _j(_err_sym(exc))
                final = Path(pdb_dir) / info.store_rel
                cached = final.is_file()
                try:
                    # Network-bound (MSDL fetch) — keep off the loop.
                    pdb = await asyncio.to_thread(
                        _sym.ensure_pdb, img, pdb_dir,
                        allow_dl, servers, info)
                except _sym.SymbolError as exc:
                    return _j(_err_sym(exc))
                return _j({"ok": True, "image": img_name,
                           "pdb": str(pdb), "cached": cached,
                           "pdb_name": info.name,
                           "guid": info.guid, "age": info.age})

            if action == "resolve":
                want = list(names or [])
                if name:
                    want.append(name)
                if symbol:
                    # 'mod!Name' — mod must agree with module= when both
                    # are given; bare 'Name' is a plain symbol.
                    smod, _, sname = symbol.partition("!")
                    if sname:
                        want.append(sname)
                        if module and module.lower() != smod.lower():
                            return _j({"ok": False,
                                       "kind": "invalid_parameter",
                                       "error": f"symbol {symbol!r} names "
                                                f"module {smod!r} but "
                                                f"module={module!r} "
                                                "disagrees"})
                    else:
                        want.append(smod)
                want = [w for w in dict.fromkeys(want) if w]
                if not want:
                    return _j({"ok": False, "kind": "invalid_parameter",
                               "error": "resolve needs names=[...], "
                                        "name=..., or symbol='mod!Name'"})
                try:
                    rvas = await asyncio.to_thread(
                        _sym.resolve_rvas, img, want, pdb_dir,
                        allow_dl, servers)
                except _sym.SymbolError as exc:
                    return _j(_err_sym(exc))
                base_i = _addr(base, name="base") if base else None
                if base_i is None and view:
                    base_i = await _live_module_base(ctx, view,
                                                     img_name, pid)
                out_syms: dict[str, Any] = {}
                missing: list[str] = []
                for nm in want:
                    r = rvas.get(nm)
                    if r is None:
                        missing.append(nm)
                        continue
                    entry: dict[str, Any] = {"rva": r}
                    if base_i:
                        entry["va"] = base_i + r
                    out_syms[nm] = entry
                if not out_syms and fallback == "pattern":
                    # v0.31 Phase 1.7: curated-pattern fallback for sealed
                    # kernels. Reads a short window of the live module and
                    # scans each requested name's signatures; the recovered
                    # VA is the rip+disp32 target of the matched prologue.
                    # Confidence is low by default — the pattern pack is a
                    # last-resort source when PDBs are unreachable, never
                    # audit-grade.
                    try:
                        from ... import symbols_patterns as _sp
                    except Exception:  # noqa: BLE001
                        _sp = None  # type: ignore
                    if _sp is not None and view:
                        try:
                            client = ctx.session.require_client(view)
                        except Exception:  # noqa: BLE001
                            client = None
                        if client is not None:
                            kernel = ctx.session.view_kind_of(view) \
                                != "user"
                            base_live = await _live_module_base(
                                ctx, view, img_name, pid) if not base_i \
                                else base_i
                            # Read a generous window — most kernel exports
                            # live in .text, which starts near base.
                            buf = b""
                            try:
                                buf = await client.mem_read(
                                    pid, int(base_live), 0x40_0000,
                                    "kernel" if kernel else "user")
                            except Exception:  # noqa: BLE001
                                buf = b""
                            if buf and base_live:
                                for nm in want:
                                    entries = _sp.pack_entries(
                                        module=img_name, name=nm)
                                    best_va: int | None = None
                                    hits = 0
                                    for entry in entries:
                                        needle, mask = _sp.parse_pattern(
                                            entry.pattern)
                                        # Scan buf for a masked match.
                                        for i in range(
                                                0, len(buf) - len(needle) + 1):
                                            ok = True
                                            for k in range(len(needle)):
                                                if mask[k] and \
                                                        buf[i + k] != needle[k]:
                                                    ok = False
                                                    break
                                            if not ok:
                                                continue
                                            disp = _sp.disp_at(
                                                buf, i +
                                                entry.rip_rel_disp_offset)
                                            # Instruction ends 4 bytes
                                            # after the disp32 within the
                                            # 7-byte LEA/MOV prologue.
                                            insn_end = (int(base_live) + i
                                                        + entry
                                                        .rip_rel_disp_offset
                                                        + 4)
                                            match_va = (insn_end + disp) & \
                                                0xFFFF_FFFF_FFFF_FFFF
                                            hits += 1
                                            if best_va is None:
                                                best_va = match_va
                                            elif best_va != match_va:
                                                best_va = None
                                                break
                                    if best_va is not None:
                                        out_syms[nm] = {
                                            "rva": best_va -
                                                   int(base_live),
                                            "va": best_va,
                                            "source": "pattern",
                                            "confidence":
                                                ("high" if hits >= 2
                                                 else "low"),
                                            "pattern_hits": hits,
                                        }
                if not out_syms:
                    return _j({"ok": False, "kind": "symbol_not_found",
                               "error": f"none of {want!r} resolved in "
                                        f"{img_name!r}"
                                        + (" (pattern fallback also "
                                           "failed)" if fallback == "pattern"
                                           else ""),
                               "image": img_name,
                               "hint": ("try fallback='pattern' with "
                                        "view='kernel' when PDBs are "
                                        "unreachable")
                                        if fallback != "pattern" else ""})
                payload: dict[str, Any] = {"ok": True, "image": img_name,
                                           "symbols": out_syms}
                if missing:
                    payload["unresolved"] = missing
                if base_i:
                    payload["module_base"] = base_i
                elif view:
                    payload["note"] = (f"view={view!r} had no module "
                                       f"{img_name!r} — rva only")
                else:
                    payload["hint"] = ("pass base=<module base> or "
                                       "view='kernel'|'user' to get VA too")
                return _j_hex(payload)

            if action == "lookup":
                rva_i = _addr(rva, name="rva") if rva else None
                va_i = _addr(va, name="va") if va else None
                base_i = _addr(base, name="base") if base else None
                if rva_i is None and va_i is not None:
                    if base_i is None and view:
                        base_i = await _live_module_base(ctx, view,
                                                         img_name, pid)
                    if base_i is None:
                        return _j({"ok": False, "kind": "invalid_parameter",
                                   "error": "lookup with va= needs base= "
                                            "or a connected view= to turn "
                                            "it into an RVA"})
                    rva_i = va_i - base_i
                    if rva_i < 0:
                        return _j({"ok": False,
                                   "kind": "invalid_parameter",
                                   "error": f"va 0x{va_i:X} is below "
                                            f"base 0x{base_i:X}"})
                if rva_i is None:
                    return _j({"ok": False, "kind": "invalid_parameter",
                               "error": "lookup needs rva= or va="})
                try:
                    hit = await asyncio.to_thread(
                        _sym.lookup_rva, img, rva_i, pdb_dir,
                        allow_dl, servers)
                except _sym.SymbolError as exc:
                    return _j(_err_sym(exc))
                if not hit.get("found"):
                    return _j_hex({"ok": False, "kind": "symbol_not_found",
                                   "error": f"no symbol covers rva "
                                            f"0x{rva_i:X} in {img_name!r}",
                                   "rva": rva_i, "image": img_name})
                out: dict[str, Any] = {"ok": True, "image": img_name,
                                       "symbol": hit["name"],
                                       "symbol_rva": hit["rva"],
                                       "rva": rva_i,
                                       "displacement": hit["displacement"]}
                # Confidence: SymFromAddrW is a NEAREST-match — a huge
                # displacement usually means no real PDB coverage for
                # this RVA (repaired GUID, wrong build, export-only
                # fallback), not "the instruction is 36 KB into the
                # symbol". Say so instead of emitting confident-looking
                # junk; max_disp= raises the threshold per call.
                try:
                    disp_limit = _addr(max_disp, name="max_disp") or 0x1000
                except ValueError:
                    disp_limit = 0x1000
                if int(hit.get("displacement") or 0) > disp_limit:
                    out["confidence"] = "low"
                    out["warning"] = (
                        f"nearest-symbol displacement "
                        f"0x{int(hit.get('displacement') or 0):x} exceeds "
                        f"max_disp 0x{disp_limit:x} — likely no PDB "
                        "coverage for this address (repaired RSDS, "
                        "build mismatch, or export-only fallback); "
                        "treat the name as a guess")
                else:
                    out["confidence"] = "high"
                if base_i:
                    out["va"] = base_i + rva_i
                    out["symbol_va"] = base_i + hit["rva"]
                return _j_hex(out)

            if action == "layout":
                tname = type_name or name
                if not tname:
                    return _j({"ok": False, "kind": "invalid_parameter",
                               "error": "layout needs type_name= "
                                        "(e.g. '_EPROCESS')"})
                try:
                    res = await asyncio.to_thread(
                        _sym.type_layout, img, tname, pdb_dir,
                        allow_dl, servers, max(1, depth))
                except _sym.SymbolError as exc:
                    return _j(_err_sym(exc))
                if not res.get("ok"):
                    return _j(res)
                return _j({"ok": True, "image": img_name, **res})

            return _unknown_action("symbols_manage", action, SYMBOL_ACTIONS, _SYMBOL_ACTION_HELP)

        return await _guard(ctx, "symbols_manage", action, args, run)
