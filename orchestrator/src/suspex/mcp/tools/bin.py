"""Binary-analysis tool registration — ``bin_manage``.

Static analysis of binaries the orchestrator already holds: module dumps
under ``artifacts/`` (``file_manage dump_module`` / ``moddump`` output),
auto-spilled payloads, or a live module's in-memory image pulled through
the connected view (``source="memory"``).

This is the knife-derived surface: it parses PE structure and runs
extraction/audit passes WITHOUT opening IDA. Deep disassembly-level work
(function recovery, CFG, xrefs, decompile) still lives behind
``ida_manage`` — bin_manage answers the triage questions.

Path inputs are sandboxed to ``artifacts_dir`` (same rule as
``grep_artifact``); a bare 64-hex ``sha256`` resolves through the spill
store. ``source="memory"`` reads the target and needs a connected view.
"""

from __future__ import annotations

import asyncio

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .. import _coverage

_BIN_ACTIONS = [
    "info", "sections", "imports", "exports", "hashes", "imphash",
    "sec", "strings", "iocs", "entropy", "scan", "caps",
    "funcs", "disasm_func", "xrefs", "paths", "callgraph", "cfg",
    "irp_surface", "ioctl_surface", "audit", "diff", "pseudo",
    "gadgets", "gadget_check", "chain_check",
    # background function-inventory builds for big images
    "analyze", "analyze_status", "analyze_list",
    # v0.22 discoverability
    "actions",
]

# Engine actions whose results carry a static-analysis coverage block
# (cfg / xrefs / rop gadget passes / ioctl_surface).
_ANALYSIS_COVERAGE_ACTIONS = frozenset({
    "cfg", "xrefs", "gadgets", "gadget_check", "chain_check",
    "ioctl_surface",
})

_BIN_ACTION_HELP = {
    "actions": {"one_liner": "this list — per-verb help",
                "key_args": "none",
                "example": "bin_manage(action='actions')"},
    "info": {"one_liner": "PE headers — timestamps, cert table, Rich "
                          "header, debug dir",
             "key_args": "path | sha256 | module+pid",
             "example": "bin_manage(action='info', sha256='...')"},
    "sections": {"one_liner": "section table + per-section entropy",
                 "key_args": "path|sha256",
                 "example": "bin_manage(action='sections', path='x.sys')"},
    "imports": {"one_liner": "import table grouped by DLL",
                "key_args": "path|sha256",
                "example": "bin_manage(action='imports', sha256='...')"},
    "exports": {"one_liner": "export table",
                "key_args": "path|sha256",
                "example": "bin_manage(action='exports', sha256='...')"},
    "hashes": {"one_liner": "sha256 + authentihash + per-section digests",
               "key_args": "path|sha256",
               "example": "bin_manage(action='hashes', sha256='...')"},
    "imphash": {"one_liner": "import hash (pefile convention)",
                "key_args": "path|sha256",
                "example": "bin_manage(action='imphash', sha256='...')"},
    "sec": {"one_liner": "security posture — signing, mitigations "
                         "(CFG/GS/ASLR), cert chain",
            "key_args": "path|sha256",
            "example": "bin_manage(action='sec', sha256='...')"},
    "strings": {"one_liner": "extract printable strings (raw bytes, no PE "
                             "parse needed)",
                "key_args": "path|sha256, min_len",
                "example": "bin_manage(action='strings', sha256='...', "
                           "min_len=8)"},
    "iocs": {"one_liner": "extract indicators — URLs, IPs, registry "
                          "paths, file paths",
             "key_args": "path|sha256",
             "example": "bin_manage(action='iocs', sha256='...')"},
    "entropy": {"one_liner": "whole-blob + windowed entropy profile",
                "key_args": "path|sha256, buckets",
                "example": "bin_manage(action='entropy', sha256='...')"},
    "scan": {"one_liner": "byte-pattern scan over the source buffer",
             "key_args": "path|sha256, pattern",
             "example": "bin_manage(action='scan', sha256='...', "
                        "pattern='4C8B??15')"},
    "caps": {"one_liner": "capability inference — what the binary can "
                          "do (heuristic)",
             "key_args": "path|sha256",
             "example": "bin_manage(action='caps', sha256='...')"},
    "funcs": {"one_liner": "function inventory (paged)",
              "key_args": "path|sha256, limit, offset",
              "example": "bin_manage(action='funcs', sha256='...')"},
    "disasm_func": {"one_liner": "disassemble one function",
                    "key_args": "path|sha256, func",
                    "example": "bin_manage(action='disasm_func', "
                               "sha256='...', func='0x1000')"},
    "xrefs": {"one_liner": "xrefs to an address/string",
              "key_args": "path|sha256, target",
              "example": "bin_manage(action='xrefs', sha256='...', "
                         "target='0x1000')"},
    "paths": {"one_liner": "execution paths between two points",
              "key_args": "path|sha256, func, target",
              "example": "bin_manage(action='paths', sha256='...', "
                         "func='0x1000', target='0x1400')"},
    "callgraph": {"one_liner": "function call graph",
                  "key_args": "path|sha256, func",
                  "example": "bin_manage(action='callgraph', sha256='...')"},
    "cfg": {"one_liner": "control-flow graph for a function",
            "key_args": "path|sha256, func",
            "example": "bin_manage(action='cfg', sha256='...', "
                       "func='0x1000')"},
    "irp_surface": {"one_liner": "driver IRP dispatch surface",
                    "key_args": "path|sha256",
                    "example": "bin_manage(action='irp_surface', "
                               "sha256='...')"},
    "ioctl_surface": {"one_liner": "driver IOCTL surface — CTL codes + "
                                   "dispatch paths",
                      "key_args": "path|sha256",
                      "example": "bin_manage(action='ioctl_surface', "
                                 "sha256='...')"},
    "audit": {"one_liner": "bundled security audit — surfaces + "
                           "dangerous-API hits",
              "key_args": "path|sha256",
              "example": "bin_manage(action='audit', sha256='...')"},
    "diff": {"one_liner": "diff two binaries (bindiff-lite)",
             "key_args": "path|sha256, compare_path",
             "example": "bin_manage(action='diff', sha256='...', "
                        "compare_path='old.sys')"},
    "pseudo": {"one_liner": "pseudo-C rendering of a function (no IDA)",
               "key_args": "path|sha256, func",
               "example": "bin_manage(action='pseudo', sha256='...', "
                          "func='0x1000')"},
    "gadgets": {"one_liner": "ROP/JOP gadget inventory over exec regions",
                "key_args": "path|sha256, ending, category, bad_bytes",
                "example": "bin_manage(action='gadgets', sha256='...')"},
    "gadget_check": {"one_liner": "verify specific gadget bytes at an "
                                  "address",
                     "key_args": "path|sha256, address",
                     "example": "bin_manage(action='gadget_check', "
                                "sha256='...', address='0x1234')"},
    "chain_check": {"one_liner": "emulate-validate a ROP chain buffer",
                    "key_args": "path|sha256, address, size",
                    "example": "bin_manage(action='chain_check', "
                               "sha256='...', address='0x...')"},
    "analyze": {"one_liner": "warm the function-inventory cache in the "
                             "background (multi-MB images)",
                "key_args": "path|sha256",
                "example": "bin_manage(action='analyze', "
                           "path='dumps/big.sys')"},
    "analyze_status": {"one_liner": "poll a background analysis job",
                       "key_args": "job_id",
                       "example": "bin_manage(action='analyze_status', "
                                  "job_id='a0001')"},
    "analyze_list": {"one_liner": "list analysis jobs",
                     "key_args": "none",
                     "example": "bin_manage(action='analyze_list')"},
}

# Actions that only need the raw bytes — no PE parse attempted.
# (Gadget actions scan exec regions of a PE when one parses, but a raw
# blob is a valid source too — the whole buffer is treated as exec.)
_BYTES_ACTIONS = frozenset({"strings", "iocs", "entropy", "scan", "hashes",
                            "gadgets", "gadget_check", "chain_check"})

_MAX_SOURCE_BYTES = 256 * 1024 * 1024  # refuse to ingest past this

# hexify keys beyond the shared HEX_ADDRESS_KEYS — analysis rows carry
# domain-specific scalar address fields the generic set doesn't name.
# (Lists of VAs are hex-formatted at construction — hexify only touches
# scalar values.)
_BIN_ADDR_KEYS = frozenset({
    "entry_va", "handler_va", "site_va", "function_va", "thunk_va",
    "fastio_dispatch_va", "image_base", "driver_start", "driver_object",
    "expected_rva", "live", "rva", "from", "to", "target", "driver_size",
    # Gadget scan / emulation validation surfaces.
    "base_va", "start_ip", "end_ip", "chain_base", "sentinel_va",
    "scratch_va", "fault_va",
})
_BIN_SIZE_KEYS = frozenset({
    "driver_size", "size_of_image", "overlay_size", "cert_size",
    "raw_size", "vsize",
})


def _jh(data: Any) -> Any:
    """bin_manage envelope — hexify with the extended address-key set."""
    from .._hex_addresses import HEX_ADDRESS_KEYS, HEX_SIZE_KEYS, hexify_dict
    return _j(hexify_dict(
        data,
        addr_keys=HEX_ADDRESS_KEYS | _BIN_ADDR_KEYS,
        size_keys=HEX_SIZE_KEYS | _BIN_SIZE_KEYS,
        add_int_mirror=True))


def register(mcp, ctx: Context) -> None:
    """Register the ``bin_manage`` tool on *mcp*, using *ctx* for state."""
    # -------------------------------------------------------------- bin_manage --

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def bin_manage(action: Annotated[str, Field(json_schema_extra={"enum": _BIN_ACTIONS})],
                         path: str = "",
                         sha256: str = "",
                         source: str = "artifact",
                         module: str = "",
                         pid: int = 0,
                         address: Any = 0,
                         size: int = 0,
                         space: str = "user",
                         name: str = "",
                         kernel: bool = False,
                         layout: str = "auto",
                         min_len: int = 5,
                         buckets: int = 64,
                         target: Any = "",
                         func: Any = "",
                         compare_path: str = "",
                         reachability: str = "",
                         max_functions: int = 20000,
                         max_instructions: int = 0,
                         limit: int = 0,
                         offset: int = 0,
                         cursor: str = "",
                         verbosity: str = "normal",
                         filter: Any = "",
                         summary: bool = False,
                         fields: list[str] | None = None,
                         ending: str = "",
                         category: str = "",
                         reg: str = "",
                         bad_bytes: str = "",
                         max_len: int = 0,
                         max_gadget_bytes: int = 0,
                         scan_budget: int = 0,
                         unique: bool = False,
                         refresh: bool = False,
                         chain: Any = "",
                         expected_json: str = "",
                         job_id: str = "") -> str:
        """Static binary analysis of artifacts and live module images —
        PE parse (info/imports/sec/caps), byte surface
        (strings/iocs/entropy/scan), code engine (funcs/cfg/xrefs/paths/
        callgraph), driver IRP+IOCTL surfaces, audit/diff/pseudo, ROP
        gadget scan + Unicorn validation. Source via sha256=, path=
        (artifacts-relative), or source='memory' + module=/address=.
        Per-verb help: bin_manage(action='actions')."""
        args = {"action": action, "path": path or sha256 or module,
                "source": source}

        async def run() -> Any:
            from ... import analysis as _an  # local import — cold path
            if action not in _BIN_ACTIONS:
                return _unknown_action("bin_manage", action, _BIN_ACTIONS, _BIN_ACTION_HELP)
            if action == "actions":
                # v0.22: pure-compute discovery, before _load_source.
                return _actions_help("bin_manage", _BIN_ACTION_HELP)

            # Job-registry verbs answer without loading a source.
            if action in ("analyze_status", "analyze_list"):
                from . import bin_engine as _be
                if action == "analyze_status":
                    return _jh(_be.ajob_status(job_id,
                                               current_client_id()))
                return _jh(_be.ajob_list(current_client_id()))

            data, origin, img_base, img, salvage = await _load_source(
                ctx, source=source, path=path, sha256=sha256,
                module=module, pid=pid, address=address, size=size,
                space=space, name=name, kernel=kernel, layout=layout,
                action=action)
            if isinstance(data, str):  # error envelope from the loader
                return data

            # Breadcrumb: analysis actions on artifacts get indexed so a
            # peer's knowledge_manage(about, artifact_sha=…) surfaces it.
            _bin_breadcrumb(ctx, action, data, origin)

            # Big-image engine work goes through the job surface: a cold
            # inventory over ~1 MiB+ of exec bytes outlives client-side
            # MCP timeouts even off the loop. Small images and warm
            # caches still run inline. `analyze` is the explicit verb.
            from . import bin_engine as _be
            if action == "analyze" or action in _be.ENGINE_ACTIONS:
                from ...analysis import engine as _eng
                budget = max_instructions or _eng.ANALYSIS_BUDGET
                if action == "analyze":
                    job = _be.start_or_join_analysis(
                        data, _be._engine_view(_an, data, img, img_base),
                        budget, origin, current_client_id(),
                        refresh=refresh)
                    if job.get("status") == "ready":
                        return _jh({"ok": True, "kind": "analysis_ready",
                                    "cached": True, "origin": origin,
                                    "hint": "inventory is cached — engine "
                                            "actions (funcs/xrefs/cfg/…) "
                                            "return instantly now"})
                    return _jh(_be.ajob_status(job["analyze_id"],
                                               current_client_id()))
                gated = _be.maybe_start_job(
                    action, data, img, img_base, budget, origin,
                    current_client_id(), refresh=refresh)
                if gated is not None:
                    return _jh(gated)

            # Off the event loop: the engine actions (funcs/xrefs/cfg/
            # audit/gadgets/…) run a synchronous recursive-descent decode
            # that takes tens of seconds on a multi-MB image — inline that
            # stalls every other MCP request and reads as a dead server.
            # Everything under _dispatch_bin is sync + touches only
            # ctx.cfg, so to_thread is safe.
            return await asyncio.to_thread(
                _dispatch_bin, ctx, _an, action, data, img, img_base,
                                 min_len=min_len, buckets=buckets,
                                 target=target, func=func,
                                 compare_path=compare_path,
                                 reachability=reachability,
                                 max_functions=max_functions,
                                 max_instructions=max_instructions,
                                 limit=limit, offset=offset,
                                 fields=fields, filter=filter,
                                 summary=summary,
                                 verbosity=verbosity,
                                 ending=ending, category=category,
                                 reg=reg, bad_bytes=bad_bytes,
                                 max_len=max_len,
                                 max_gadget_bytes=max_gadget_bytes,
                                 salvage=salvage,
                                 scan_budget=scan_budget,
                                 unique=unique, refresh=refresh,
                                 chain=chain,
                                 expected_json=expected_json)

        return await _guard(ctx, "bin_manage", action, args, run)


# ---------------------------------------------------------------------------
# Source loading — artifact path / spill sha / live memory.
# ---------------------------------------------------------------------------

async def _load_source(ctx: Context, *, source: str, path: str,
                       sha256: str, module: str, pid: int,
                       address: Any, size: int, space: str, name: str,
                       kernel: bool, layout: str,
                       action: str):
    """Resolve the input buffer.

    Returns ``(data:bytes, origin:str, image_base:int|None, img|None,
    salvage:dict|None)`` — *salvage* is set when a ``source="memory"``
    read needed the bisect-and-zero-fill path (``{"holes": [...],
    "bytes_missing": N}``), else ``None``. Error form:
    ``(envelope_str, "", 0, None, None)``.
    """
    import re as _re
    from ...analysis import pe as _pe

    if source == "memory":
        data, origin, base, size_img, salvage = await _load_memory(
            ctx, module=module, pid=pid, address=address, size=size,
            space=space, name=name, kernel=kernel, action=action)
        if isinstance(data, str):
            return data, origin, 0, None, None
        img = _maybe_parse(_pe, data, "image")
        return data, origin, base, img, salvage

    if source not in ("artifact", "file"):
        return _j({"ok": False, "kind": "bad_arg",
                   "error": f"bin_manage: unknown source {source!r}",
                   "hint": "source= 'artifact' | 'memory'"}), "", 0, None, None

    p = None
    if sha256:
        if not _re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "bin_manage: sha256 must be 64 hex chars"}), \
                "", 0, None, None
        # v0.27: whole-store lookup — dumps/, ingested/, spill/, and
        # store_binary workdirs all carry their content sha, not just
        # spill/.
        from .._artifacts import find_artifact_by_sha
        hit = find_artifact_by_sha(ctx.cfg, sha256)
        if hit is None:
            return _j({"ok": False, "kind": "artifact_missing",
                       "error": f"no artifact for sha256 "
                                f"{sha256[:12]}…",
                       "hint": "file_manage(action='list_artifacts') to see "
                               "what's on disk"}), "", 0, None, None
        p = Path(hit[0])
    elif path:
        # Canonical artifact-path resolution — 'dumps/x.sys',
        # 'artifacts/dumps/x.sys', and the abs_path list_artifacts emits
        # all land on the same file; anything outside the store roots is
        # refused (bin_manage is an orchestrator-side tool, not a general
        # FS browser).
        from .._artifacts import resolve_artifact_path
        p = resolve_artifact_path(ctx.cfg, path)
        if p is None:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"bin_manage: {path!r} is outside "
                                "artifacts_dir",
                       "hint": "analysis input must live under artifacts/ "
                               "(dump_module lands there) — for a local file "
                               "outside the sandbox use file_manage("
                               "action='ingest', local_path=…) then pass the "
                               "returned path"}), \
                "", 0, None, None
    else:
        return _j({"ok": False, "kind": "bad_arg",
                   "error": "bin_manage: need sha256=, path=, or "
                            "source='memory'",
                   "hint": "dump a module with file_manage(action="
                           "'dump_module') then pass its path"}), "", 0, None, None

    try:
        st_size = p.stat().st_size
    except OSError as exc:
        return _j({"ok": False, "kind": "file_not_found",
                   "error": f"bin_manage: {exc}"}), "", 0, None, None
    if st_size > _MAX_SOURCE_BYTES:
        return _j({"ok": False, "kind": "input_too_large",
                   "error": f"{p.name} is {st_size} bytes — over the "
                            f"{_MAX_SOURCE_BYTES} cap",
                   "hint": "split the dump or analyze a single section"}), \
            "", 0, None, None
    try:
        data = p.read_bytes()
    except OSError as exc:
        return _j({"ok": False, "kind": "read_failed",
                   "error": f"bin_manage: {exc}"}), "", 0, None, None
    img = _maybe_parse(_pe, data, layout)
    base = img.image_base if img is not None else 0
    return data, f"artifact:{p}", base, img, None


async def _load_exports_sparse(c, pid: int, base: int, mod_size: int,
                               space: str, origin: str):
    """Export-table-only image fetch for ``source="memory"``.

    Reads just the PE headers plus the export directory region and
    assembles them into an image-layout buffer (``rva_to_off`` is identity
    in image layout, so gaps between regions parse as unmapped). A kernel
    image is ~20 MB — this keeps `bin_manage(action='exports')` from
    pulling the whole thing across the wire just to reach a 4 KB .edata.

    Returns ``(data, origin, base, mod_size)`` or ``None`` to fall back to
    the full-image read.
    """
    from ...analysis import pe as _pe

    try:
        hdr = await c.mem_read(pid, base, 0x1000, space)
        if isinstance(hdr, tuple):
            hdr = hdr[0]
        if len(hdr) < 0x40 or hdr[:2] != b"MZ":
            return None
        need = _pe.header_extent(hdr)
        if need > len(hdr):
            hdr = await c.mem_read(pid, base, min(need, 0x100000), space)
            if isinstance(hdr, tuple):
                hdr = hdr[0]
        img0 = _pe.parse(bytes(hdr), layout="image")
    except Exception:
        return None
    edata_rva, edata_size = img0.directories[0]
    if not edata_rva or not edata_size:
        # No export directory — the headers alone are the full answer.
        return bytes(hdr), origin, base, mod_size
    # +0x1000 slack: forwarder/name strings can straddle the directory's
    # declared end. Clamp to the module's mapped size.
    want_end = edata_rva + edata_size
    if mod_size:
        want_end = min(want_end + 0x1000, mod_size)
    try:
        ed = await c.mem_read(pid, base + edata_rva,
                              want_end - edata_rva, space)
        if isinstance(ed, tuple):
            ed = ed[0]
    except Exception:
        # .edata paged out / read refused — let the caller take the
        # full-image path, which has its own salvage.
        return None
    if not ed:
        return None
    buf = bytearray(max(len(hdr), edata_rva + len(ed)))
    buf[: len(hdr)] = hdr
    buf[edata_rva: edata_rva + len(ed)] = ed
    return bytes(buf), origin, base, mod_size


# Salvage granularity: first try 1 MiB reads, bisect failures down to a
# page. The driver's PARTIAL walk stops at the first page MmCopyMemory
# refuses and completes the IOCTL with STATUS_PARTIAL_COPY — which the
# I/O manager turns into a *failed* DeviceIoControl (gle=299) and drops
# the partial bytes, so a single big read cannot salvage a module with
# paged-out pages. Bisecting re-reads the resident neighbours and
# zero-fills only the pages that actually refuse.
_SALVAGE_CHUNK = 1 << 20
_SALVAGE_PAGE = 0x1000


async def _salvage_read(c, pid: int, base: int, size: int, space: str,
                        buf: bytearray, off: int,
                        holes: list[dict]) -> None:
    """Read ``[base, base+size)`` into ``buf[off:]``, bisecting on failure
    and zero-filling pages that refuse."""
    if size <= 0:
        return
    try:
        data = await c.mem_read(pid, base, size, space, partial=True)
        if isinstance(data, tuple):
            data = data[0]
    except Exception:
        data = b""
    if len(data) >= size:
        buf[off:off + size] = data
        return
    if data:
        # Short read — a driver that *does* deliver the prefix. Keep the
        # bytes and continue right after them (the hole follows).
        buf[off:off + len(data)] = data
        await _salvage_read(c, pid, base + len(data), size - len(data),
                            space, buf, off + len(data), holes)
        return
    if size <= _SALVAGE_PAGE:
        holes.append({"va": base, "offset": off, "size": size})
        return
    half = max(_SALVAGE_PAGE, (size // 2) & ~0xFFF)
    await _salvage_read(c, pid, base, half, space, buf, off, holes)
    await _salvage_read(c, pid, base + half, size - half, space,
                        buf, off + half, holes)


def _merge_holes(holes: list[dict]) -> list[dict]:
    """Coalesce adjacent page holes into ranges (reporting only)."""
    if not holes:
        return []
    out = [dict(holes[0])]
    for h in holes[1:]:
        last = out[-1]
        if h["offset"] == last["offset"] + last["size"]:
            last["size"] += h["size"]
        else:
            out.append(dict(h))
    return out


async def _salvage_module(c, pid: int, base: int, size: int,
                          space: str) -> tuple[bytearray, list[dict]]:
    """Chunked read of a whole module with hole zero-fill.

    Returns ``(buffer, holes)`` — holes are page-granular, coalesced,
    zero-filled regions (the same policy ``file_manage dump_module``
    applies to discarded PAGE/INIT sections). The buffer stays a
    bytearray so the caller can merge the fast-path prefix over it.
    """
    buf = bytearray(size)
    holes: list[dict] = []
    off = 0
    while off < size:
        want = min(_SALVAGE_CHUNK, size - off)
        await _salvage_read(c, pid, base + off, want, space, buf, off, holes)
        off += want
    return buf, _merge_holes(holes)


async def _stream_module(c, pid: int, base: int, size: int,
                         space: str) -> bytes | None:
    """Collect a module image via ``Memory.ReadStream`` — the streaming RPC
    has no ``maxMemReadBytes`` ceiling (it reads in 1 MiB chunks), unlike
    the unary ``Memory.Read``. Returns the contiguous prefix fetched;
    ``None`` when streaming is unavailable or the first read failed.
    """
    if not hasattr(c, "mem_read_stream"):
        return None
    buf = bytearray(size)
    got = 0
    try:
        async for off, chunk in c.mem_read_stream(pid, base, size, space):
            end = min(off + len(chunk), size)
            if off < end:
                buf[off:end] = chunk[: end - off]
                got = max(got, end)
    except Exception:
        pass
    if got < 0x40:
        return None
    return bytes(buf[:got])


async def _load_memory(ctx: Context, *, module: str, pid: int,
                       address: Any, size: int, space: str, name: str,
                       kernel: bool, action: str = ""):
    """Pull a live module image (or raw range) through the connected view."""
    try:
        c = ctx.session.require_client(name)
    except Exception as exc:
        return _j({"ok": False, "kind": "no_target",
                   "error": f"bin_manage memory source: {exc}",
                   "hint": "target_manage(action='connect') first"}), "", 0, 0, None

    use_kernel = kernel or space in ("kernel", "physical")
    base, mod_size = 0, 0
    if module:
        try:
            mods = await c.mem_modules(pid, use_kernel)
        except Exception as exc:
            return _j({"ok": False, "kind": "enum_failed",
                       "error": f"module list failed: {exc}"}), "", 0, 0, None
        mlow = module.lower()
        hit = None
        for m in mods:
            mname = str(m.get("name") or "").split("\\")[-1].split("/")[-1]
            if mname.lower() == mlow or \
                    str(m.get("path") or "").lower().endswith(mlow):
                hit = m
                break
        if hit is None:
            return _j({"ok": False, "kind": "module_not_found",
                       "error": f"module {module!r} not in the "
                                f"{'kernel' if use_kernel else 'user'} list",
                       "hint": "mem_rw(action='modules') to browse"}), "", 0, 0, None
        base = int(hit.get("base", 0))
        mod_size = int(hit.get("size", 0))
    else:
        if not address:
            return _j({"ok": False, "kind": "bad_arg",
                       "error": "memory source needs module= or "
                                "address=[+size]"}), "", 0, 0, None
        try:
            base = int(address) if not isinstance(address, str) \
                else int(address, 0)
        except (TypeError, ValueError):
            return _j({"ok": False, "kind": "bad_arg",
                       "error": f"bad address {address!r}"}), "", 0, 0, None
        mod_size = size
    if not mod_size:
        # Try reading the headers to discover SizeOfImage, else default 1 MiB.
        try:
            hdr = await c.mem_read(pid, base, 0x400,
                                   "kernel" if use_kernel else "user",
                                   partial=True)
            if isinstance(hdr, tuple):
                hdr = hdr[0]
            if len(hdr) >= 0x40 and hdr[:2] == b"MZ":
                import struct as _st
                e_lfanew = _st.unpack_from("<I", hdr, 0x3C)[0]
                if e_lfanew + 0x5C <= len(hdr):
                    magic = _st.unpack_from(
                        "<H", hdr, e_lfanew + 24)[0]
                    off = e_lfanew + 24 + 56
                    if magic in (0x10B, 0x20B) and off + 4 <= len(hdr):
                        mod_size = _st.unpack_from("<I", hdr, off)[0]
        except Exception:
            pass
        if not mod_size or mod_size > _MAX_SOURCE_BYTES:
            mod_size = min(mod_size or (1 << 20), _MAX_SOURCE_BYTES)
    read_space = "kernel" if use_kernel else "user"
    origin = (f"memory:{'kernel' if use_kernel else 'user'}:"
              f"{module or hex(base)}")
    if action == "exports":
        # Fast path: headers + .edata only — a 20 MB kernel image trips
        # the unary read cap for a 4 KB answer otherwise.
        fast = await _load_exports_sparse(c, pid, base, mod_size,
                                          read_space, origin)
        if fast is not None:
            return fast[0], fast[1], fast[2], fast[3], None
    # Fast path: one read. Over the unary cap ReadStream has no
    # maxMemReadBytes ceiling — it walks in 1 MiB chunks.
    cap = int(getattr(ctx.cfg.security, "max_mem_read_mb", 8)) * 1024 * 1024
    data: bytes | None = None
    if mod_size > cap and hasattr(c, "mem_read_stream"):
        data = await _stream_module(c, pid, base, mod_size, read_space)
    else:
        try:
            got = await c.mem_read(pid, base, mod_size, read_space,
                                   partial=True, want_meta=True)
            data = got[0] if isinstance(got, tuple) else got
        except TypeError:
            try:
                data = await c.mem_read(pid, base, mod_size, read_space,
                                        partial=True)
            except Exception:
                data = None
        except Exception:
            data = None
    if data and len(data) >= mod_size:
        return bytes(data), origin, base, mod_size, None

    # Salvage: the fast path failed or came up short (paged-out pages —
    # driver v1.3+ delivers the valid prefix; older builds fail the IOCTL
    # with gle=299 and drop the bytes). Re-read in bisected chunks —
    # resident pages come back, refused pages are zero-filled and
    # reported so callers can tell "no gadgets here" from "no data here".
    buf, holes = await _salvage_module(c, pid, base, mod_size, read_space)
    if data:
        buf[:len(data)] = data[:mod_size]  # keep the fast-path prefix
    if not any(buf):
        return _j({"ok": False, "kind": "read_failed",
                   "error": f"bin_manage: read of {mod_size} bytes at "
                            f"{hex(base)} returned nothing",
                   "hint": "check the address with mem_rw(action='probe_va');"
                           " exports only? bin_manage(action='exports') "
                           "fetches just the .edata region"}), "", 0, 0, None
    salvage = {"holes": holes,
               "bytes_missing": sum(h["size"] for h in holes)}
    if holes:
        salvage["note"] = ("paged-out/unreadable pages are zero-filled "
                           "(same policy as file_manage dump_module); "
                           "gadgets/functions in those ranges are absent, "
                           "not 'none'")
    return bytes(buf), origin, base, mod_size, salvage


def _maybe_parse(_pe, data: bytes, layout: str):
    """Parse PE under the requested layout; 'auto' tries file then image.
    Returns a PeImage or None (non-PE buffers are still analyzable by the
    byte-surface actions)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    for lay in (("file", "image") if layout == "auto" else (layout,)):
        try:
            img = _pe.parse(data, layout=lay)
        except Exception:
            continue
        # Sanity: in file layout the entrypoint must map into the buffer;
        # if it doesn't, the image was likely dumped as-mapped.
        if lay == "file" and layout == "auto":
            if img.entry_rva and img.rva_to_off(img.entry_rva) is None \
                    and img.sections and all(s.raw_off == 0
                                             for s in img.sections):
                continue
        return img
    return None


def _bin_breadcrumb(ctx: Context, action: str, data: bytes,
                    origin: str) -> None:
    """Best-effort artifact index row + tool event for the analyzed image."""
    try:
        sha = hashlib.sha256(data).hexdigest()
        cid = current_client_id()
        sid = ctx.get_current_session_id(cid) or ""
        alias = origin.rsplit(":", 1)[-1].rsplit("/", 1)[-1] \
            .rsplit("\\", 1)[-1]
        ctx.ledger.upsert_artifact(
            sha, name=alias, kind=_kind_from_ext(alias),
            size=len(data), origin=f"bin_manage:{action}", alias=alias)
        ctx.ledger.event(
            "bin_manage", action, agent_id=cid, session_id=sid,
            artifact_sha=sha, module=alias,
            summary=f"{action} on {origin} ({len(data)} bytes)")
    except Exception:
        pass


def _dispatch_bin(ctx: Context, _an, action: str, data: bytes, img,
                  img_base: int, *, min_len: int, buckets: int,
                  target: Any, func: Any, compare_path: str,
                  reachability: str, max_functions: int,
                  max_instructions: int, limit: int, offset: int,
                  fields: Any, filter: Any, summary: bool,
                  verbosity: str, ending: str = "", category: str = "",
                  reg: str = "", bad_bytes: str = "", max_len: int = 0,
                  max_gadget_bytes: int = 0, scan_budget: int = 0,
                  unique: bool = False, refresh: bool = False,
                  chain: Any = "", expected_json: str = "",
                  salvage: dict | None = None) -> str:
    """Route one bin_manage action to its analysis pass."""
    from ...analysis import caps as _caps
    from ...analysis import entropy as _entropy
    from ...analysis import extract as _extract
    from ...analysis import hardening as _hard
    from ...analysis import pe as _pe
    from ...analysis import signatures as _sigs

    needs_pe = action not in _BYTES_ACTIONS
    if needs_pe and img is None:
        return _j({"ok": False, "kind": "bad_magic",
                   "error": f"{action}: source is not a parseable PE",
                   "hint": "byte-surface actions (strings/iocs/entropy/scan/"
                           "hashes) still work on raw buffers"})
    list_kw = dict(tool="bin_manage", action=action,
                   limit=limit, offset=offset, fields=fields or (),
                   filter=filter, summary=summary,
                   global_cap=ctx.cfg.mcp_max_items())

    if action == "info":
        return _jh(_info(img))
    if action == "sections":
        rows = []
        for s in img.sections:
            raw = data[s.raw_off:s.raw_off + s.raw_size] \
                if img.layout == "file" else img.read_rva(s.va, s.vsize)
            rows.append({
                "name": s.name, "va": img_base + s.va, "rva": s.va,
                "vsize": s.vsize, "raw_off": s.raw_off,
                "raw_size": s.raw_size,
                "entropy": round(_entropy.shannon(raw), 3),
                "flags": ("X" if s.exec else "-")
                         + ("R" if s.readable else "-")
                         + ("W" if s.writable else "-"),
            })
        return _jh(_list_envelope(rows, kind="sections", **list_kw))
    if action == "imports":
        rows = []
        for d in img.imports:
            for e in d["entries"]:
                rows.append({
                    "dll": d["dll"], "delayed": d["delayed"],
                    "name": e["name"],
                    "ordinal": e["ordinal"],
                    "thunk_va": img_base + e["thunk_rva"],
                })
        return _jh(_list_envelope(rows, kind="imports", **list_kw))
    if action == "exports":
        rows = [dict(e) for e in img.exports]
        # For source="memory" the parse-time `va` used the header's
        # *preferred* ImageBase — under ASLR/KASLR that's not where the
        # image is loaded. img_base carries the live base in that case.
        if img_base and img_base != img.image_base:
            for r in rows:
                r["va"] = img_base + r.get("rva", 0)
        return _jh(_list_envelope(rows, kind="exports", **list_kw))
    if action in ("hashes", "imphash"):
        out = {
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if img is not None:
            out["imphash"] = _pe.imphash(img)
            out["imphash_note"] = (
                "normalized 'lib.func' order, md5 — malware-family pivot")
        elif action == "imphash":
            return _j({"ok": False, "kind": "bad_magic",
                       "error": "imphash needs a PE source"})
        return _jh(out)
    if action == "sec":
        out = _hard.audit(img)
        out["module_hint"] = _module_hint(img)
        return _jh(out)
    if action == "strings":
        rows = _extract.find_strings(data, min_len=min_len)
        for r in rows:
            va = img.off_to_va(r["offset"]) if img else -1
            if va >= 0:
                r["va"] = va
        return _jh(_list_envelope(rows, kind="strings",
                                 default_limit=500, **list_kw))
    if action == "iocs":
        rows = _extract.find_iocs(data)
        for r in rows:
            va = img.off_to_va(r["offset"]) if img else -1
            if va >= 0:
                r["va"] = va
        return _jh(_list_envelope(rows, kind="iocs",
                                 default_limit=500, **list_kw))
    if action == "entropy":
        out = {"entropy": round(_entropy.shannon(data), 4),
               "size": len(data),
               "map": _entropy.bucket_map(data, buckets)}
        if img is not None:
            out["sections"] = [
                {"name": s.name,
                 "entropy": round(_entropy.shannon(
                     img.read_rva(s.va, s.vsize) if img.layout == "image"
                     else data[s.raw_off:s.raw_off + s.raw_size]), 3),
                 "exec": s.exec}
                for s in img.sections]
        return _jh(out)
    if action == "scan":
        rows = _sigs.scan(data)
        if img is not None:
            for s in img.sections:
                tag = _sigs.PACKER_SECTIONS.get(s.name.strip("\0").lower())
                if tag:
                    rows.append({"name": "packer_section",
                                 "category": "packer_marker",
                                 "offset": s.raw_off,
                                 "note": f"section {s.name!r} → {tag}"})
            rows.sort(key=lambda h: h["offset"])
        return _jh(_list_envelope(rows, kind="scan", **list_kw))
    if action == "caps":
        imp = {e["name"] for d in img.imports for e in d["entries"]
               if e["name"]}
        exp = {e["name"] for e in img.exports if e["name"]}
        rows = _caps.infer_capabilities(imp, exp)
        return _jh(_list_envelope(rows, kind="caps", **list_kw))

    # ---------------- engine / driver / heavy passes -------------------
    from . import bin_engine
    out = bin_engine.dispatch(ctx, _an, action, data, img, img_base,
                              target=target, func=func,
                              compare_path=compare_path,
                              reachability=reachability,
                              max_functions=max_functions,
                              max_instructions=max_instructions,
                              limit=limit, offset=offset, fields=fields,
                              filter=filter, summary=summary,
                              verbosity=verbosity,
                              ending=ending, category=category,
                              reg=reg, bad_bytes=bad_bytes,
                              max_len=max_len,
                              max_gadget_bytes=max_gadget_bytes,
                              scan_budget=scan_budget, unique=unique,
                              refresh=refresh, chain=chain,
                              expected_json=expected_json,
                              salvage=salvage)
    if action in _ANALYSIS_COVERAGE_ACTIONS:
        # static-analysis coverage: the decoder ran over the buffer we
        # handed it — complete unless the memory-source read had holes
        # (paged-out pages zero-filled), which makes matches in those
        # ranges absent, not "none".
        out = _coverage.attach(out, _coverage.coverage(
            "static-analysis",
            "partial" if salvage else "complete",
            *(["memory_read_holes"] if salvage else [])))
    return out


def _info(img) -> dict:
    from ...analysis.pe import MACHINE_NAMES, SUBSYSTEM_NAMES
    dbg = next((d for d in img.debug if d.get("pdb_path")), None)
    return {
        "format": "pe32+" if img.pe32_plus else "pe32",
        "layout": img.layout,
        "arch": MACHINE_NAMES.get(img.machine, hex(img.machine)),
        "image_base": img.image_base,
        "entry_va": img.image_base + img.entry_rva,
        "size_of_image": img.size_of_image,
        "subsystem": SUBSYSTEM_NAMES.get(img.subsystem,
                                       str(img.subsystem)),
        "is_driver": img.subsystem == 1,
        "characteristics": img.characteristics,
        "dll_characteristics": img.dll_characteristics,
        "timestamp": img.timestamp,
        "checksum": img.checksum,
        "sections": len(img.sections),
        "imports_dlls": len(img.imports),
        "imports_total": sum(len(d["entries"]) for d in img.imports),
        "exports_total": len(img.exports),
        "signed": bool(img.cert_size),
        "cert_size": img.cert_size,
        "overlay_bytes": img.overlay_size,
        "pdb": ({"path": dbg["pdb_path"], "guid": dbg.get("guid"),
                 "age": dbg.get("age")} if dbg else None),
        "pdata_functions": len(img.pdata),
        "reloc_blocks": img.reloc_blocks,
        "load_config": bool(img.load_config),
    }


def _module_hint(img) -> str:
    for d in img.debug:
        p = d.get("pdb_path") or ""
        if p:
            return p.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if img.imports:
        return img.imports[0]["dll"]
    return ""
