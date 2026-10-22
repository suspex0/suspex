"""Mem tool registration for the suspex0 MCP server.

Wraps the exact code that used to live inline inside ``build_server``.
Every symbol the closure closes over is re-exported by ``.common`` —
``from .common import *`` brings in the pydantic types, the
``AgentClient`` / ``FindingsLedger`` / ``IdaBridge`` handles, the
``READONLY_*`` annotations, the ``PRIMARY_TARGET`` default, and every
``_helper`` function.
"""

from __future__ import annotations

from .common import *  # noqa: F401,F403 — closures rely on module-scope helpers
from .context import Context
from .._coverage import coverage as _coverage  # noqa: F401 — result stamps
# Part 3 evidence envelope (detail=/retention); aliased to keep the
# closure namespace untouched. split_detail disambiguates the legacy
# disasm bool from the new "summary"|"complete" selector sharing the name.
from ..evidence.store import split_detail as _ev_split_detail
from ..evidence.store import with_evidence as _ev_with
from .follow import (  # noqa: F401 — file_manage closure calls these directly
    _auto_key,
    _auto_kick_start,
    _auto_kick_status,
    _auto_kick_stop,
    _follow_key,
    _follow_list,
    _follow_poll,
    _follow_start,
    _follow_stop,
)


# v0.22: module-level so the lazy action-enum annotation resolves
# (from __future__ import annotations defers eval to module globals).
MEM_ACTIONS = ["read", "write", "alloc", "free", "protect", "modules",
               "process_list", "pattern_scan", "vad", "handles",
               "imports", "exports", "heaps", "probe_va",
               "phys_ranges", "pool_scan",
               # v7 additions (ABI v7 agent required):
               "va_translate", "watch", "watch_list", "watch_stop",
               # v0.13 dev-feedback:
               "resolve",
               # codegen extra (Phase 1 of 2026-09-11 plan):
               "disasm", "assemble",
               # v0.16: long-running scan job surface — a wide-range
               # pattern_scan used to blow the 2 min MCP deadline with
               # no cancel/poll. scan_start returns a scan_id
               # immediately; scan_status/scan_result/scan_cancel/
               # scan_list drive the lifecycle.
               "scan_start", "scan_status", "scan_result",
               "scan_cancel", "scan_list",
               # v0.17 B-1c/B-1d: kernel-RE convenience primitives.
               "walk_list", "read_qwords",
               "read_unicode_string", "read_ansi_string",
               "strings", "iocs", "entropy",
               # v0.20: system-wide per-thread inventory (agent-side
               # NtQuerySystemInformation; driver enrichment on v11).
               "threads",
               # v0.20: kernel object-directory enumeration
               # (\Device, \Driver, ... — feeds device_manage ioctl).
               "obj_enum",
               # v0.25 forensic verbs (engagement feedback #9/#10):
               # dps-style pointer scan, named-type read sugar, IDT dump.
               "resolve_range", "dps", "dt", "idt",
               # v0.22 discoverability
               "actions"]


def _scan_window_cov(telem: dict | None, ranged: bool) -> dict:
    """scan-window coverage for pattern_scan/pool_scan: hit/byte caps →
    partial, unreadable chunks → partial+range_unreadable, no range
    established (whole-space sweep) → unknown."""
    if not ranged:
        return _coverage("scan-window", "unknown")
    t = telem or {}
    if t.get("truncated"):
        return _coverage("scan-window", "partial", "scan_limit_reached")
    if t.get("chunks_skipped") or t.get("partial_chunks") \
            or t.get("partial_bytes"):
        return _coverage("scan-window", "partial", "range_unreadable")
    return _coverage("scan-window", "complete")


def register(mcp, ctx: Context) -> None:
    """Register the ``mem_rw`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------------- mem_rw --

    _MEM_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "mem_rw(action='actions')"},
        "read": {"one_liner": "read memory (user/kernel/physical space); "
                              "decode='u64[4]' primitives or decode="
                              "{'type':'_EPROCESS','module':...} named "
                              "type (dt is the shortcut for that)",
                 "key_args": "pid, address, size, space, decode, "
                             "want_disasm",
                 "example": "mem_rw(action='read', pid=1234, "
                            "address='0x7ff60000', size=64)"},
        "resolve": {"one_liner": "VA <-> module+offset, and "
                                 "module!symbol(+addend) -> VA via the "
                                 "PDB (needs a dumped/local image)",
                    "key_args": "value, pid, space, path",
                    "example": "mem_rw(action='resolve', space='kernel', "
                               "value='ntoskrnl.exe!PsLoadedModuleList')"},
        "write": {"one_liner": "write memory (data_hex)",
                  "key_args": "pid, address, data_hex, space",
                  "example": "mem_rw(action='write', pid=1234, "
                             "address='0x...', data_hex='90')"},
        "alloc": {"one_liner": "VirtualAlloc(Ex) in the target",
                  "key_args": "pid, size, protect, space",
                  "example": "mem_rw(action='alloc', pid=1234, size=0x1000, "
                             "protect='rwx')"},
        "free": {"one_liner": "free an allocation",
                 "key_args": "pid, address",
                 "example": "mem_rw(action='free', pid=1234, address='0x...')"},
        "protect": {"one_liner": "change page protection",
                    "key_args": "pid, address, size, protect",
                    "example": "mem_rw(action='protect', pid=1234, "
                               "address='0x...', size=0x1000, protect='rx')"},
        "modules": {"one_liner": "module list for a pid (or kernel list)",
                    "key_args": "pid, filter, fields, limit",
                    "example": "mem_rw(action='modules', pid=1234)"},
        "process_list": {"one_liner": "process inventory",
                         "key_args": "fields, filter, summary",
                         "example": "mem_rw(action='process_list')"},
        "pattern_scan": {"one_liner": "sync byte-pattern scan over a range "
                                      "(use scan_start for wide sweeps)",
                         "key_args": "pid, address/base, size, pattern|"
                                     "pattern_hex, mask, space, sections",
                         "example": "mem_rw(action='pattern_scan', pid=1234, "
                                    "base='ntoskrnl.exe', "
                                    "pattern='4C 8B ?? 15')"},
        "vad": {"one_liner": "VAD / memory-region map for a process",
                "key_args": "pid, filter",
                "example": "mem_rw(action='vad', pid=1234)"},
        "handles": {"one_liner": "handle table for a pid (pid=4 = kernel "
                                 "objects; prefer summary=true under load)",
                    "key_args": "pid, want_names, limit, offset, fields, "
                                "summary",
                    "example": "mem_rw(action='handles', pid=4, "
                               "want_names=false, summary=true)"},
        "imports": {"one_liner": "module import table (live image)",
                    "key_args": "pid, module",
                    "example": "mem_rw(action='imports', pid=1234, "
                               "module='x.dll')"},
        "exports": {"one_liner": "module export table (live image)",
                    "key_args": "pid, module",
                    "example": "mem_rw(action='exports', module='ntoskrnl.exe', "
                               "space='kernel')"},
        "heaps": {"one_liner": "process heap inventory",
                  "key_args": "pid",
                  "example": "mem_rw(action='heaps', pid=1234)"},
        "probe_va": {"one_liner": "probe whether an address is readable "
                                  "(no data returned)",
                     "key_args": "pid, address, space",
                     "example": "mem_rw(action='probe_va', space='kernel', "
                                "address='0xfffff800...')"},
        "phys_ranges": {"one_liner": "valid physical-memory ranges "
                                     "(MmPhysicalMemoryBlock)",
                        "key_args": "none",
                        "example": "mem_rw(action='phys_ranges')"},
        "pool_scan": {"one_liner": "kernel pool scan by tag",
                      "key_args": "tag, pool_type, limit",
                      "example": "mem_rw(action='pool_scan', tag='Proc')"},
        "va_translate": {"one_liner": "VA -> PA via the driver's page-table "
                                      "walk (kernel space only; cr3= "
                                      "override needs ABI v12)",
                         "key_args": "pid, address, space",
                         "example": "mem_rw(action='va_translate', pid=1234, "
                                    "address='0x...')"},
        "watch": {"one_liner": "arm a memory watch — background poll "
                               "notifies on change",
                  "key_args": "pid, address, size, interval_ms, tag",
                  "example": "mem_rw(action='watch', pid=1234, "
                             "address='0x...', size=8)"},
        "watch_list": {"one_liner": "list active watches",
                       "key_args": "none",
                       "example": "mem_rw(action='watch_list')"},
        "watch_stop": {"one_liner": "stop a watch",
                       "key_args": "watch_id",
                       "example": "mem_rw(action='watch_stop', "
                                  "watch_id='w1')"},
        "disasm": {"one_liner": "disassemble bytes or live memory "
                                "(bytes_hex short-circuits with no target; "
                                "space='physical' works — reads via "
                                "mem_read)",
                   "key_args": "address|bytes_hex, size, arch, syntax, "
                               "count, detail",
                   "example": "mem_rw(action='disasm', bytes_hex='4889C8')"},
        "assemble": {"one_liner": "assemble to bytes (dry-run when no "
                                  "write_to)",
                     "key_args": "code, arch, write_to, address",
                     "example": "mem_rw(action='assemble', code='nop;ret')"},
        "scan_start": {"one_liner": "start a background scan job — returns "
                                    "scan_id immediately",
                       "key_args": "pid, address/base, size, pattern, "
                                   "space, sections, max_results",
                       "example": "mem_rw(action='scan_start', space='kernel', "
                                  "base='ntoskrnl.exe', size=0x200000, "
                                  "pattern='48 8B ??')"},
        "scan_status": {"one_liner": "poll a scan job's progress",
                        "key_args": "scan_id",
                        "example": "mem_rw(action='scan_status', "
                                   "scan_id='s3')"},
        "scan_result": {"one_liner": "fetch a finished scan's hits",
                        "key_args": "scan_id, limit, offset",
                        "example": "mem_rw(action='scan_result', "
                                   "scan_id='s3')"},
        "scan_cancel": {"one_liner": "cancel a running scan",
                        "key_args": "scan_id",
                        "example": "mem_rw(action='scan_cancel', "
                                   "scan_id='s3')"},
        "scan_list": {"one_liner": "list scan jobs",
                      "key_args": "none",
                      "example": "mem_rw(action='scan_list')"},
        "walk_list": {"one_liner": "walk a LIST_ENTRY chain",
                      "key_args": "pid, address, link_offset, max_nodes",
                      "example": "mem_rw(action='walk_list', space='kernel', "
                                 "address='0x...', link_offset='0x448')"},
        "read_qwords": {"one_liner": "read N qwords as a table (pointer "
                                     "walks)",
                        "key_args": "pid, address, count",
                        "example": "mem_rw(action='read_qwords', "
                                   "space='kernel', address='0x...', "
                                   "count=16)"},
        "read_unicode_string": {"one_liner": "read a UNICODE_STRING at "
                                             "address",
                                "key_args": "pid, address, space",
                                "example": "mem_rw(action='read_unicode_string', "
                                           "space='kernel', address='0x...')"},
        "read_ansi_string": {"one_liner": "read an ANSI_STRING at address",
                             "key_args": "pid, address, space",
                             "example": "mem_rw(action='read_ansi_string', "
                                        "space='kernel', address='0x...')"},
        "strings": {"one_liner": "extract printable strings from live "
                                 "memory",
                    "key_args": "pid, address, size, min_len",
                    "example": "mem_rw(action='strings', pid=1234, "
                               "address='0x...', size=0x1000)"},
        "iocs": {"one_liner": "extract indicators from live memory",
                 "key_args": "pid, address, size",
                 "example": "mem_rw(action='iocs', pid=1234, address='0x...', "
                            "size=0x1000)"},
        "entropy": {"one_liner": "entropy profile over a live range",
                    "key_args": "pid, address, size, buckets",
                    "example": "mem_rw(action='entropy', pid=1234, "
                               "address='0x...', size=0x1000)"},
        "threads": {"one_liner": "system-wide per-thread inventory (v20+)",
                    "key_args": "pid, fields, filter",
                    "example": "mem_rw(action='threads', pid=1234)"},
        "obj_enum": {"one_liner": "kernel object-directory enumeration "
                                  "(\\Device, \\Driver, ...)",
                     "key_args": "path",
                     "example": "mem_rw(action='obj_enum', "
                                "path='\\\\Driver')"},
        "resolve_range": {"one_liner": "scan a range, resolve every "
                                       "pointer-looking qword to "
                                       "module!sym+off (dps-style)",
                          "key_args": "address|base, size (<=1 MiB), space, "
                                      "pid, filter ('ptr' default, 'all' "
                                      "dumps everything), include_ascii "
                                      "(=include zeros), resolve_symbols",
                          "example": "mem_rw(action='resolve_range', "
                                     "space='kernel', address='0x...', "
                                     "size=0x200)"},
        "dps": {"one_liner": "alias for resolve_range",
                "key_args": "same as resolve_range",
                "example": "mem_rw(action='dps', space='kernel', "
                           "address='0x...', size=0x200)"},
        "dt": {"one_liner": "named-type read sugar — value='<TYPE>' "
                            "decodes at address via the PDB layout "
                            "(read decode={'type'} without the dict)",
               "key_args": "value (type name), address, module, space, "
                           "pid, size, decode={build_id|source|depth}",
               "example": "mem_rw(action='dt', value='_KTRAP_FRAME', "
                          "module='ntoskrnl.exe', space='kernel', "
                          "address='0x...')"},
        "idt": {"one_liner": "dump the IDT — handler VAs resolved to "
                             "module!sym+off with a `suspicious` flag on "
                             "off-allowlist handlers (needs ABI v12 "
                             "agent)",
                "key_args": "all_cpus (default current CPU only), "
                            "filter, fields, limit",
                "example": "mem_rw(action='idt')"},
    }

    # Orchestrator-side registry of active watches. Each entry is
    #   {watch_id, task, events: [...], started_ts, tag, target}
    # The gRPC stream is drained by a background task; the MCP caller
    # polls via `watch_events`. Live only for the orchestrator lifetime.
    _WATCHES: dict[str, dict[str, Any]] = {}
    _WATCH_SEQ = [0]

    # v0.16: orchestrator-side registry of active scan jobs. Same shape
    # as _WATCHES but tuned for one-shot pattern_scans. Each entry is
    #   {scan_id, owner, task, hits: list[int], progress: {...},
    #    status: 'running'|'done'|'cancelled'|'error',
    #    error?: str, args: {...for observability}, started_ts,
    #    finished_ts?, cancel: asyncio.Event}
    _SCANS: dict[str, dict[str, Any]] = {}
    _SCAN_SEQ = [0]

    async def _scan_start(ctx: Context, c, *, pid: int, addr: int,
                           base_i: int, size: int, space: str, kernel: bool,
                           pattern: str, pattern_hex: str, mask: str,
                           max_results: int, module: str = "",
                           sections: str = "") -> dict[str, Any]:
        """Kick off a background pattern_scan, return {scan_id, status}."""
        start = base_i or addr
        if kernel and space == "user":
            space_r = "kernel"
        elif space in ("user", "kernel", "physical"):
            space_r = space
        else:
            space_r = "user"
        if pattern:
            from ...sdk import parse_mask
            from ...sdk.reader import SuspexError as _ScanErr
            try:
                pat, mask_r = parse_mask(pattern)
            except _ScanErr as exc:
                return {"ok": False, "kind": "bad_arg",
                        "error": f"scan_start: {exc}"}
        else:
            pat = bytes.fromhex(pattern_hex) if pattern_hex else b""
            mask_r = mask
        if not pat:
            return {"ok": False, "kind": "bad_arg",
                    "error": "scan_start: pattern or pattern_hex is required"}
        max_r = int(max_results or 64)
        # Section-scoped mode: resolve `sections=` into (va, size) spans
        # over the live module image. start (or module=) is the image base.
        span_list: list[tuple[int, int]] | None = None
        span_info: dict[str, Any] = {}
        if sections:
            _kernel_lookup = kernel or space in ("kernel", "physical")
            span_list, span_info, serr = await _section_spans(
                c, pid, space_r, sections, module, start, _kernel_lookup)
            if serr:
                return serr
            assert span_list is not None
            start = span_list[0][0]
            size = sum(sz for _, sz in span_list)
        # Whole-space unary path can't be cancelled orchestrator-side without
        # the streaming proto RPC (v0.16 agent-side stretch goal), so demand
        # start+size for the job surface. Small whole-space calls stay on
        # pattern_scan. Note: `address`/`base` may legitimately be 0 — the
        # check is on `size` alone (a 0x0 start scans the low VAs).
        if not size:
            return {"ok": False, "kind": "bad_arg",
                    "error": "scan_start requires size>0 for the "
                             "cancellable client-side chunked path "
                             "(address/base may be 0)",
                    "hint": "for a small whole-space sweep, use "
                            "mem_rw(action='pattern_scan') directly; "
                            "scan_start is for wide (multi-GiB) ranges where "
                            "you need scan_status/scan_cancel"}
        import asyncio as _asyncio
        import time as _t
        _SCAN_SEQ[0] += 1
        scan_id = f"s{_SCAN_SEQ[0]:04d}"
        cancel_evt = _asyncio.Event()
        owner = current_client_id()
        entry: dict[str, Any] = {
            "scan_id": scan_id, "owner": owner,
            "task": None,
            "hits": [], "progress": {
                "bytes_scanned": 0, "bytes_total": int(size),
                "chunks_read": 0, "chunks_skipped": 0,
                "hits_so_far": 0,
            },
            "status": "running",
            "args": {"pid": pid, "start": hex(start), "size": int(size),
                     "space": space_r, "pattern": pattern or pattern_hex,
                     "max_results": max_r,
                     **({"sections": sections,
                         "spans": span_info.get("spans", [])}
                        if sections else {})},
            "started_ts": _t.time(), "finished_ts": None,
            "cancel": cancel_evt,
        }
        _SCANS[scan_id] = entry

        async def _runner() -> None:
            from ...sdk import _scan_range_impl, pattern_scan as _match

            class _AdapterView:
                async def read(self, pid, ea, n, sp):
                    return await c.mem_read(pid, ea, n, sp)

            try:
                view = _AdapterView()
                # spans -> [(start, end)] pairs. Single-span mode is the
                # historical [start, start+size) range.
                spans_end = [(s0, s0 + sz)
                             for s0, sz in (span_list or [(start, size)])]
                completed = 0  # bytes fully swept before the current span
                chunk = 0x100000
                overlap = max(0, len(pat) - 1)
                # v0.22 Phase 3: coverage spans — same semantics as
                # sdk._scan_range_impl but tracked across the whole job.
                _cov_scanned: list[tuple[int, int]] = []
                _cov_skipped: list[tuple[int, int]] = []
                for (span_start, end) in spans_end:
                    cursor = span_start
                    while cursor < end and len(entry["hits"]) < max_r:
                        if cancel_evt.is_set():
                            entry["status"] = "cancelled"
                            break
                        n = min(chunk, end - cursor)
                        data: bytes | None = None
                        try:
                            data = await view.read(pid, cursor, n, space_r)
                        except Exception:
                            # Per-page salvage: identical to sdk._scan_range_impl.
                            prefix = bytearray()
                            page = cursor
                            page_end = cursor + n
                            while page < page_end:
                                if cancel_evt.is_set():
                                    entry["status"] = "cancelled"
                                    break
                                take = min(0x1000 - (page & 0xFFF), page_end - page)
                                try:
                                    p = await view.read(pid, page, take, space_r)
                                except Exception:
                                    break
                                if not p:
                                    break
                                prefix += p
                                page += len(p)
                                if len(p) < take:
                                    break
                            if entry["status"] == "cancelled":
                                break
                            if prefix:
                                data = bytes(prefix)
                            else:
                                adv = 0x1000
                                entry["progress"]["chunks_skipped"] += 1
                                _cov_skipped.append(
                                    (cursor, min(cursor + adv, end)))
                                cursor += adv
                                entry["progress"]["bytes_scanned"] = min(
                                    completed + (cursor - span_start), size)
                                continue
                        if not data:
                            break
                        entry["progress"]["chunks_read"] += 1
                        _cov_scanned.append(
                            (cursor, min(cursor + len(data), end)))
                        entry["progress"]["bytes_scanned"] = min(
                            completed + (cursor - span_start) + len(data),
                            size)
                        for off in _match(data, pat, mask_r):
                            entry["hits"].append(cursor + off)
                            entry["progress"]["hits_so_far"] = len(entry["hits"])
                            if len(entry["hits"]) >= max_r:
                                break
                        got = len(data)
                        if cursor + got >= end:
                            break
                        cursor = (cursor + got - overlap
                                  if got > overlap else cursor + got)
                    completed += end - span_start
                    if (entry["status"] == "cancelled"
                            or len(entry["hits"]) >= max_r):
                        break
                if entry["status"] == "running":
                    entry["status"] = "done"
                # v0.22 Phase 3: publish the coverage map — for a single
                # span, unscanned is the complement inside [start, end);
                # multi-span (sections=) merges without it.
                try:
                    from ...sdk.scan import (_coverage_map, _coalesce,
                                             _COVERAGE_CAP)
                    if len(spans_end) == 1:
                        s0, e0 = spans_end[0]
                        entry["coverage"] = _coverage_map(
                            _cov_scanned, _cov_skipped, s0, e0)
                    else:
                        # Disjoint spans — 'unscanned' between them is
                        # out of scope, so merge the raw lists directly.
                        def _fmt(rs):
                            return [{"start": hex(s), "end": hex(e)}
                                    for s, e in rs[:_COVERAGE_CAP]]
                        sc = _coalesce(_cov_scanned)
                        sk = _coalesce(_cov_skipped)
                        entry["coverage"] = {
                            "scanned": _fmt(sc), "skipped": _fmt(sk),
                            "scanned_ranges": len(sc),
                            "skipped_ranges": len(sk),
                            "truncated": max(len(sc), len(sk))
                                         > _COVERAGE_CAP,
                            "merged_spans": len(spans_end)}
                except Exception:
                    pass  # coverage is best-effort, never fails the job
            except Exception as exc:  # noqa: BLE001
                entry["status"] = "error"
                entry["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                entry["finished_ts"] = _t.time()

        entry["task"] = _asyncio.create_task(_runner(), name=f"suspex-scan-{scan_id}")
        return {"ok": True, "scan_id": scan_id, "status": "running",
                "owner": owner, "hint": "poll mem_rw(action='scan_status', "
                                       f"scan_id={scan_id!r})"}

    def _scan_status(scan_id: str) -> dict[str, Any]:
        entry = _SCANS.get(scan_id)
        if entry is None:
            return {"ok": False, "kind": "unknown_scan",
                    "error": f"scan_id {scan_id!r} not found",
                    "hint": "mem_rw(action='scan_list') to see active scans"}
        current = current_client_id()
        return {"ok": True,
                "scan_id": scan_id,
                "status": entry["status"],
                "progress": dict(entry["progress"]),
                "hits_so_far": len(entry["hits"]),
                "started_ts": entry["started_ts"],
                "finished_ts": entry.get("finished_ts"),
                "owner": entry["owner"],
                "foreign": entry["owner"] != current,
                "error": entry.get("error")}

    def _scan_result(scan_id: str, *, limit: int, offset: int,
                     global_cap: int) -> dict[str, Any]:
        entry = _SCANS.get(scan_id)
        if entry is None:
            return {"ok": False, "kind": "unknown_scan",
                    "error": f"scan_id {scan_id!r} not found"}
        if entry["status"] == "running":
            return {"ok": False, "kind": "not_ready",
                    "error": f"scan {scan_id!r} is still running",
                    "status": "running",
                    "progress": dict(entry["progress"]),
                    "hint": "mem_rw(action='scan_status') to poll, or "
                            "mem_rw(action='scan_cancel') to stop"}
        addresses = [hex(a) for a in entry["hits"]]
        return _hexify_dict(_list_envelope(
            addresses, tool="mem_rw", action="scan_result",
            limit=limit or 0, offset=offset,
            fields=(),
            filter="",
            summary=False,
            global_cap=global_cap,
            extras={"scan_id": scan_id,
                    "status": entry["status"],
                    "progress": dict(entry["progress"]),
                    "coverage": entry.get("coverage"),
                    "started_ts": entry["started_ts"],
                    "finished_ts": entry.get("finished_ts"),
                    "owner": entry["owner"],
                    "args": entry["args"]},
        ), add_int_mirror=True)  # already returns a JSON string envelope

    async def _scan_cancel(scan_id: str) -> dict[str, Any]:
        entry = _SCANS.get(scan_id)
        if entry is None:
            return {"ok": False, "kind": "unknown_scan",
                    "error": f"scan_id {scan_id!r} not found"}
        current = current_client_id()
        if entry["owner"] != current:
            return {"ok": False, "kind": "foreign_owned",
                    "error": f"scan {scan_id!r} owned by {entry['owner']!r}",
                    "hint": "pass force=true to override (not implemented "
                            "yet on scan_cancel — ask the peer to cancel)"}
        entry["cancel"].set()
        # Let the runner observe the flag; the status transitions on its own
        # loop tick.
        return {"ok": True, "scan_id": scan_id,
                "status": entry["status"],
                "hint": "poll scan_status until status == 'cancelled'"}

    def _scan_list(current: str) -> dict[str, Any]:
        rows = []
        for sid, entry in _SCANS.items():
            rows.append({
                "scan_id": sid,
                "status": entry["status"],
                "hits_so_far": len(entry["hits"]),
                "progress": dict(entry["progress"]),
                "started_ts": entry["started_ts"],
                "owner": entry["owner"],
                "foreign": entry["owner"] != current,
                "args": entry["args"],
            })
        rows.sort(key=lambda r: -r["started_ts"])
        return {"ok": True, "count": len(rows), "scans": rows}

    # ------------------------------------------------ section-scoped scans ----

    async def _section_spans(c, pid: int, space: str, sections: str,
                             module: str, base: int, kernel_lookup: bool):
        """Resolve ``sections='.text,PAGE'`` to ``[(va, size), ...]`` spans
        inside a live module image.

        ``module`` (image name) or ``base`` (image-start VA) selects the
        image; both may be given (module wins). Section names are
        case-insensitive, support ``*``/``?`` globs, and the meta-token
        ``!exec`` matches every executable (IMAGE_SCN_MEM_EXECUTE) section.

        Returns ``(spans, info, err)`` — ``err`` is a ready-to-return
        error dict on failure, else ``None``.
        """
        from fnmatch import fnmatch
        from ...analysis import pe as _pe

        want = [w.strip().lower() for w in sections.split(",") if w.strip()]
        if not want:
            return [], None, {
                "ok": False, "kind": "bad_arg",
                "error": "sections= was provided but empty",
                "hint": "sections='.text' | '.text,PAGE' | '!exec'"}
        img_base = base
        if module:
            try:
                img_base = await _addr_resolve(
                    module + "+0x0", c, kernel=kernel_lookup, pid=pid,
                    name="module")
            except Exception as exc:  # noqa: BLE001 - surfaced verbatim
                return [], None, {"ok": False, "kind": "no_module",
                                  "error": f"sections: {exc}"}
        if not img_base:
            return [], None, {
                "ok": False, "kind": "bad_arg",
                "error": "sections= needs module=<image name> or a "
                         "base=/address= pointing at the image start",
                "hint": "mem_rw(action='modules', filter='ntoskrnl') "
                        "to find the base"}
        try:
            hdr = await c.mem_read(pid, img_base, 0x1000, space)
            if isinstance(hdr, tuple):
                hdr = hdr[0]
            need = _pe.header_extent(hdr)
            if need > len(hdr):
                hdr = await c.mem_read(pid, img_base,
                                       min(need, 0x100000), space)
                if isinstance(hdr, tuple):
                    hdr = hdr[0]
            img = _pe.parse(bytes(hdr), layout="image")
        except Exception as exc:  # noqa: BLE001 - parse/read errors unify
            return [], None, {
                "ok": False, "kind": "pe_parse",
                "error": f"sections: PE header read/parse at "
                         f"{hex(img_base)} failed: {exc}"}

        spans: list[tuple[int, int]] = []
        matched: list[str] = []
        missed: list[str] = []
        exec_tokens = {"!exec", "!code", "exec"}
        for w in want:
            hit_w = False
            for s in img.sections:
                ok = s.exec if w in exec_tokens else fnmatch(s.name.lower(), w)
                if not ok:
                    continue
                sz = s.vsize or s.raw_size
                if sz and (img_base + s.va, sz) not in spans:
                    spans.append((img_base + s.va, sz))
                    matched.append(s.name)
                hit_w = True
            if not hit_w:
                missed.append(w)
        if not spans:
            return [], None, {
                "ok": False, "kind": "no_sections",
                "error": f"sections: none of {want} matched; image has "
                         f"{[s.name for s in img.sections]}",
                "hint": "names are case-insensitive, '*'/'?' globs "
                        "allowed, '!exec' selects executable sections"}
        info: dict[str, Any] = {
            "module_base": img_base,
            "sections": matched,
            "spans": [{"va": s0, "size": sz} for s0, sz in spans],
            "size_of_image": img.size_of_image,
        }
        if missed:
            info["sections_unmatched"] = missed
        return spans, info, None


    # ------------------------------------------------- v0.25 forensic verbs ----

    _KERNEL_QWORD_MIN = 0xFFFF800000000000
    _USER_QWORD_MIN = 0x10000
    _USER_QWORD_MAX = 0x800000000000

    # IDT handler allowlist (module-name prefixes). A handler landing
    # anywhere else — or in no module at all — is flagged `suspicious`.
    # It's a warning flag, not a verdict: hypervisor IDT detours are
    # exactly what lights up here.
    _IDT_ALLOW_PREFIXES = ("ntoskrnl", "ntkrnlmp", "hal", "kd", "cng",
                           "ksecdd", "suspex")

    def _mod_ranges(mods: list[dict]) -> list[tuple[int, int, str]]:
        """Module rows -> sorted [(lo, hi, name)] coverage list."""
        out: list[tuple[int, int, str]] = []
        for m in mods or []:
            try:
                b = m.get("base", 0)
                z = m.get("size", 0)
                b_i = int(b, 0) if isinstance(b, str) else int(b or 0)
                z_i = int(z, 0) if isinstance(z, str) else int(z or 0)
            except (TypeError, ValueError):
                continue
            if b_i and z_i:
                out.append((b_i, b_i + z_i, str(m.get("name", ""))))
        out.sort()
        return out

    def _lookup_mod(ranges: list[tuple[int, int, str]],
                    va: int) -> tuple[int, int, str] | None:
        # Module lists are small (~hundreds); a linear scan is fine and
        # tolerates overlapping ranges better than bisect.
        for lo, hi, nm in ranges:
            if lo <= va < hi:
                return lo, hi, nm
        return None

    async def _ptr_symbol(img_cache: dict, mod_name: str, off: int,
                          path: str = "") -> dict | None:
        """Best-effort RVA -> symbol via lookup_rva — silent on any miss.

        `img_cache` maps module name -> local image path (or None) so a
        bulk scan pays the artifacts-dir probe once per module.
        """
        if mod_name not in img_cache:
            try:
                from .symbols import _resolve_image
                img, _ = _resolve_image(ctx, mod_name, path)
            except Exception:  # noqa: BLE001 - no local image = no symbols
                img = None
            img_cache[mod_name] = img
        img = img_cache.get(mod_name)
        if not img:
            return None
        try:
            from ... import symbols as _sym
            hit = await asyncio.to_thread(
                _sym.lookup_rva, img, off,
                str(ctx.cfg.pdb_cache_dir()),
                ctx.cfg.symbols.allow_download,
                ctx.cfg.symbols.servers or None)
            if hit.get("found"):
                return hit
        except Exception:  # noqa: BLE001 - symbolization is gravy
            pass
        return None

    def _fmt_modsym(row: dict) -> str:
        """'ntoskrnl.exe!KiDispatchException+0x10' / 'ntoskrnl.exe+0x1234'."""
        mod = str(row.get("module") or "")
        if not mod:
            return ""
        sym = row.get("symbol")
        if sym:
            disp = int(row.get("symbol_disp") or 0)
            return f"{mod}!{sym}+{disp:#x}" if disp else f"{mod}!{sym}"
        return f"{mod}+{int(row.get('rva') or 0):#x}"

    def _looks_invalid_addr(msg: str) -> bool:
        m = msg.upper()
        # v0.27: the MMIO/BAR class joins the family — device-backed VAs
        # fail MmCopyMemory with NTSTATUS whose Win32 projection is
        # gle=59 (UNEXP_NET_ERR) or gle=1117 (IO_DEVICE); the raw nt=
        # forms ride along once comm surfaces them.
        return ("STATUS_INVALID_ADDRESS" in m or "C0000141" in m
                or "GLE=487" in m
                or "GLE=59" in m or "GLE=1117" in m
                or "UNEXP_NET_ERR" in m or "IO_DEVICE" in m
                or "C00000E9" in m or "C00000C4" in m
                or "C0000185" in m)

    def _kernel_va_err(action: str, exc: Exception) -> dict:
        """v0.25: INVALID_ADDRESS on a kernel read — enrich in-place with
        the dt/decode pointer (_error_enrich isn't reachable from here)."""
        return {"ok": False, "kind": "invalid_address",
                "error": f"{action}: {exc}",
                "hint": ("kernel VA is unmapped, outside a valid range, or "
                         "backed by MMIO/device memory MmCopyMemory won't "
                         "touch — mem_rw(action='probe_va') tests "
                         "readability, mem_rw(action='va_translate') shows "
                         "the PA (a BAR-backed page reads via "
                         "space='physical' at that PA). For struct dumps "
                         "prefer mem_rw(action='dt', value='<TYPE>', ...) "
                         "or read decode={'type':..., 'module':...}")}


    class MemArgs(BaseModel):
        action: str = Field(description="|".join(MEM_ACTIONS))
        pid: int = 0
        address: int | str = Field(default=0,
                                   description="int, '0x...' hex, or "
                                               "'module+offset'")
        size: int = 0
        data_hex: str = Field(default="", description="write payload as hex")
        space: str = Field(default="user",
                           description="user|kernel|physical; kernel=true is "
                                       "a legacy alias")
        protect: int = 0
        kernel: bool = False
        pattern_hex: str = ""
        mask: str = ""
        pattern: str = Field(default="", description="IDA-style pattern "
                                                     "'4D 5A ?? 90'")
        base: int | str = Field(default=0,
                                description="pattern_scan start (alias for "
                                            "address)")
        max_results: int = 64
        want_names: bool = Field(default=False, description="handles: resolve "
                                                            "object names "
                                                            "(slow)")
        module: str = Field(default="", description="imports/exports: module "
                                                    "basename or full path")
        sections: str = Field(default="",
                              description="pattern_scan/scan_start: PE "
                                          "section names to scan")
        filter: Any = Field(default="", description="row filter — name "
                                                    "substring or "
                                                    "{field: value} dict")
        name_regex: str = Field(default="",
                                description="modules: case-insensitive name "
                                            "regex")
        name_glob: str = Field(default="",
                               description="modules: case-insensitive name "
                                           "glob")
        path_contains: str = Field(default="",
                                   description="modules: substring on the "
                                               "full path")
        compact: bool = Field(default=False,
                              description="modules: name/base/size only")
        summary: bool = Field(default=False,
                              description="list verbs: compact summary "
                                          "block")
        fields: list[str] = Field(default_factory=list,
                                  description="server-side row projection")
        value: str = Field(default="", description="resolve: module+offset "
                                                   "or absolute VA; dt: "
                                                   "type name")
        # --- Phase 1 codegen: disasm / assemble ---
        bytes_hex: str = Field(default="",
                               description="disasm: raw hex buffer (no "
                                           "target contact)")
        arch: str = Field(default="x64",
                          description="disasm/assemble: x64|x86")
        syntax: str = Field(default="intel",
                            description="disasm: intel|att")
        count: int = Field(default=64,
                           description="disasm: max instructions")
        detail: bool = Field(default=False,
                             description="disasm: attach cs.detail (legacy "
                                         "bool); read/scan/inventory verbs: "
                                         "'complete' (default) or 'summary' "
                                         "evidence detail")
        resolve_symbols: bool = Field(default=False,
                                      description="disasm: annotate operands "
                                                  "as module+offset")
        code: str = Field(default="",
                          description="assemble: source (labels allowed)")
        write_to: int | str = Field(default=0,
                                    description="assemble: write bytes at "
                                                "this VA (needs "
                                                "dry_run=false)")
        dry_run: bool = Field(default=True,
                              description="assemble: refuse write unless "
                                          "false")
        want_blocks: bool = Field(default=False,
                                  description="heaps: per-block detail")
        max_blocks: int = Field(default=0, description="heaps: per-heap block "
                                                       "cap")
        allow_fault: bool = Field(default=False,
                                  description="kernel read: permit driver "
                                              "soft-fault of non-resident "
                                              "pages — keep OFF for blind "
                                              "probing")
        allow_map_write: bool = Field(default=False,
                                      description="physical write: opt into "
                                                  "the MmMapIoSpaceEx path")
        partial: bool = Field(default=False,
                              description="kernel read: per-4KB partial "
                                          "walk (stop at first hole)")
        timeout_s: float = Field(default=0.0,
                                 description="per-call gRPC timeout (s)")
        scan_id: str = Field(default="",
                             description="scan job id from scan_start")
        verify: bool = Field(default=False,
                             description="write: atomic write-then-readback")
        decode: Any = Field(default=None,
                            description="read: typed decode — 'u64[4]' "
                                        "shorthand or {'type','module'}")
        reads: list[dict] | None = Field(default=None,
                                         description="read: batch "
                                                     "{va,size,decode?} "
                                                     "list")
        include_ascii: bool = Field(default=False,
                                    description="read+decode: also emit the "
                                                "ASCII preview")
        from_va: int | str = Field(default=0,
                                   description="read+space=physical: VA to "
                                               "translate first")
        resolve_physical: bool = Field(default=False,
                                       description="read: VA->PA->physical "
                                                   "shortcut")
        name: str = Field(default="", description="target view: kernel|user "
                                                  "(empty = your focused "
                                                  "machine's kernel view; "
                                                  "'<machine>.<kind>' for a "
                                                  "specific view)")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def mem_rw(action: Annotated[str, Field(json_schema_extra={"enum": MEM_ACTIONS})],
                     pid: int = 0, address: int | str = 0, size: int = 0,
                     data_hex: str = "", space: str = "user", protect: int = 0,
                     kernel: bool = False, pattern_hex: str = "", mask: str = "",
                     pattern: str = "", base: int | str = 0, max_results: int = 64,
                     want_names: bool = False, module: str = "",
                     filter: Any = "",
                     # v0.17 B-4b: typed module filters (were defined in
                     # _apply_modules_filter but never invoked before).
                     name_regex: str = "",
                     name_glob: str = "",
                     path_contains: str = "",
                     compact: bool = False,
                     summary: bool = False,
                     fields: list[str] | None = None,
                     want_blocks: bool = False, max_blocks: int = 0,
                     allow_fault: bool = False, allow_map_write: bool = False,
                     partial: bool = False,
                     timeout_s: float = 0.0,
                     value: str = "",
                     # --- Phase 1 codegen extras ---
                     bytes_hex: str = "",
                     arch: str = "x64",
                     syntax: str = "intel",
                     count: int = 64,
                     detail: bool | str = False,
                     resolve_symbols: bool = False,
                     code: str = "",
                     write_to: int | str = 0,
                     dry_run: bool = True,
                     # --- v0.14 unified paging (Layer 3) ---
                     limit: int = 0,
                     offset: int = 0,
                     cursor: str = "",
                     verbosity: str = "normal",
                     # --- v0.16 long-running scan job surface ---
                     scan_id: str = "",
                     # --- v0.17 B-5: write verify ---
                     verify: bool = False,
                     # --- v0.17 B-1: decode + batch reads ---
                     decode: Any = None,
                     reads: list[dict] | None = None,
                     include_ascii: bool = False,
                     # --- v0.17 B-2: VA -> PA -> physical read shortcut ---
                     from_va: int | str = 0,
                     resolve_physical: bool = False,
                     # --- v0.19: live extraction params ---
                     min_len: int = 5,
                     buckets: int = 64,
                     entropy: bool = False,
                     # --- v0.20: obj_enum params ---
                     path: str = "",
                     depth: int = 1,
                     # --- v0.25: idt per-CPU dump ---
                     all_cpus: bool = False,
                     # --- v0.21: section-scoped scans ---
                     sections: str = "",
                     # --- v14: NtQSI enrichments (no driver needed) ---
                     with_cmdline: bool = False,
                     with_context: bool = False,
                     name: str = "") -> str:
        """User/kernel/physical memory R/W, alloc/free/protect, module +
        process lists, pattern scan, VAD/handle tables, decode/dt,
        disasm/assemble, scan jobs, resolve_range/idt forensics.
        name='user' routes through the usermode umagent view (no driver);
        kernel=True is a legacy alias for space='kernel'. Addresses take
        int, '0x...' or 'module+offset'. List verbs take limit/offset
        (cursor=), fields=[...], filter=, summary=true, and
        verbosity='compact'|'normal'|'full' to trade detail for tokens;
        action='read' takes reads=[...] for batched reads. Per-verb help:
        mem_rw(action='actions')."""
        # v0.9.1: promote the legacy `kernel=True` shorthand into the canonical
        # space so read/write dispatch matches what the caller asked for. The
        # docstring has always promised this; only pattern_scan was honoring it.
        if kernel and space == "user":
            space = "kernel"
        args = {"action": action, "name": name, "pid": pid,
                "address": address, "size": size, "space": space,
                # Forward the response-shaping kwargs so _guard's
                # _opts_from_args can honor them in finalize (row-collapse,
                # mirror strips, projection, spill budget). Without these in
                # `args` the per-call verbosity/fields/etc. are ignored.
                "verbosity": verbosity, "fields": fields or [],
                "filter": filter, "include_ascii": include_ascii}
        # Part 3: `detail` carries both meanings — the legacy disasm bool
        # and the evidence selector ("summary" bounds the inline payload
        # to counts; "complete" delivers inline AND retains the record
        # under artifacts/evidence/).
        _ev_detail, _disasm_detail = _ev_split_detail(detail)

        async def run() -> str:
            # Reject unknown actions BEFORE we require a connected client so
            # "unknown action X" beats "not connected" as an error.
            if action not in MEM_ACTIONS:
                return _unknown_action("mem_rw", action, MEM_ACTIONS, _MEM_ACTION_HELP)
            if action == "actions":
                # v0.22: pure-compute discovery — answers unconnected.
                return _actions_help("mem_rw", _MEM_ACTION_HELP)
            # v0.17 B-4d: `name=` selects a target view (`kernel`|`user`),
            # never a row filter. Callers who wanted to filter modules by
            # substring have always been supposed to use `filter=` or the
            # typed `name_regex=` / `name_glob=`. Refuse the misuse with a
            # named error so the collision doesn't quietly route to the
            # wrong view. v0.27: '<machine>'/'<machine>.<kind>' selectors
            # pass through — their machine token must resolve.
            if name not in (PRIMARY_TARGET, "user", "kernel", "") \
                    and ctx.session._match_machine(
                        name.rsplit(".", 1)[0]) is None:
                return _j({"ok": False,
                           "kind": "kwarg_collision",
                           "error": ("'name' selects a target view ('kernel'|"
                                     "'user'), not a row filter. Use 'filter' "
                                     "or 'name_regex' to select rows."),
                           "hint": "filter='tcpip' or name_regex='^tcpip\\\\.sys$' "
                                   "for a modules row filter; name='kernel'/"
                                   "'user' picks the view"})
            # Pure-compute short-circuit: `disasm` with a raw hex buffer and
            # `assemble` with no `write_to` do not need a target. Handle
            # them BEFORE `require_client` so the LLM can round-trip bytes
            # without an active connection.
            if action == "disasm" and bytes_hex and not address:
                return await _mem_disasm(
                    ctx, name=name, pid=pid, space=space,
                    address=0, bytes_hex=bytes_hex,
                    arch=arch, syntax=syntax, count=count, size=size,
                    detail=_disasm_detail, resolve_symbols=False,  # symbols need target
                    allow_fault=allow_fault, timeout_s=timeout_s,
                )
            if action == "assemble" and not write_to:
                return await _mem_assemble(
                    ctx, name=name, pid=pid, space=space,
                    code=code, arch=arch, address=_addr(address, "address"),
                    write_to=0, dry_run=True, allow_map_write=allow_map_write,
                )
            c = ctx.session.require_client(name)
            # v0.20: every kernel-view mem_rw action routes through the
            # suspex driver — preflight it ONCE here so a missing driver
            # surfaces as a named `driver_absent` error instead of raw
            # gRPC noise (previously only 5 actions were guarded). The
            # user view (umagent) never touches the driver.
            # v14: process_list + threads(kernel=false) enumerate via
            # agent-side NtQuerySystemInformation — no driver needed, and
            # gating them here is exactly the post-reboot hole this build
            # was made to close.
            _driver_free = {"process_list"}
            if action == "threads" and not kernel:
                _driver_free.add("threads")
            if ctx.session.view_kind_of(name) != "user" \
                    and action not in _driver_free:
                guard = await _require_driver(ctx, "mem_rw", action, name)
                if guard:
                    return _j(guard)
            # module+offset resolution needs live modules; kernel-list for
            # kernel/physical addresses, per-pid user list otherwise.
            _kernel_lookup = kernel or space in ("kernel", "physical")
            addr = await _addr_resolve(address, c, kernel=_kernel_lookup,
                                       pid=pid, name="address")
            base_i = await _addr_resolve(base, c, kernel=_kernel_lookup,
                                         pid=pid, name="base")
            if action == "read":
                # v0.17 B-3: `offset` used to be a silent no-op on read
                # (the read branch never referenced it while `apply_page_opts`
                # consumed it for list actions). A caller migrating from a
                # base+offset call convention would see the wrong bytes with
                # no diagnostic. Refuse the read outright and point at the
                # intended migration path.
                if offset:
                    return _j({"ok": False,
                               "kind": "unknown_kwarg",
                               "error": ("'offset' has no meaning on mem_rw read; "
                                         "the read address is 'address' itself. "
                                         "Pass address=hex(base+offset) if you want a "
                                         "shifted read."),
                               "hint": f"add offset to address before calling: "
                                       f"address = base + 0x{offset:X}"})
                # v0.17 B-1b: batch mode — a list of {va, size, decode?} dicts.
                # Every row runs independently; a single failed row appears as
                # {address, error, size:0} and the rest of the batch still
                # returns. `_addr_resolve` is used for module+offset support.
                if reads:
                    from ..conversions import decode_buffer as _decode_buf
                    from ..conversions import ConversionError as _ConvErr
                    results: list[dict] = []
                    for spec in reads:
                        if not isinstance(spec, dict):
                            results.append({"error": f"read entry must be a dict, "
                                            f"got {type(spec).__name__}"})
                            continue
                        va_raw = spec.get("va") if "va" in spec else spec.get("address")
                        sz_raw = spec.get("size", 0)
                        dec = spec.get("decode")
                        try:
                            va_i = await _addr_resolve(va_raw, c,
                                                       kernel=_kernel_lookup,
                                                       pid=pid, name="reads[].va")
                            sz_i = int(sz_raw or 0)
                            if sz_i <= 0:
                                results.append({"address": hex(va_i),
                                                "error": "size required (> 0)"})
                                continue
                            row_data = await c.mem_read(pid, va_i, sz_i, space,
                                                        allow_fault=allow_fault,
                                                        timeout=timeout_s or None)
                            row: dict[str, Any] = {"address": hex(va_i),
                                                    "size": len(row_data),
                                                    "hex": row_data.hex()}
                            if include_ascii or not dec:
                                row["ascii"] = _ascii(row_data)
                            if dec:
                                try:
                                    decoded = _decode_buf(row_data, dec)
                                except _ConvErr as exc:
                                    row["decode_error"] = f"{exc.kind}: {exc}"
                                else:
                                    row["values"] = decoded["values"]
                                    row["layout"] = decoded["layout"]
                                    if decoded.get("truncated"):
                                        row["truncated"] = True
                                    if decoded.get("remainder_hex"):
                                        row["remainder_hex"] = decoded["remainder_hex"]
                            results.append(row)
                        except Exception as exc:  # noqa: BLE001 - per-row salvage: one bad va must not sink the batch
                            addr_hint = ""
                            try:
                                addr_hint = hex(int(va_raw, 0)
                                                if isinstance(va_raw, str)
                                                else int(va_raw or 0))
                            except (TypeError, ValueError):
                                addr_hint = str(va_raw)
                            results.append({"address": addr_hint,
                                            "error": f"{type(exc).__name__}: {exc}"})
                    bad = any("error" in r for r in results)
                    return _j({"batch": True,
                               "count": len(results),
                               "coverage": _coverage(
                                   "mem-read",
                                   "partial" if bad else "complete",
                                   *(["read_failed_mid_buffer"] if bad
                                     else [])),
                               "results": results})
                # v0.17 B-2: VA -> PA -> physical read shortcut. One
                # driver round-trip replaces (va_translate) +
                # (mem_rw read space=physical). `resolve_physical=true`
                # with a non-physical space is invalid; `from_va` +
                # non-zero `address` is a collision.
                if resolve_physical and space != "physical":
                    return _j({"ok": False, "kind": "invalid_parameter",
                               "error": ("resolve_physical=true only makes "
                                         "sense with space='physical'; drop "
                                         "either the flag or set space='physical'"),
                               "hint": "use plain mem_rw read for kernel or "
                                       "user VAs"})
                if from_va and address:
                    return _j({"ok": False, "kind": "kwarg_collision",
                               "error": ("read: pass either 'address' OR "
                                         "'from_va', not both — the two "
                                         "select different code paths (raw "
                                         "PA vs VA-first translate)"),
                               "hint": "drop `address` when using from_va"})
                if from_va and (space == "physical" or resolve_physical):
                    from_va_i = _addr(from_va, name="from_va")
                    try:
                        tr = await c.mem_va_translate(from_va_i,
                                                       space="kernel",
                                                       pid=pid)
                    except Exception as exc:  # noqa: BLE001 - translate fault -> pte_absent
                        return _j({"ok": False, "kind": "pte_absent",
                                   "error": (f"mem_va_translate({hex(from_va_i)}) "
                                             f"failed: {type(exc).__name__}: {exc}"),
                                   "hint": "the VA has no PTE; use probe_va for "
                                           "the PML4/PDPT/PD/PT layer breakdown"})
                    if not tr.get("present"):
                        return _j({"ok": False, "kind": "pte_absent",
                                   "error": (f"VA {hex(from_va_i)} has no valid PTE "
                                             f"(present=false)"),
                                   "translate": tr,
                                   "hint": "probe_va shows the layer that fenced "
                                           "the walk"})
                    pa = int(tr.get("pa", 0))
                    n = size or 64
                    data = await c.mem_read(pid, pa, n, "physical",
                                             allow_fault=allow_fault,
                                             timeout=timeout_s or None)
                    payload: dict[str, Any] = {
                        "va": hex(from_va_i),
                        "physical_address": hex(pa),
                        "size": len(data),
                        "hex": data.hex(),
                        "cr3": hex(int(tr.get("cr3", 0))),
                        "page_size_shift": int(tr.get("page_size_shift", 0)),
                    }
                    if decode:
                        from ..conversions import decode_buffer as _decode_buf
                        from ..conversions import ConversionError as _ConvErr
                        try:
                            decoded = _decode_buf(data, decode)
                        except _ConvErr as exc:
                            return _j({"ok": False, "kind": exc.kind,
                                       "error": str(exc),
                                       "hint": getattr(exc, "hint", "")})
                        payload["values"] = decoded["values"]
                        payload["layout"] = decoded["layout"]
                        if decoded.get("truncated"):
                            payload["truncated"] = True
                    if include_ascii or not decode:
                        payload["ascii"] = _ascii(data)
                    payload["coverage"] = _coverage("mem-read", "complete")
                    return _j(payload)
                n = size or 64
                # v0.9.1: fail fast when the caller forgot both pid= and
                # space=kernel — otherwise the driver's SuspxUserMemRead
                # rejects Pid=0 with STATUS_INVALID_PARAMETER (c000000d)
                # and the caller sees a bare gle=87 with no hint. This
                # is the shape the field regression took: `mem_manage
                # read kernel=true` was routing to space=user before
                # the alias-promotion above landed.
                if space == "user" and not pid:
                    return _j({"ok": False,
                               "error": "user-space read requires pid=<target>; "
                                        "use space='kernel' for kernel VAs "
                                        "(the driver rejects pid=0 user reads "
                                        "with STATUS_INVALID_PARAMETER)"})
                # gRPC message cap on the agent side is 4 MiB. When the
                # caller asks for more, auto-use the streaming path
                # instead of refusing — v5 wired Memory.ReadStream so
                # this is now transparent.
                MAX_READ = 4 * 1024 * 1024 - 0x1000
                if n > MAX_READ:
                    if not hasattr(c, "mem_read_all"):
                        return _j({"ok": False,
                                   "error": f"read size {n} exceeds per-call cap "
                                            f"{MAX_READ}; agent < v5 (no ReadStream)"})
                    data = await c.mem_read_all(pid, addr, n, space,
                                                 allow_fault=allow_fault,
                                                 timeout=timeout_s or None)
                    return _j({"address": hex(addr), "size": len(data),
                               "hex": data.hex(), "ascii": _ascii(data),
                               "stream": True,
                               "coverage": _coverage(
                                   "mem-read",
                                   "complete" if len(data) >= n else "partial",
                                   *(["read_failed_mid_buffer"]
                                     if len(data) < n else []))})
                if partial:
                    # v6 kernel PARTIAL: caller wants the valid prefix
                    # + the offset of the first hole. Surface both.
                    got = await c.mem_read(pid, addr, n, space,
                                            allow_fault=allow_fault,
                                            partial=True, want_meta=True,
                                            timeout=timeout_s or None)
                    data, meta = got
                    hole = int(meta.get("read_bytes", len(data))) < n
                    return _j({"address": hex(addr), "size": len(data),
                               "requested": n,
                               "hex": data.hex(), "ascii": _ascii(data),
                               "partial": True,
                               "read_bytes": meta.get("read_bytes", len(data)),
                               "first_bad_offset": meta.get("first_bad_offset", 0),
                               "coverage": _coverage(
                                   "mem-read",
                                   "partial" if hole else "complete",
                                   *(["read_failed_mid_buffer"] if hole
                                     else []))})
                try:
                    data = await c.mem_read(pid, addr, n, space,
                                            allow_fault=allow_fault,
                                            timeout=timeout_s or None)
                except Exception as exc:  # noqa: BLE001 - v0.25: point kernel-read INVALID_ADDRESS at dt/decode
                    if space in ("kernel", "physical") and \
                            _looks_invalid_addr(str(exc)):
                        return _j(_kernel_va_err("read", exc))
                    raise
                # v0.17 B-1a: `decode=` turns the raw bytes into typed
                # values. Always include hex+size so a caller who wants the
                # underlying buffer keeps it; skip the ascii preview unless
                # the caller explicitly asked (the values+layout are the
                # signal now, ascii mostly noise).
                payload: dict[str, Any] = {"address": hex(addr),
                                            "size": len(data),
                                            "hex": data.hex()}
                if decode:
                    from ..conversions import decode_buffer as _decode_buf
                    from ..conversions import ConversionError as _ConvErr
                    # v0.22 B-1e: named-type decode — decode={'type':
                    # '_EPROCESS', 'module': 'ntoskrnl.exe'} (build_id /
                    # path / source optional; module=/path= fall back to
                    # the outer kwargs). Resolves via the IDA-dumped
                    # layout cache or straight from the PDB with dbghelp.
                    if isinstance(decode, dict) and \
                            (decode.get("type") or decode.get("type_name")):
                        from .symbols import _resolve_type_layout
                        from ..conversions import (
                            decode_typed_buffer as _decode_typed)
                        lay, lerr = await _resolve_type_layout(
                            ctx, decode, module=module, path=path)
                        if lerr is not None:
                            return _j(lerr)
                        try:
                            decoded = _decode_typed(
                                data, lay["members"],
                                type_name=lay.get("type_name", ""),
                                size=lay.get("size", 0),
                                types=lay.get("types"),
                                max_depth=int(decode.get("depth") or 2))
                        except _ConvErr as exc:
                            return _j({"ok": False, "kind": exc.kind,
                                       "error": str(exc),
                                       "hint": getattr(exc, "hint", "")})
                        payload["type"] = lay.get("type_name")
                        payload["layout_source"] = lay.get("source")
                        if lay.get("build_id"):
                            payload["build_id"] = lay["build_id"]
                        if lay.get("image"):
                            payload["image"] = lay["image"]
                        if lay.get("note"):
                            payload["layout_note"] = lay["note"]
                    else:
                        try:
                            decoded = _decode_buf(data, decode)
                        except _ConvErr as exc:
                            return _j({"ok": False, "kind": exc.kind,
                                       "error": str(exc),
                                       "hint": getattr(exc, "hint", "")})
                    payload["values"] = decoded["values"]
                    payload["layout"] = decoded["layout"]
                    if decoded.get("truncated"):
                        payload["truncated"] = True
                    if decoded.get("remainder_hex"):
                        payload["remainder_hex"] = decoded["remainder_hex"]
                if include_ascii or not decode:
                    payload["ascii"] = _ascii(data)
                payload["coverage"] = _coverage(
                    "mem-read", "complete" if len(data) >= n else "partial",
                    *(["read_failed_mid_buffer"] if len(data) < n else []))
                return _j(payload)
            if action == "write":
                # Same guard as read: user-space write with pid=0 is a
                # driver-rejected combo — surface the misuse in the tool
                # layer with a named error instead of a bare gle=87.
                if space == "user" and not pid:
                    return _j({"ok": False,
                               "error": "user-space write requires pid=<target>; "
                                        "use space='kernel' for kernel VAs "
                                        "(the driver rejects pid=0 user writes "
                                        "with STATUS_INVALID_PARAMETER)"})
                if space == "physical" and not allow_map_write:
                    # Fail fast with a named reason instead of a bare
                    # gle=5 from the v5 driver's opt-in gate.
                    return _j({"ok": False,
                               "error": "physical write requires allow_map_write=true "
                                        "(ABI v5: opts into the MmMapIoSpaceEx write "
                                        "path; skipped pages surface as written < "
                                        "payload size)"})
                data = bytes.fromhex(data_hex)
                n = await c.mem_write(pid, addr, data, space,
                                      allow_map_write=allow_map_write)
                if not verify:
                    return _j({"ok": True, "written": n})
                # v0.17 B-5: atomic write-then-read-back. Callers who need
                # the classical "write reported success but nothing landed"
                # forensic pair get it in one round trip. verify=true doubles
                # bandwidth, so a warning fires past a 64 KiB payload.
                payload: dict[str, Any] = {"written": n, "verified": None}
                readback_err: str = ""
                try:
                    readback = await c.mem_read(pid, addr, len(data), space,
                                                allow_fault=allow_fault,
                                                timeout=timeout_s or None)
                except Exception as exc:  # noqa: BLE001 - readback fault is one of the states we surface
                    readback = b""
                    readback_err = f"{type(exc).__name__}: {exc}"
                if readback_err:
                    payload["verified"] = False
                    payload["read_back_error"] = readback_err
                    payload["hint"] = (
                        "write reported success but readback threw — the "
                        "target range may be write-only, fenced, or crossed "
                        "an unmapped page. Re-read smaller chunks to isolate "
                        "the bad page.")
                elif readback == data:
                    payload["verified"] = True
                else:
                    diff_off = next((i for i, (a, b) in enumerate(
                        zip(readback, data)) if a != b),
                                     min(len(readback), len(data)))
                    payload["verified"] = False
                    payload["diff_offset"] = diff_off
                    payload["expected_hex"] = data[diff_off:diff_off + 16].hex()
                    payload["actual_hex"] = readback[diff_off:diff_off + 16].hex()
                    payload["hint"] = (
                        "write reported success but readback differs — check "
                        "that the range isn't COW / read-only / device-mapped, "
                        "and that another writer didn't race")
                warnings: list[str] = []
                if len(data) > 64 * 1024:
                    warnings.append(
                        "verify=true doubles bandwidth; disable for large "
                        "writes (payload > 64 KiB)")
                env = _envelope_ok(
                    payload, kind="write", tool="mem_rw", action="write",
                    warnings=warnings,
                )
                return _j(env)
            if action == "alloc":
                a2 = await c.mem_alloc(pid, size or 0x1000, protect or 4, kernel)
                return _j({"ok": True, "address": hex(a2)})
            if action == "free":
                return _j(await c.mem_free(pid, addr, kernel))
            if action == "protect":
                return _j(await c.mem_protect(pid, addr, size or 0x1000, protect))
            if action == "modules":
                # v0.17 B-4a: `filter` is case-insensitive substring; dict
                # form ANDs {field: value} case-insensitive substring per
                # field. For exact match, pass a compiled regex:
                #   filter={"name": re.compile(r"^tcpip\.sys$")}
                # Prefer the dedicated name_regex / name_glob / path_contains
                # kwargs for modules — they surface named errors on typos.
                use_kernel = kernel or space in ("kernel", "physical")
                if use_kernel:
                    guard = await _require_driver(ctx, "mem_rw", "modules",
                                                  name)
                    if guard: return _j(guard)
                mods_all = await c.mem_modules(pid, use_kernel)
                mods = list(mods_all)
                # v0.17 B-4b: wire the dedicated typed filters (defined in
                # _apply_modules_filter since v0.14 but never invoked).
                if name_regex or name_glob or path_contains:
                    import re as _re_mods
                    try:
                        mods = _apply_modules_filter(mods, {
                            "name_regex": name_regex,
                            "name_glob": name_glob,
                            "path_contains": path_contains,
                        })
                    except _re_mods.error as exc:
                        return _j({"ok": False,
                                   "kind": "invalid_parameter",
                                   "error": f"name_regex compile error: {exc}",
                                   "hint": "escape metacharacters or drop the "
                                           "regex and use name_glob instead"})
                # v0.14 Layer 3: single uniform list envelope. Old knobs
                # (`filter` str/dict, `fields`, `compact`, `summary`,
                # `max_results`) route through apply_page_opts.
                if compact:
                    mods = [{"name": m.get("name", ""),
                             "base": m.get("base"),
                             "size": m.get("size")} for m in mods]
                eff_limit = limit or max_results
                # v0.17 B-4c: zero-match diagnostic. When any filter was
                # applied and nothing matched, return an empty items list
                # with filter_matched:false plus a 5-item sample of the
                # available module names so the caller can spot a typo
                # without a follow-up call. `_list_envelope`'s filter still
                # runs after this check when `filter` is the only knob, so
                # we only branch when the pre-envelope filters trimmed the
                # rows or `filter` is set.
                pre_filtered = bool(name_regex or name_glob or path_contains)
                if pre_filtered and not mods:
                    all_names = [str(m.get("name", "")) for m in mods_all]
                    env = _envelope_ok(
                        {"items": [], "filter_matched": False,
                         "sample_available_names": all_names[:5],
                         "total_available": len(all_names),
                         "filter_applied": {
                             "name_regex": name_regex or None,
                             "name_glob": name_glob or None,
                             "path_contains": path_contains or None,
                         }},
                        kind="filter_no_match", tool="mem_rw",
                        action="modules",
                        item_count=0, item_total=0,
                        coverage=_coverage("enumeration", "complete"),
                    )
                    return _hexify_dict(env, add_int_mirror=True)
                env = _list_envelope(
                    mods, tool="mem_rw", action="modules",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "process_list":
                res = await c.mem_processes(with_cmdline=with_cmdline,
                                            full=True)
                procs = (res.get("processes") if isinstance(res, dict)
                         else res) or []
                eff_limit = limit or max_results
                env = _list_envelope(
                    procs, tool="mem_rw", action="process_list",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"source": res.get("source")
                            if isinstance(res, dict) else "agent"},
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "resolve":
                v = str(value or address or module or "").strip()
                if not v:
                    return _j({"ok": False,
                                "error": "resolve: 'value' (or 'address' / 'module') required",
                                "hint": "value=0xfffff80000abc123 | value='ntoskrnl.exe+0xabc123' "
                                        "| value='ntoskrnl.exe!PsLoadedModuleList'"})
                use_kernel = kernel or space in ("kernel", "physical") or space == "user" and pid == 0
                # v0.22: `module!symbol(+addend)` — resolves the symbol's
                # RVA out of the module's PDB (dbghelp on a dumped/local
                # image), then adds the live module base. Needs a local
                # image: file_manage(action='dump_module') or path=.
                if "!" in v and not v.lower().startswith("0x"):
                    from .symbols import _resolve_image
                    from ... import symbols as _sym
                    mod_name, _, sym_expr = v.partition("!")
                    sym_name, _, add_s = sym_expr.partition("+")
                    mod_name = mod_name.strip()
                    sym_name = sym_name.strip()
                    try:
                        add = _addr(add_s.strip()) if add_s.strip() else 0
                    except (ValueError, TypeError) as exc:
                        return _j({"ok": False, "kind": "invalid_parameter",
                                   "error": f"resolve: bad addend in "
                                            f"{v!r}: {exc}"})
                    if not mod_name or not sym_name:
                        return _j({"ok": False, "kind": "invalid_parameter",
                                   "error": f"resolve: {v!r} not valid "
                                            "module!symbol(+addend)"})
                    mods = await c.mem_modules(pid, use_kernel)
                    mod_low = mod_name.lower()
                    hit_mod = None
                    for m in mods:
                        nm = str(m.get("name", "")).lower()
                        pth = str(m.get("path", "")).lower()
                        if (nm == mod_low or pth.endswith("\\" + mod_low)
                                or nm.startswith(mod_low)):
                            hit_mod = m
                            break
                    if hit_mod is None:
                        return _j({"ok": False, "kind": "module_not_found",
                                   "error": f"resolve: module {mod_name!r} "
                                            "not in the "
                                            f"{'kernel' if use_kernel else 'user'} "
                                            "module list",
                                   "hint": "mem_rw(action='modules', "
                                           "filter=…) to browse loaded "
                                           "names"})
                    b = hit_mod.get("base", 0)
                    base_i = int(b, 0) if isinstance(b, str) else int(b)
                    try:
                        img, img_name = _resolve_image(ctx, mod_name, path)
                    except _sym.SymbolError as exc:
                        return _j({"ok": False, "kind": "module_not_found",
                                   "error": str(exc)})
                    try:
                        rvas = await asyncio.to_thread(
                            _sym.resolve_rvas, img, [sym_name],
                            str(ctx.cfg.pdb_cache_dir()),
                            ctx.cfg.symbols.allow_download,
                            ctx.cfg.symbols.servers or None)
                    except _sym.SymbolError as exc:
                        return _j({"ok": False, "kind": "dbghelp_failed",
                                   "error": str(exc)})
                    if sym_name not in rvas:
                        return _j({"ok": False, "kind": "symbol_not_found",
                                   "error": f"{sym_name!r} not in "
                                            f"{img_name!r}'s PDB",
                                   "hint": "symbols_manage(action='resolve',"
                                           f" module={mod_name!r}, ...) for "
                                           "bulk lookups / diagnostics"})
                    rva = rvas[sym_name]
                    return _j_hex({"ok": True,
                                   "va": base_i + rva + add,
                                   "module": mod_name, "symbol": sym_name,
                                   "rva": rva, "module_base": base_i,
                                   "addend": add,
                                   "resolved_from": "module!symbol"})
                # module+offset case — reuse existing helper.
                if "+" in v and not v.lower().startswith("0x"):
                    va = await _addr_resolve(v, c, kernel=use_kernel, pid=pid, name="value")
                    mod_name, _, off = v.partition("+")
                    return _j_hex({"ok": True, "va": va,
                                    "module": mod_name.strip(),
                                    "offset": _addr(off),
                                    "resolved_from": "module+offset"})
                # Numeric address case — search kernel/user module ranges.
                try:
                    va = _addr(v, name="value")
                except ValueError:
                    return _j({"ok": False,
                                "error": f"resolve: {v!r} not a hex/decimal address, "
                                          "module+offset, or module!symbol notation",
                                "hint": "module!symbol needs a local image — "
                                        "file_manage(action='dump_module') or "
                                        "symbols_manage(action='resolve')"})
                mods = await c.mem_modules(pid, use_kernel)
                for m in mods:
                    b = m.get("base", 0)
                    s = m.get("size", 0)
                    base_i = int(b, 0) if isinstance(b, str) else int(b)
                    size_i = int(s, 0) if isinstance(s, str) else int(s)
                    if base_i <= va < base_i + size_i:
                        out: dict[str, Any] = {"ok": True, "va": va,
                                               "module": m.get("name"),
                                               "path": m.get("path"),
                                               "base": base_i,
                                               "offset": va - base_i,
                                               "module_size": size_i,
                                               "resolved_from": "address"}
                        # v0.22: best-effort symbolization — when a local
                        # image exists for the module, SymFromAddrW names
                        # the nearest symbol + displacement. Failures are
                        # silent: symbol lookup is gravy, not the payload.
                        try:
                            from .symbols import _resolve_image
                            from ... import symbols as _sym
                            img, _ = _resolve_image(
                                ctx, str(m.get("name") or ""), path)
                            if img:
                                hit = await asyncio.to_thread(
                                    _sym.lookup_rva, img, va - base_i,
                                    str(ctx.cfg.pdb_cache_dir()),
                                    ctx.cfg.symbols.allow_download,
                                    ctx.cfg.symbols.servers or None)
                                if hit.get("found"):
                                    out["symbol"] = hit["name"]
                                    out["symbol_rva"] = hit["rva"]
                                    out["symbol_disp"] = hit["displacement"]
                        except Exception:
                            pass
                        return _j_hex(out)
                return _j_hex({"ok": True, "va": va, "module": None,
                                "resolved_from": "address_unresolved",
                                "hint": "VA is not inside any known module "
                                        f"({'kernel' if use_kernel else 'user pid=' + str(pid)}) — "
                                        "verify pid or space, or try the other side"})
            # ---- v0.25: resolve_range (dps) / dt / idt ----
            if action in ("resolve_range", "dps"):
                # v0.25 (feedback #10): dps-style pointer annotation over a
                # range. Each qword is classified by canonical VA shape and
                # resolved against the module map; symbolization is opt-in
                # (resolve_symbols) since it's one dbghelp call per unique
                # module. `partial=True` makes PTE holes truncate the sweep
                # honestly instead of failing it.
                start = base_i or addr
                if not size or int(size) <= 0:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"{action}: size= is required (>0, "
                                        "cap 1 MiB)",
                               "hint": "mem_rw(action='resolve_range', "
                                       "space='kernel', address='0x...', "
                                       "size=0x200)"})
                if space == "user" and not pid:
                    return _j({"ok": False,
                               "error": "user-space resolve_range requires "
                                        "pid=<target>; use space='kernel' "
                                        "for kernel VAs (the driver rejects "
                                        "pid=0 user reads with "
                                        "STATUS_INVALID_PARAMETER)"})
                n = min(int(size), 0x100000)
                try:
                    got = await c.mem_read(pid, start, n, space,
                                           allow_fault=allow_fault,
                                           partial=True, want_meta=True,
                                           timeout=timeout_s or None)
                except Exception as exc:  # noqa: BLE001 - same INVALID_ADDRESS hint as read
                    if space in ("kernel", "physical") and \
                            _looks_invalid_addr(str(exc)):
                        return _j(_kernel_va_err(action, exc))
                    raise
                if isinstance(got, tuple):
                    data, meta = got
                else:
                    data, meta = got, {}
                # Kernel pointers resolve against the kernel module map no
                # matter the scan space (a user-space buffer can hold
                # kernel VAs); user pointers resolve against the pid's
                # list when a pid was given. Both lists are best-effort —
                # a umagent view can't enumerate kernel modules.
                kernel_ranges: list[tuple[int, int, str]] = []
                user_ranges: list[tuple[int, int, str]] = []
                try:
                    kernel_ranges = _mod_ranges(
                        await c.mem_modules(pid, True))
                except Exception:  # noqa: BLE001 - unresolved stays honest
                    kernel_ranges = []
                if pid:
                    try:
                        user_ranges = _mod_ranges(
                            await c.mem_modules(pid, False))
                    except Exception:  # noqa: BLE001
                        user_ranges = []
                rows: list[dict] = []
                pointers = 0
                resolved = 0
                img_cache: dict[str, Any] = {}
                qwords = len(data) // 8
                for i in range(qwords):
                    off = i * 8
                    (q,) = struct.unpack_from("<Q", data, off)
                    row: dict[str, Any] = {"off": off, "va": q}
                    if q == 0:
                        row["class"] = "zero"
                    elif q >= _KERNEL_QWORD_MIN:
                        pointers += 1
                        hit = _lookup_mod(kernel_ranges, q)
                        if hit:
                            lo, _hi, mod = hit
                            row["class"] = "kernel"
                            row["module"] = mod
                            row["rva"] = q - lo
                            resolved += 1
                        else:
                            row["class"] = "kernel_unresolved"
                    elif _USER_QWORD_MIN <= q < _USER_QWORD_MAX:
                        row["class"] = "user"
                        pointers += 1
                        hit = _lookup_mod(user_ranges, q)
                        if hit:
                            lo, _hi, mod = hit
                            row["module"] = mod
                            row["rva"] = q - lo
                            resolved += 1
                    else:
                        row["class"] = "nonptr"
                    if resolve_symbols and row.get("module"):
                        sym = await _ptr_symbol(
                            img_cache, row["module"], int(row["rva"]), path)
                        if sym:
                            row["symbol"] = sym["name"]
                            row["symbol_rva"] = sym.get("rva")
                            row["symbol_disp"] = sym.get("displacement")
                    row["name"] = _fmt_modsym(row) or \
                        f"<{row['class'].replace('_', ' ')}>"
                    rows.append(row)
                # Class gate: `filter` doubles as the row-class selector.
                # "" / "ptr" keeps pointer-looking rows (+zeros when
                # include_ascii doubles as include_zeros); "all" dumps
                # every scanned qword; any other string/dict filters the
                # pointer rows through _list_envelope as usual.
                flt = filter.strip().lower() if isinstance(filter, str) else ""
                keep_ptr = {"kernel", "kernel_unresolved", "user"}
                if include_ascii:  # repurposed: include_zeros
                    keep_ptr.add("zero")
                if isinstance(filter, dict) and filter:
                    kept, env_filter = rows, filter
                elif flt == "all":
                    kept, env_filter = rows, ""
                else:
                    kept = [r for r in rows if r["class"] in keep_ptr]
                    env_filter = "" if flt in ("", "ptr") else filter
                if compact or verbosity == "compact":
                    if env_filter:
                        # Row filters operate on dicts — apply before the
                        # text-line collapse (a dict filter on str rows
                        # would crash _filter_rows).
                        from .._envelope.paging import _filter_rows as _fr
                        kept = _fr(kept, env_filter)
                        env_filter = ""
                    kept = [f"off={r['off']:#06x}  0x{r['va']:016X}  "
                            f"{r['name']}" for r in kept]
                extras: dict[str, Any] = {
                    "start": hex(start), "space": space,
                    "scanned": len(data), "requested": n,
                    "qwords": qwords,
                    "pointers": pointers, "resolved": resolved,
                    "truncated": len(data) < n,
                }
                if meta.get("first_bad_offset"):
                    extras["first_bad_offset"] = meta["first_bad_offset"]
                if meta.get("first_bad_offset") or len(data) < n:
                    cov = _coverage("mem-read", "partial",
                                    "read_failed_mid_buffer")
                else:
                    cov = _coverage("mem-read", "complete")
                env = _list_envelope(
                    kept, tool="mem_rw", action=action,
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=env_filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras=extras,
                )
                env["coverage"] = cov
                return _hexify_dict(env, add_int_mirror=True)
            if action == "dt":
                # v0.25 (feedback #9): named-type read sugar — the
                # `read decode={'type':...}` path without making the
                # caller spell the decode dict. `value` is the type name;
                # a decode={} dict still merges in for the exotic knobs
                # (build_id/source/depth/cache_dir).
                tname = str(value or "").strip()
                if not tname:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "dt: value='<TYPE_NAME>' is "
                                        "required (e.g. "
                                        "value='_KTRAP_FRAME')",
                               "hint": "mem_rw(action='dt', "
                                       "value='_KTRAP_FRAME', "
                                       "module='ntoskrnl.exe', "
                                       "space='kernel', address='0x...')"})
                if not addr:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "dt: address= is required",
                               "hint": "address accepts int, '0x...' or "
                                       "'module+0xoff'"})
                if space == "user" and not pid:
                    return _j({"ok": False,
                               "error": "user-space dt requires "
                                        "pid=<target>; use space='kernel' "
                                        "for kernel VAs (the driver "
                                        "rejects pid=0 user reads with "
                                        "STATUS_INVALID_PARAMETER)"})
                from .symbols import _resolve_type_layout
                spec = dict(decode) if isinstance(decode, dict) else {}
                spec["type"] = tname
                lay, lerr = await _resolve_type_layout(
                    ctx, spec, module=module, path=path)
                if lerr is not None:
                    return _j(lerr)
                assert lay is not None
                n = int(size or lay.get("size") or 0)
                if n <= 0:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"dt: layout for {tname!r} has "
                                        "size 0 — pass size= explicitly"})
                try:
                    data = await c.mem_read(pid, addr, n, space,
                                            allow_fault=allow_fault,
                                            timeout=timeout_s or None)
                except Exception as exc:  # noqa: BLE001 - same INVALID_ADDRESS hint as read
                    if space in ("kernel", "physical") and \
                            _looks_invalid_addr(str(exc)):
                        return _j(_kernel_va_err("dt", exc))
                    raise
                from ..conversions import decode_typed_buffer as _dty
                from ..conversions import ConversionError as _ConvErr
                try:
                    decoded = _dty(
                        data, lay["members"],
                        type_name=lay.get("type_name", ""),
                        size=lay.get("size", 0),
                        types=lay.get("types"),
                        max_depth=int(spec.get("depth") or 2))
                except _ConvErr as exc:
                    return _j({"ok": False, "kind": exc.kind,
                               "error": str(exc),
                               "hint": getattr(exc, "hint", "")})
                payload: dict[str, Any] = {
                    "address": hex(addr), "size": len(data),
                    "hex": data.hex(),
                    "type": lay.get("type_name"),
                    "layout_source": lay.get("source"),
                }
                if lay.get("build_id"):
                    payload["build_id"] = lay["build_id"]
                if lay.get("image"):
                    payload["image"] = lay["image"]
                if lay.get("note"):
                    payload["layout_note"] = lay["note"]
                payload["values"] = decoded["values"]
                payload["layout"] = decoded["layout"]
                if decoded.get("truncated"):
                    payload["truncated"] = True
                    payload["coverage"] = _coverage("mem-read", "partial",
                                                    "decode_truncated")
                else:
                    payload["coverage"] = _coverage("mem-read", "complete")
                if decoded.get("remainder_hex"):
                    payload["remainder_hex"] = decoded["remainder_hex"]
                if include_ascii:
                    payload["ascii"] = _ascii(data)
                return _j(payload)
            if action == "idt":
                # v0.25 (feedback #9): per-CPU IDT dump. Needs the WP4
                # IdtList RPC — feature-gated so the verb lands before the
                # driver side does; an old agent gets kind='agent_old'.
                if not hasattr(c, "idt_list"):
                    return _j({"ok": False, "kind": "agent_old",
                               "error": "idt: agent < v12 "
                                        "(Memory.IdtList missing)",
                               "hint": "rebuild agent with ABI v12"})
                # KIDT is per-processor — `all_cpus` dumps every table;
                # the default call gets the current CPU's.
                try:
                    res = await c.idt_list(all_cpus=all_cpus)
                except Exception as exc:  # noqa: BLE001 - UNIMPLEMENTED == agent_old
                    msg = str(exc)
                    if "UNIMPLEMENTED" in msg:
                        return _j({"ok": False, "kind": "agent_old",
                                   "error": f"idt: {msg}",
                                   "hint": "rebuild agent with ABI v12"})
                    return _j({"ok": False, "kind": "idt_failed",
                               "error": msg})
                if isinstance(res, dict) and res.get("ok") is False:
                    return _j({"ok": False, "kind": "idt_failed",
                               "error": res.get("error",
                                                "idt list failed")})
                entries = res.get("entries", []) \
                    if isinstance(res, dict) else []
                try:
                    kranges = _mod_ranges(await c.mem_modules(pid, True))
                except Exception:  # noqa: BLE001 - unresolved still dumps
                    kranges = []
                img_cache: dict[str, Any] = {}
                rows: list[dict] = []
                def _ei(e: dict, k: str) -> int:
                    try:
                        return int(_addr(e.get(k), name=k) or 0)
                    except (TypeError, ValueError):
                        return 0
                suspicious = 0
                for e in entries:
                    hva = _ei(e, "handler_va")
                    row = {
                        "cpu": _ei(e, "cpu"),
                        "vector": _ei(e, "vector"),
                        "handler_va": hex(hva),
                        "selector": _ei(e, "selector"),
                        "ist": _ei(e, "ist"),
                        "dpl": _ei(e, "dpl"),
                    }
                    hit = _lookup_mod(kranges, hva)
                    if hit:
                        lo, _hi, mod = hit
                        row["module"] = mod
                        row["rva"] = hva - lo
                        sym = await _ptr_symbol(img_cache, mod, hva - lo,
                                                path)
                        if sym:
                            row["symbol"] = sym["name"]
                            row["symbol_disp"] = sym.get("displacement")
                        row["name"] = _fmt_modsym(row)
                        if not mod.lower().startswith(_IDT_ALLOW_PREFIXES):
                            row["suspicious"] = True
                    else:
                        row["suspicious"] = True
                    if row.get("suspicious"):
                        suspicious += 1
                    rows.append(row)
                rows.sort(key=lambda r: (r["cpu"], r["vector"]))
                def _res_int(k: str) -> int:
                    if not isinstance(res, dict):
                        return 0
                    try:
                        return int(_addr(res.get(k), name=k) or 0)
                    except (TypeError, ValueError):
                        return 0
                extras = {
                    "idt_base": hex(_res_int("idt_base")),
                    "idt_limit": _res_int("idt_limit"),
                    "all_cpus": all_cpus,
                    "suspicious": suspicious,
                }
                if all_cpus:
                    # Per-CPU bases — present when the agent reports them
                    # (per-cpu map on the response, or per-row base).
                    bases: dict[str, int] = {}
                    raw_bases = (res.get("per_cpu_bases")
                                 or res.get("bases")) \
                        if isinstance(res, dict) else None
                    if isinstance(raw_bases, dict):
                        for k, v in raw_bases.items():
                            try:
                                bases[str(k)] = int(_addr(v))
                            except (TypeError, ValueError):
                                continue
                    else:
                        for e in entries:
                            if e.get("idt_base") is not None:
                                try:
                                    bases[str(int(_addr(e.get("cpu", 0))
                                                    or 0))] = \
                                        int(_addr(e["idt_base"]))
                                except (TypeError, ValueError):
                                    continue
                    if bases:
                        extras["per_cpu_bases"] = {
                            k: hex(v)
                            for k, v in sorted(bases.items(),
                                               key=lambda kv: int(kv[0]))}
                        if len(set(bases.values())) > 1:
                            extras["base_drift"] = True
                            extras["drift_note"] = (
                                "per-CPU IDT bases differ — KIDT is "
                                "per-processor, but a copied/detoured "
                                "table looks the same; cross-check "
                                "handler_drift")
                    # Same vector resolving to different handlers on
                    # different CPUs is the detour signature.
                    by_vec: dict[int, set] = {}
                    for r in rows:
                        by_vec.setdefault(r["vector"], set()).add(
                            r["handler_va"])
                    drifted = sorted(v for v, s in by_vec.items()
                                     if len(s) > 1)
                    if drifted:
                        extras["handler_drift"] = drifted[:64]
                        extras["handler_drift_total"] = len(drifted)
                env_filter = filter
                if compact or verbosity == "compact":
                    if env_filter:
                        # Apply dict/str row filters before the text-line
                        # collapse (see resolve_range).
                        from .._envelope.paging import _filter_rows as _fr
                        rows = _fr(rows, env_filter)
                        env_filter = ""
                    rows = [
                        f"cpu{r['cpu']}  vec={r['vector']:#04x}  "
                        f"{r['handler_va']}  ist={r['ist']}  dpl={r['dpl']}"
                        f"  {r.get('name') or '<unresolved>'}"
                        f"{'  SUSPICIOUS' if r.get('suspicious') else ''}"
                        for r in rows]
                env = _list_envelope(
                    rows, tool="mem_rw", action="idt",
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=env_filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras=extras,
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "pattern_scan":
                # base is the canonical param; accept address as an alias.
                # kernel=true is honored when space wasn't explicitly set.
                start = base_i or addr
                if kernel and space == "user":
                    space_r = "kernel"
                elif space in ("user", "kernel", "physical"):
                    space_r = space
                else:
                    space_r = "user"
                if pattern:
                    from ...sdk import parse_mask
                    from ...sdk.reader import SuspexError as _ScanErr
                    try:
                        pat, mask_r = parse_mask(pattern)
                    except _ScanErr as exc:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": f"pattern_scan: {exc}"})
                else:
                    pat = bytes.fromhex(pattern_hex)
                    mask_r = mask
                eff_limit = limit or max_results
                # v0.21: section-scoped scan — `sections='.text,PAGE'`
                # resolves the named PE sections of the image at
                # `module=`/`base=` and scans each in turn. Paged-out
                # ranges simply aren't in the span list, so they can't
                # pollute chunks_skipped the way a whole-image sweep does.
                if sections:
                    from ...sdk import scan_range_with_stats
                    spans, sinfo, serr = await _section_spans(
                        c, pid, space_r, sections, module, start,
                        _kernel_lookup)
                    if serr:
                        return _j(serr)
                    hits: list[int] = []
                    telem: dict[str, Any] = {
                        "start": hex(sinfo["module_base"]),
                        "end": hex(spans[-1][0] + spans[-1][1]),
                        "chunk_size": 0x100000,
                        "chunks_read": 0, "chunks_skipped": 0,
                        "bytes_scanned": 0, "bytes_skipped": 0,
                        "partial_chunks": 0, "partial_bytes": 0,
                        "truncated": False,
                    }
                    span_covs: list[dict] = []
                    for s0, sz in spans:
                        if len(hits) >= max_results:
                            telem["truncated"] = True
                            break
                        h, t = await scan_range_with_stats(
                            c, pid, s0, sz, pat, mask_r, space_r,
                            max_results=max_results - len(hits))
                        hits += h
                        for k in ("chunks_read", "chunks_skipped",
                                  "bytes_scanned", "bytes_skipped",
                                  "partial_chunks", "partial_bytes"):
                            telem[k] += t.get(k, 0)
                        if isinstance(t.get("coverage"), dict):
                            span_covs.append(t["coverage"])
                        telem["truncated"] = bool(
                            telem["truncated"] or t.get("truncated"))
                    # v0.22 Phase 3: merge per-span coverage; 'unscanned'
                    # is meaningless across disjoint section spans so the
                    # merged map drops it.
                    if span_covs:
                        from ...sdk.scan import merge_coverage
                        telem["coverage"] = merge_coverage(span_covs)
                    addresses = [hex(a) for a in hits]
                    extras = {"space": space_r}
                    extras.update(telem)
                    extras.update(sinfo)
                    try:
                        _pattern_scan_breadcrumb(
                            ctx, pattern=pattern or pattern_hex,
                            space=space_r,
                            address=sinfo["module_base"],
                            size=sinfo["size_of_image"],
                        )
                    except Exception as _bc_exc:  # pragma: no cover
                        log.debug("pattern_scan breadcrumb dropped: %s",
                                  _bc_exc)
                    env = _list_envelope(
                        addresses, tool="mem_rw", action="pattern_scan",
                        limit=eff_limit, offset=offset,
                        fields=fields or (),
                        filter=filter,
                        summary=summary,
                        global_cap=ctx.cfg.mcp_max_items(),
                        extras=extras,
                    )
                    env["coverage"] = _scan_window_cov(telem, ranged=True)
                    return _hexify_dict(env, add_int_mirror=True)
                # If the caller gave a range (start or size), run the
                # client-side chunked scan so we can report telemetry
                # (bytes scanned, chunks skipped). Otherwise fall back to
                # the agent-side scan which enumerates the space for us.
                if start or size:
                    from ...sdk import scan_range_with_stats
                    scan_size = size or 0
                    if not scan_size:
                        return _j({"ok": False,
                                   "error": "pattern_scan with `address`/`base` "
                                            "requires `size` too; leave both 0 to "
                                            "sweep the whole space."})
                    hits, telem = await scan_range_with_stats(
                        c, pid, start, scan_size, pat, mask_r,
                        space_r, max_results=max_results,
                    )
                    addresses = [hex(a) for a in hits]
                    extras = {"space": space_r}
                    extras.update(telem)
                    try:
                        _pattern_scan_breadcrumb(
                            ctx, pattern=pattern or pattern_hex, space=space_r,
                            address=start, size=scan_size,
                        )
                    except Exception as _bc_exc:  # pragma: no cover
                        log.debug("pattern_scan breadcrumb dropped: %s", _bc_exc)
                    env = _list_envelope(
                        addresses, tool="mem_rw", action="pattern_scan",
                        limit=eff_limit, offset=offset,
                        fields=fields or (),
                        filter=filter,
                        summary=summary,
                        global_cap=ctx.cfg.mcp_max_items(),
                        extras=extras,
                    )
                    env["coverage"] = _scan_window_cov(telem, ranged=True)
                    return _hexify_dict(env, add_int_mirror=True)
                # Whole-space: agent-side scan. 'H'/'L' nibble mask
                # positions (pattern tokens '6?'/'?F') are byte-granular
                # on the wire, so sdk.scan downgrades them to '?' and
                # post-verifies each candidate via mem_read.
                from ...sdk.scan import agent_pattern_scan
                hits = await agent_pattern_scan(
                    c, pid, pat, mask_r, 0, 0, max_results, space_r)
                addresses = [hex(a) for a in hits]
                try:
                    _pattern_scan_breadcrumb(
                        ctx, pattern=pattern or pattern_hex, space=space_r,
                        address=0, size=0,
                    )
                except Exception as _bc_exc:  # pragma: no cover
                    log.debug("pattern_scan breadcrumb dropped: %s", _bc_exc)
                env = _list_envelope(
                    addresses, tool="mem_rw", action="pattern_scan",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"space": space_r, "start": None, "end": None,
                            "note": "whole-space scan; pass address+size for telemetry"},
                )
                env["coverage"] = _scan_window_cov(None, ranged=False)
                return _hexify_dict(env, add_int_mirror=True)
            if action in ("scan_start", "scan_status", "scan_result",
                          "scan_cancel", "scan_list"):
                # v0.16 long-running scan job surface. Same args as
                # pattern_scan for scan_start; scan_status / scan_result /
                # scan_cancel address by scan_id.
                if action == "scan_start":
                    return _j(await _scan_start(
                        ctx, c, pid=pid, addr=addr, base_i=base_i,
                        size=size, space=space, kernel=kernel,
                        pattern=pattern, pattern_hex=pattern_hex,
                        mask=mask, max_results=max_results,
                        module=module, sections=sections,
                    ))
                if action == "scan_status":
                    return _j(_scan_status(scan_id))
                if action == "scan_result":
                    # _scan_result returns the fully-formatted envelope
                    # STRING (already through _list_envelope) so we hand it
                    # back verbatim without a second _j round-trip. The
                    # not-ready / unknown_scan branches DO return a plain
                    # dict, so wrap those on the way out.
                    out = _scan_result(scan_id, limit=limit, offset=offset,
                                        global_cap=ctx.cfg.mcp_max_items())
                    return out if isinstance(out, str) else _j(out)
                if action == "scan_cancel":
                    return _j(await _scan_cancel(scan_id))
                if action == "scan_list":
                    return _j(_scan_list(current_client_id()))
            # v0.17 B-1c: walk_list — follow a linked-list from `base`
            # hopping `next_offset` bytes into each node to read the next
            # pointer. Every kernel-object walk used to hand-roll this in
            # exec_idapython or repeated mem_rw pattern_scans.
            if action == "walk_list":
                from ..conversions import decode_buffer as _decode_buf
                from ..conversions import ConversionError as _ConvErr
                next_off_raw = value or "0"
                try:
                    next_off = _addr(next_off_raw, name="next_offset")
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"walk_list: {exc}",
                               "hint": "pass value=<offset-of-next-pointer> "
                                       "(int or hex string) — e.g. value='0x8'"})
                # count -> max_hops override; max_results -> back-compat.
                max_hops = count if count and count != 64 else max_results or 64
                # want_names doubles as `stop_when_self`; default True. We
                # use a dedicated flag through `filter=self:false` /
                # `filter=null:false` — simplest is to just default to
                # both stops on unless the caller passes `include_ascii=True`
                # (which we repurpose as "no self/null stop"). Cleanest
                # long-term: dedicated flags, but keep the surface tight
                # for v0.17.
                stop_when_self = True
                stop_when_null = True
                read_size = size or 8
                visited: set[int] = set()
                nodes: list[dict] = []
                va_cur = int(addr)
                stopped_at = "max_hops"
                for hop in range(max(1, int(max_hops))):
                    if va_cur == 0 and stop_when_null:
                        stopped_at = "null"
                        break
                    if va_cur in visited and stop_when_self:
                        stopped_at = "self"
                        break
                    visited.add(va_cur)
                    node: dict[str, Any] = {"va": hex(va_cur), "hop": hop}
                    if decode:
                        try:
                            node_bytes = await c.mem_read(
                                pid, va_cur, read_size, space,
                                allow_fault=allow_fault,
                                timeout=timeout_s or None)
                        except Exception as exc:  # noqa: BLE001 - salvage node
                            node["error"] = f"{type(exc).__name__}: {exc}"
                            nodes.append(node)
                            break
                        try:
                            decoded = _decode_buf(node_bytes, decode)
                        except _ConvErr as exc:
                            node["decode_error"] = f"{exc.kind}: {exc}"
                        else:
                            node["values"] = decoded["values"]
                            node["layout"] = decoded["layout"]
                            if decoded.get("truncated"):
                                node["truncated"] = True
                    try:
                        ptr_bytes = await c.mem_read(
                            pid, va_cur + next_off, 8, space,
                            allow_fault=allow_fault,
                            timeout=timeout_s or None)
                    except Exception as exc:  # noqa: BLE001 - salvage tail
                        node["next_error"] = f"{type(exc).__name__}: {exc}"
                        nodes.append(node)
                        stopped_at = "next_read_failed"
                        break
                    if len(ptr_bytes) < 8:
                        node["truncated"] = True
                        nodes.append(node)
                        stopped_at = "short_next_ptr"
                        break
                    (next_va,) = struct.unpack("<Q", ptr_bytes)
                    node["next_va"] = hex(next_va)
                    nodes.append(node)
                    va_cur = next_va
                return _j({"base": hex(int(addr)),
                           "next_offset": hex(next_off),
                           "node_count": len(nodes),
                           "stopped_at": stopped_at,
                           "nodes": nodes})
            # v0.17 B-1d: convenience wrappers built on decode_buffer.
            if action == "read_qwords":
                cnt = int(count if count and count != 64 else max_results or 8)
                if cnt <= 0:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "read_qwords: count must be > 0"})
                data = await c.mem_read(pid, addr, cnt * 8, space,
                                        allow_fault=allow_fault,
                                        timeout=timeout_s or None)
                from ..conversions import decode_buffer as _decode_buf
                decoded = _decode_buf(data, [f"u64"] * cnt)
                return _j({"address": hex(addr),
                           "count": cnt,
                           "size": len(data),
                           "hex": data.hex(),
                           "values": decoded["values"],
                           "values_hex": [f"0x{v:016X}"
                                          for v in decoded["values"]],
                           "layout": decoded["layout"],
                           "truncated": decoded["truncated"]})
            if action in ("read_unicode_string", "read_ansi_string"):
                # Layout: UNICODE_STRING / ANSI_STRING —
                #   Length:u16, MaxLength:u16, pad:u32, Buffer:ptr
                # Buffer is a VA to the raw wide/ansi chars. Length is in
                # BYTES for wchars; we decode the referenced buffer under
                # utf-16-le / mbcs and strip a trailing NUL when present.
                header = await c.mem_read(pid, addr, 16, space,
                                          allow_fault=allow_fault,
                                          timeout=timeout_s or None)
                if len(header) < 16:
                    return _j({"ok": False, "kind": "partial_read",
                               "error": f"{action}: header truncated "
                                        f"({len(header)}/16 bytes at {hex(addr)})"})
                length, max_length = struct.unpack_from("<HH", header, 0)
                (buffer_va,) = struct.unpack_from("<Q", header, 8)
                out: dict[str, Any] = {
                    "address": hex(addr),
                    "length": int(length),
                    "max_length": int(max_length),
                    "buffer_va": hex(buffer_va),
                    "text": "",
                }
                if length == 0 or buffer_va == 0:
                    return _j(out)
                try:
                    body = await c.mem_read(pid, buffer_va, int(length), space,
                                            allow_fault=allow_fault,
                                            timeout=timeout_s or None)
                except Exception as exc:  # noqa: BLE001 - report the buffer read failure
                    out["buffer_error"] = f"{type(exc).__name__}: {exc}"
                    return _j(out)
                if action == "read_unicode_string":
                    text = body.decode("utf-16-le", errors="replace")
                else:
                    text = body.decode("mbcs", errors="replace")
                # UNICODE_STRING can carry a trailing NUL when MaxLength >
                # Length; strip a single trailing NUL for readability.
                out["text"] = text.rstrip("\x00")
                out["bytes_hex"] = body.hex()
                return _j(out)
            if action == "vad":
                vads = await c.vad_list(pid)
                # Normalize before filter so protect/vad_type are comparable.
                vads = [{"start": int(e.get("start", 0)) if not isinstance(e.get("start"), str)
                                    else int(e.get("start", "0"), 0),
                          "end":   int(e.get("end", 0)) if not isinstance(e.get("end"), str)
                                    else int(e.get("end", "0"), 0),
                          "protect": int(e.get("protect", 0)),
                          "vad_type": int(e.get("vad_type", 0)),
                          "commit_charge": int(e.get("commit_charge", 0))}
                         for e in vads]
                # Dict-shaped filter uses VAD-specific semantics (protect flags,
                # range overlap); apply it here so str filters still route
                # through apply_page_opts below.
                if isinstance(filter, dict) and filter:
                    vads = _apply_vad_filter(vads, filter)
                if summary:
                    env = _envelope_ok(
                        {"summary": _vad_summary(vads)},
                        kind="vad", tool="mem_rw", action="vad",
                        item_count=0, item_total=len(vads),
                        coverage=_coverage("enumeration", "complete"),
                    )
                    return _hexify_dict(env, add_int_mirror=True)
                # attach _decoded siblings for protect + vad_type
                vads = _decode_list(vads, "vad")
                eff_limit = limit or max_results
                pass_filter = "" if isinstance(filter, dict) else filter
                env = _list_envelope(
                    vads, tool="mem_rw", action="vad",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=pass_filter,
                    summary=False,
                    global_cap=ctx.cfg.mcp_max_items(),
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "handles":
                # v0.22: pull the table in bounded pages instead of one
                # shot. The proto's limit/offset are post-fill (the agent
                # still enumerates the full table per call), so paging
                # costs one enumeration per page — but it caps each wire
                # response, which is what killed the single mega-message
                # under load on pid=4. A short page ends the table; when
                # the caller asked for a bounded window we early-out once
                # it is filled.
                _PAGE = 2000
                eff_limit = limit or max_results
                # Early-out only when no filter/summary needs the full
                # table — filtering happens post-fetch in _list_envelope.
                # `need` mirrors resolve_limit so a default call pulls
                # just the 128-row window, not the whole table.
                from .._envelope.opts import resolve_limit as _res_lim
                need = 0
                if not filter and not summary:
                    resolved = _res_lim("mem_rw", "handles", eff_limit,
                                        global_cap=ctx.cfg.mcp_max_items())
                    need = offset + resolved
                raw: list[dict[str, Any]] = []
                off = 0
                pages = 0
                while True:
                    want = _PAGE if not need else min(_PAGE, need - off)
                    if want <= 0:
                        break
                    page = await c.handle_list(pid, want_names,
                                               limit=want, offset=off)
                    pages += 1
                    if not page:
                        break
                    raw.extend(page)
                    off += len(page)
                    if len(page) < want:  # short page = end of table
                        break
                # Early-out can't see past the window — the true table
                # size is unknown. Probe one row past the end so
                # truncated/next_cursor in the envelope stay honest.
                has_more = False
                if need and raw and len(raw) >= need:
                    probe = await c.handle_list(pid, False,
                                                limit=1, offset=need)
                    pages += 1
                    has_more = bool(probe)
                handles = [{"handle": int(h.get("handle", 0)),
                             "type_name": h.get("type_name", ""),
                             "object": int(h.get("object", 0)),
                             "granted_access": int(h.get("granted_access", 0)),
                             "name": h.get("name", "")} for h in raw]
                handles = _decode_list(handles, "handle")
                env = _list_envelope(
                    handles, tool="mem_rw", action="handles",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"pages_fetched": pages,
                            "table_total_unknown": has_more},
                )
                if has_more:
                    # The envelope computed truncated/next_cursor against
                    # the fetched rows, not the (unknown) table — patch so
                    # callers see the real paging contract.
                    summ = env.get("summary")
                    if isinstance(summ, dict):
                        summ["truncated"] = True
                        summ["item_total"] = None
                        summ["next_cursor"] = (
                            f"offset:{offset + summ.get('item_count', 0)}")
                # Coverage is about the requested window, not table size:
                # the loop provably ran to a short page (end of table) or
                # filled the window, so the enumeration itself is complete.
                # `has_more` stays a paging concern (summary.truncated).
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "imports":
                if not module:
                    return _j({"ok": False, "error": "imports requires 'module'"})
                if _kernel_lookup:
                    guard = await _require_driver(ctx, "mem_rw", "imports",
                                                  name)
                    if guard: return _j(guard)
                ents = await c.mem_imports(pid, module, _kernel_lookup)
                hooked = sum(1 for e in ents if e.get("hooked"))
                eff_limit = limit or max_results
                env = _list_envelope(
                    ents, tool="mem_rw", action="imports",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"module": module, "hooked": hooked},
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "exports":
                if not module:
                    return _j({"ok": False, "error": "exports requires 'module'"})
                if _kernel_lookup:
                    guard = await _require_driver(ctx, "mem_rw", "exports",
                                                  name)
                    if guard: return _j(guard)
                ents = await c.mem_exports(pid, module, _kernel_lookup)
                eff_limit = limit or max_results
                env = _list_envelope(
                    ents, tool="mem_rw", action="exports",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"module": module},
                )
                env["coverage"] = _coverage("enumeration", "complete")
                return _hexify_dict(env, add_int_mirror=True)
            if action == "heaps":
                heaps = await c.mem_heaps(pid, want_blocks, max_blocks)
                return _j({"count": len(heaps), "heaps": heaps,
                           "coverage": _coverage("enumeration", "complete")})
            if action == "phys_ranges":
                # Enumerate MmGetPhysicalMemoryRanges (re-queried per call).
                # Returned Base/Size come back as hex strings for LLM clients.
                ranges = await c.phys_ranges()
                total = sum(r["size"] for r in ranges)
                return _j({"count": len(ranges),
                           "total_ram_bytes": total,
                           "total_ram_gib": round(total / (1 << 30), 3),
                           "coverage": _coverage("enumeration", "complete"),
                           "ranges": [{"base": hex(r["base"]),
                                       "size": hex(r["size"]),
                                       "kind": r["kind"]} for r in ranges]})
            if action == "pool_scan":
                # Tag filter accepted as int or 4-char string ('EDID' etc.).
                # Pattern uses the same IDA-style hex OR raw hex bytes; mask
                # length must equal pattern length (or be empty).
                tag_i = 0
                if pattern:
                    from ...sdk import parse_mask
                    from ...sdk.reader import SuspexError as _ScanErr
                    try:
                        pat_bytes, mask_str = parse_mask(pattern)
                    except _ScanErr as exc:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": f"pool_scan: {exc}"})
                    if "H" in mask_str or "L" in mask_str:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": "pool_scan: nibble wildcards "
                                            "('6?'/'?F') aren't supported — "
                                            "the driver's pool matcher is "
                                            "byte-granular; use '?' for a "
                                            "wildcard byte"})
                    mask_bytes = mask_str.encode("ascii") if mask_str else b""
                else:
                    pat_bytes = bytes.fromhex(pattern_hex) if pattern_hex else b""
                    if "H" in mask or "L" in mask:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": "pool_scan: mask chars are "
                                            "'?' (wildcard) or 'x' (exact) "
                                            "— nibble masks ('H'/'L') are "
                                            "pattern_scan-only"})
                    mask_bytes = mask.encode("ascii") if mask else b""
                # A caller-supplied `module` arg carries the 4-char tag (we
                # already have a `module` field; overloading avoids adding
                # yet another top-level parameter for a single-use scan).
                if module:
                    tag = module.strip()
                    if len(tag) == 4:
                        tag_i = int.from_bytes(tag.encode("ascii", "replace"), "little")
                    else:
                        try:
                            tag_i = int(tag, 0)
                        except ValueError:
                            return _j({"ok": False,
                                       "error": f"pool_scan `module` (tag) must be a "
                                                f"4-char string or an int; got {module!r}"})
                # v0.16: refuse pattern + size=0 up front. The driver
                # (Pool.c:187-210) silently skips the content-filter branch
                # when span==0 and emits every considered entry with
                # matched_offset=0 — indistinguishable from a real hit at
                # VA 0. Fail fast with a typed error so the caller learns
                # the actual shape instead of trusting fake matches.
                content_span = int(size or 0)
                if pat_bytes and content_span <= 0:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "pool_scan pattern requires size>0 "
                                        "(content window)",
                               "hint": "set `size` to the number of bytes to "
                                       "read from `offset` into each "
                                       "allocation for the pattern match "
                                       "(e.g. size=256, offset=0)"})
                content_filter_active = bool(pat_bytes) and content_span > 0
                nonpaged_only = space == "kernel"  # kernel space => non-paged only
                result = await c.pool_scan(
                    tag_filter=tag_i,
                    nonpaged_only=nonpaged_only or kernel,
                    max_results=max_results or 256,
                    pattern=pat_bytes, mask=mask_bytes,
                    offset=protect,  # reuse `protect` int field for byte offset
                    content_span=content_span,
                )
                # v0.14 Layer 3: single uniform list envelope. `entries` rows
                # get _decoded siblings for pool_tag; `required` / `considered`
                # ride under `data` as extras. finalize strips `_int` mirrors +
                # `_decoded` siblings at the default verbosity.
                entries = _decode_list(result.get("entries", []), "pool")
                eff_limit = limit or max_results
                cov = _scan_window_cov(
                    {"truncated": len(entries) >= (max_results or 256)},
                    ranged=True)
                env = _list_envelope(
                    entries, tool="mem_rw", action="pool_scan",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"required": result.get("required", 0),
                            "considered": result.get("considered", 0),
                            "content_filter_active": content_filter_active},
                )
                env["coverage"] = cov
                return _hexify_dict(env, add_int_mirror=True)
            if action == "probe_va":
                # 1-byte read with allow_fault forced OFF. `readable`
                # tells you whether the address currently backs valid
                # memory without the risk of the driver's soft-fault
                # fallback bugchecking the target — the exact primitive
                # for walking unknown kernel pools.
                try:
                    await c.mem_read(pid, addr, 1, space, allow_fault=False)
                    return _j({"ok": True, "readable": True,
                               "address": hex(addr), "space": space})
                except Exception as exc:  # noqa: BLE001 - probe never raises
                    return _j({"ok": True, "readable": False,
                               "address": hex(addr), "space": space,
                               "reason": _enrich_win32(str(exc))})
            # ---- Phase 2 (ABI v7+): VaTranslate + MemoryWatch ----
            if action == "va_translate":
                if not hasattr(c, "mem_va_translate"):
                    return _j({"ok": False,
                               "error": "va_translate: agent < v7 (Memory.VaTranslate missing)",
                               "hint": "rebuild agent + comm + driver with ABI v7"})
                r = await c.mem_va_translate(addr, space=space, pid=pid)
                r.update({"ok": True, "va": hex(addr), "space": space, "pid": pid,
                          "pa_hex": hex(r["pa"])})
                return _j(r)
            if action == "watch":
                if not hasattr(c, "mem_watch_stream"):
                    return _j({"ok": False,
                               "error": "watch: agent < v7 (Memory.Watch missing)",
                               "hint": "rebuild agent with ABI v7"})
                if not size or size > 256:
                    return _j({"ok": False,
                               "error": "watch: `size` must be 1..256 (small-object watcher)",
                               "hint": "for larger reads use mem_rw read directly"})
                # Auto-poll (blocking-collect) mode when max_results is
                # small and interval*count is under 30 s. Otherwise
                # kick off a background task and return a handle for
                # `watch_list` / `watch_stop` / `watch_events` polling.
                interval_ms = max(int(timeout_s * 1000) or 100, 10)
                # `max_results` doubles as max_events for the watch.
                dur_s = min(max(int(max_results or 60), 1), 600)
                events_cap = min(int(max_results or 0), 256)
                expected = bytes.fromhex(pattern_hex) if pattern_hex else b""
                # Fast-path: short duration -> collect inline (auto-poll).
                if dur_s <= 30 and events_cap <= 32:
                    r = await c.mem_watch_collect(
                        address=addr, length=size, space=space, pid=pid,
                        interval_ms=interval_ms, duration_s=dur_s,
                        expected_hex=expected, max_events=events_cap,
                        tag=(filter or ""))
                    r.update({"address": hex(addr), "space": space, "pid": pid,
                              "length": size, "interval_ms": interval_ms,
                              "duration_s": dur_s, "mode": "collect"})
                    return _j(r)
                # Long-running: register a background task and return a handle.
                _WATCH_SEQ[0] += 1
                watch_id = f"w{_WATCH_SEQ[0]:04d}"
                bucket: dict[str, Any] = {
                    "id": watch_id, "events": [], "reason": "",
                    "started_ts": __import__("time").time(),
                    "tag": filter or "", "target": name,
                    "spec": {"address": hex(addr), "space": space, "pid": pid,
                             "length": size, "interval_ms": interval_ms,
                             "duration_s": dur_s, "max_events": events_cap},
                    "done": False,
                }
                async def _drain() -> None:
                    try:
                        async for ev in c.mem_watch_stream(
                            address=addr, length=size, space=space, pid=pid,
                            interval_ms=interval_ms, duration_s=dur_s,
                            expected_hex=expected, max_events=events_cap,
                            tag=filter or ""):
                            if ev.get("eof"):
                                bucket["reason"] = ev.get("reason") or ""
                                bucket["done"] = True
                                break
                            bucket["events"].append(ev)
                    except Exception as exc:  # noqa: BLE001
                        bucket["error"] = _enrich_win32(str(exc))
                        bucket["done"] = True
                bucket["task"] = asyncio.create_task(_drain())
                _WATCHES[watch_id] = bucket
                return _j({"ok": True, "watch_id": watch_id, "mode": "background",
                           "hint": "poll with mem_rw(action='watch_list') then "
                                   "read events (currently on the bucket); "
                                   "stop with watch_stop(name=watch_id)"})
            if action == "watch_list":
                out = []
                for wid, w in list(_WATCHES.items()):
                    out.append({"id": wid, "done": w["done"],
                                "events": len(w["events"]),
                                "reason": w.get("reason", ""),
                                "started_ts": w["started_ts"],
                                "tag": w.get("tag", ""),
                                "spec": w.get("spec", {}),
                                "error": w.get("error")})
                return _j({"ok": True, "watches": out})
            if action == "watch_stop":
                # Reuse `module` as the watch_id carrier (avoids a new arg).
                wid = module or filter
                w = _WATCHES.get(wid)
                if not w:
                    return _j({"ok": False,
                               "error": f"watch_stop: no watch with id {wid!r}"})
                if w.get("task") and not w["task"].done():
                    w["task"].cancel()
                w["done"] = True
                events = list(w["events"])
                _WATCHES.pop(wid, None)
                return _j({"ok": True, "watch_id": wid,
                           "events": events, "count": len(events),
                           "reason": w.get("reason") or "stopped"})
            if action == "disasm":
                raw = await _mem_disasm(
                    ctx, name=name, pid=pid, space=space,
                    address=addr, bytes_hex=bytes_hex,
                    arch=arch, syntax=syntax, count=count, size=size,
                    detail=_disasm_detail, resolve_symbols=resolve_symbols,
                    allow_fault=allow_fault, timeout_s=timeout_s,
                )
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    return raw
                if not isinstance(parsed, dict) or not parsed.get("ok"):
                    return parsed
                instructions = parsed.get("instructions", []) or []
                extras = {k: parsed[k] for k in
                          ("arch", "start", "bytes_used",
                           "truncated", "source", "first_bad_offset")
                          if k in parsed}
                eff_limit = limit or count or max_results
                if parsed.get("first_bad_offset") is not None:
                    cov = _coverage("mem-read", "partial",
                                    "read_failed_mid_buffer")
                elif parsed.get("truncated"):
                    cov = _coverage("mem-read", "partial", "decode_truncated")
                else:
                    cov = _coverage("mem-read", "complete")
                env = _list_envelope(
                    instructions, tool="mem_rw", action="disasm",
                    limit=eff_limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras=extras,
                )
                env["coverage"] = cov
                return _hexify_dict(env, add_int_mirror=True)
            if action == "assemble":
                return await _mem_assemble(
                    ctx, name=name, pid=pid, space=space,
                    code=code, arch=arch, address=addr,
                    write_to=write_to, dry_run=dry_run,
                    allow_map_write=allow_map_write,
                )
            # ---- v0.19: byte-surface extraction on live ranges ----
            if action in ("strings", "iocs"):
                if not addr or not size:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"{action} needs address= and size=",
                               "hint": "mem_rw strings address=0x... size=0x10000 "
                                       "min_len=6"})
                n = min(size, 4 * 1024 * 1024 - 0x1000)
                data = await c.mem_read(pid, addr, n, space,
                                        allow_fault=allow_fault,
                                        partial=partial,
                                        timeout=timeout_s or None)
                if isinstance(data, tuple):
                    data = data[0]
                from ...analysis.extract import find_iocs, find_strings
                if action == "strings":
                    rows = find_strings(data, min_len=max(3, min_len),
                                        utf16=True, base_va=addr)
                else:
                    rows = find_iocs(data, base_va=addr)
                if size > n:
                    cov = _coverage("mem-read", "partial", "size_cap_reached")
                elif len(data) < size:
                    cov = _coverage("mem-read", "partial",
                                    "read_failed_mid_buffer")
                else:
                    cov = _coverage("mem-read", "complete")
                env = _list_envelope(
                    rows, tool="mem_rw", action=action,
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=filter if isinstance(filter, str) else "",
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"source_va": addr, "bytes": len(data),
                            "truncated": len(data) < size},
                )
                env["coverage"] = cov
                return _hexify_dict(env, add_int_mirror=True)
            if action == "entropy":
                from ...analysis.entropy import entropy_map
                if addr and size:
                    n = min(size, 4 * 1024 * 1024 - 0x1000)
                    data = await c.mem_read(pid, addr, n, space,
                                            allow_fault=allow_fault,
                                            partial=partial,
                                            timeout=timeout_s or None)
                    if isinstance(data, tuple):
                        data = data[0]
                    em = entropy_map(data, buckets=buckets)
                    em["source_va"] = addr
                    em["truncated"] = len(data) < size
                    if size > n:
                        em["coverage"] = _coverage("mem-read", "partial",
                                                   "size_cap_reached")
                    elif len(data) < size:
                        em["coverage"] = _coverage("mem-read", "partial",
                                                   "read_failed_mid_buffer")
                    else:
                        em["coverage"] = _coverage("mem-read", "complete")
                    return _j_hex(em)
                # VAD sweep: score a bounded sample of each
                # private/executable region in the process.
                if not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "entropy sweep needs pid= "
                                        "(or address+size for a range)"})
                vads = await c.vad_list(pid)
                rows = []
                skipped = 0
                for e in vads:
                    prot = int(e.get("protect", 0))
                    start = int(e.get("start", 0))
                    end = int(e.get("end", 0))
                    if prot & 0xF0 not in (0x10, 0x20, 0x40, 0x80):
                        continue  # EXECUTE/_READ/_READWRITE/_WRITECOPY
                    try:
                        sample = await c.mem_read(
                            pid, start, min(end - start, 4096), "user",
                            allow_fault=True,
                            timeout=timeout_s or None)
                    except Exception:
                        skipped += 1
                        continue
                    if isinstance(sample, tuple):
                        sample = sample[0]
                    if not sample:
                        skipped += 1
                        continue
                    em = entropy_map(sample)
                    rows.append({"start": start, "end": end,
                                 "protect": prot,
                                 "entropy": em["mean_entropy"],
                                 "packed": em["packed"],
                                 "sampled": len(sample)})
                rows.sort(key=lambda r: -r["entropy"])
                env = _list_envelope(
                    rows, tool="mem_rw", action="entropy",
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=filter if isinstance(filter, str) else "",
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"mode": "vad_sweep", "pid": pid},
                )
                env["coverage"] = _coverage(
                    "enumeration",
                    "partial" if skipped else "complete",
                    *(["vad_read_skipped"] if skipped else []))
                return _hexify_dict(env, add_int_mirror=True)
            # ---- v0.20: system-wide per-thread inventory ----
            if action == "threads":
                try:
                    res = await c.thread_list(pid=pid, kernel=kernel,
                                              with_context=with_context)
                except Exception as exc:
                    msg = str(exc)
                    if "UNIMPLEMENTED" in msg:
                        return _j({"ok": False, "kind": "agent_version",
                                   "error": ("threads: agent < v11 "
                                             "(Memory.ThreadList missing)"),
                                   "hint": ("rebuild + redeploy the agent "
                                            "(scripts/update_target.py "
                                            "--component agent)")})
                    return _j({"ok": False, "kind": "thread_enum_failed",
                               "error": msg})
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "thread_enum_failed",
                               "error": res.get("error",
                                                "thread list failed")})
                rows = res.get("threads", [])
                # Module attribution: flag start VAs outside every loaded
                # module (the injected-thread *sense* — a fact, not a
                # verdict). Kernel list for kernel threads, the pid's user
                # list otherwise.
                mods = []
                try:
                    mods = await c.mem_modules(pid, True)
                except Exception:
                    mods = []
                ranges = []
                for m in mods or []:
                    try:
                        b = int(m.get("base", 0) or 0)
                        z = int(m.get("size", 0) or 0)
                        if b and z:
                            ranges.append((b, b + z, str(m.get("name", ""))))
                    except Exception:
                        continue
                for r in rows:
                    sv = int(r.get("start_va", 0) or 0)
                    hit = next(((lo, hi, nm) for lo, hi, nm in ranges
                                if lo <= sv < hi), None)
                    r["in_module"] = hit is not None
                    if hit:
                        r["module"] = hit[2]
                env = _list_envelope(
                    rows, tool="mem_rw", action="threads",
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=filter if isinstance(filter, str) else "",
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"source": res.get("source", "agent"),
                            "truncated": res.get("truncated", False),
                            "note": ("start_va outside every loaded module "
                                     "is the injected-thread shape — an "
                                     "observation, not a verdict")},
                )
                env["coverage"] = _coverage(
                    "enumeration",
                    "partial" if res.get("truncated") else "complete",
                    *(["provider_truncated"] if res.get("truncated") else []))
                return _j_hex(env)

            # ---- v0.20: kernel object-directory enumeration ----
            if action == "obj_enum":
                if not path:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": ("obj_enum: path= is required "
                                         "(e.g. path='\\\\Device')"),
                               "hint": ("mem_rw(action='obj_enum', "
                                        "path='\\\\Device', depth=1) — "
                                        "feeds device_manage ioctl sends")})
                try:
                    res = await c.obj_enum(path, depth=depth,
                                           max_entries=max_results or 4096)
                except Exception as exc:
                    msg = str(exc)
                    if "UNIMPLEMENTED" in msg:
                        return _j({"ok": False, "kind": "agent_version",
                                   "error": ("obj_enum: agent < v11 "
                                             "(Memory.ObjEnum missing)"),
                                   "hint": ("rebuild + redeploy the agent "
                                            "(scripts/update_target.py "
                                            "--component agent)")})
                    return _j({"ok": False, "kind": "obj_enum_failed",
                               "error": msg})
                if not res.get("ok"):
                    return _j({"ok": False, "kind": "obj_enum_failed",
                               "error": res.get("error", "obj enum failed")})
                env = _list_envelope(
                    res.get("entries", []), tool="mem_rw", action="obj_enum",
                    limit=limit or max_results, offset=offset,
                    fields=fields or (),
                    filter=filter if isinstance(filter, str) else "",
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"path": path, "depth": depth,
                            "truncated": res.get("truncated", False),
                            "note": ("device names here feed "
                                     "device_manage(action='ioctl') "
                                     "directly")},
                )
                env["coverage"] = _coverage(
                    "enumeration",
                    "partial" if res.get("truncated") else "complete",
                    *(["provider_truncated"] if res.get("truncated") else []))
                return _j(env)

            return _unknown_action("mem_rw", action, MEM_ACTIONS, _MEM_ACTION_HELP)

        return await _guard(ctx, "mem_rw", action, args,
                            _ev_with(ctx, "mem_rw", action, args, run,
                                     _ev_detail))
