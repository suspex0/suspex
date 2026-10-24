"""Memory-service methods split off from AgentClient."""

from __future__ import annotations

from typing import Any, AsyncIterator

from ..generated import suspex_pb2 as pb
from .wire import proto_to_dict, status_dict

# v12: MemoryWriteRequest.flags mirrors SUSPEX_MEM_WRF_* (comm/suspex_abi.h);
# response write_path indexes proto's 0..3 enum.
_SUSPEX_MEM_WRF_STRICT_VA = 0x1
_WRITE_PATH_NAMES = {0: "unknown", 1: "direct_va", 2: "phys_remap", 3: "foreign_cr3"}


class MemMixin:
    # --------------------------------------------------------------- Memory ----

    async def mem_read(self, pid: int, address: int, size: int, space: str = "user",
                       allow_fault: bool = False,
                       partial: bool = False,
                       timeout: float | None = None,
                       want_meta: bool = False,
                       *,
                       max_bytes: int = 0) -> bytes | tuple[bytes, dict]:
        """Read `size` bytes from `pid`/`address` in the given space.

        v6 `partial=True` (kernel space only): per-4KB walk on the driver
        side; returns whatever prefix succeeds. Combine with `want_meta=True`
        to get `(data, {"read_bytes": N, "first_bad_offset": M})` — the
        offset tells you where the hole starts so you can advance past it.
        Without want_meta the return is bytes as before (backwards-compat).

        v9 `max_bytes` (keyword-only): agent-side hard byte cap independent
        of `size`. 0 disables. When set to N < size, the driver reads only
        N bytes without touching the maxMemReadBytes ceiling.
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req_kwargs = {"pid": pid, "address": address, "size": size, "space": sp,
                      "allow_fault": allow_fault}
        # Only set partial= when the caller asked for it — a v5 agent that
        # doesn't know the field silently ignores unknown proto3 fields.
        if partial:
            req_kwargs["partial"] = True
        if max_bytes:
            req_kwargs["max_bytes"] = int(max_bytes)
        msg = await self._call(
            self.memory.Read,
            pb.MemoryReadRequest(**req_kwargs),
            timeout=timeout,
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        data = bytes(msg.data)
        if want_meta:
            meta = {"read_bytes": msg.read_bytes,
                    "first_bad_offset": getattr(msg, "first_bad_offset", 0)}
            return data, meta
        return data

    async def mem_write(self, pid: int, address: int, data: bytes, space: str = "user",
                        allow_map_write: bool = False, *,
                        strict_va: bool = False, cr3: int = 0) -> dict[str, Any]:
        """Write `data` to `pid`/`address`; returns
        ``{"written_bytes": n, "write_path": str}``.

        v12 (ABI v12 agent+driver): `write_path` reports which store path
        ran — "direct_va" (linear VA copy), "phys_remap" (page-walk +
        physical map; DR watchpoints on the linear address did NOT see
        the store), "foreign_cr3" (direct VA under `cr3`), or "unknown"
        (pre-v12 peer / no out-reply).

        `strict_va` (kernel space): refuse the phys-remap fallback — a
        fault on the direct VA path fails the write instead of silently
        bypassing linear-address watchpoints.
        `cr3` (kernel space): run the store under the caller-supplied
        address space (driver verifies the foreign kernel half first).
        Both are keyword-only; `allow_map_write` stays positional-or-keyword
        for the pre-v12 callers that pass it as the 5th arg.
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        flags = _SUSPEX_MEM_WRF_STRICT_VA if strict_va else 0
        msg = await self._call(
            self.memory.Write,
            pb.MemoryWriteRequest(pid=pid, address=address, data=data, space=sp,
                                  allow_map_write=allow_map_write,
                                  cr3=cr3, flags=flags),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"written_bytes": msg.written_bytes,
                "write_path": _WRITE_PATH_NAMES.get(
                    msg.write_path, f"path_{msg.write_path}")}

    async def mem_alloc(self, pid: int, size: int, protect: int = 4, kernel: bool = False) -> int:
        msg = await self._call(
            self.memory.Alloc,
            pb.MemoryAllocRequest(pid=pid, size=size, protect=protect, kernel=kernel),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return msg.address

    async def mem_free(self, pid: int, address: int, kernel: bool = False) -> dict[str, Any]:
        st = await self._call(
            self.memory.Free, pb.MemoryFreeRequest(pid=pid, address=address, kernel=kernel)
        )
        return status_dict(st.status)

    async def mem_protect(self, pid: int, address: int, size: int, protect: int) -> dict[str, Any]:
        msg = await self._call(
            self.memory.Protect,
            pb.MemoryProtectRequest(pid=pid, address=address, size=size, protect=protect),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"old_protect": msg.old_protect}

    async def mem_modules(self, pid: int, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        msg = await self._call(
            self.memory.Modules,
            pb.ModulesRequest(pid=pid, kernel=kernel, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(m) for m in msg.modules]

    async def mem_imports(self, pid: int, module: str, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Walk the IAT of `module` in `pid` (or in the kernel view when kernel=True)."""
        msg = await self._call(
            self.memory.ModuleImports,
            pb.ModuleImportsRequest(pid=pid, module=module, kernel=kernel,
                                    limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def mem_exports(self, pid: int, module: str, kernel: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Walk the export table of `module` in `pid` (kernel view when kernel=True)."""
        msg = await self._call(
            self.memory.ModuleExports,
            pb.ModuleExportsRequest(pid=pid, module=module, kernel=kernel,
                                    limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def mem_heaps(self, pid: int, want_blocks: bool = False,
                        max_blocks: int = 0) -> list[dict[str, Any]]:
        """Cross-process heap enumeration; want_blocks=True fetches per-block detail."""
        msg = await self._call(
            self.memory.HeapList,
            pb.HeapListRequest(pid=pid, want_blocks=want_blocks, max_blocks=max_blocks),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(h) for h in msg.heaps]

    async def mem_processes(self, *, limit: int = 0, offset: int = 0,
                            with_cmdline: bool = False,
                            full: bool = False) -> list[dict[str, Any]] | dict[str, Any]:
        # v14: agent+umagent enumerate via NtQuerySystemInformation now —
        # no driver dependency, plus session_id + create_time_100ns rows.
        # cmdline is opt-in (per-pid open cost). full=True returns
        # {"processes": [...], "source": "agent"|"driver"} so callers can
        # tell which enumerator answered.
        req_kw: dict[str, Any] = {"limit": limit, "offset": offset}
        if "with_cmdline" in pb.ListProcessesRequest.DESCRIPTOR.fields_by_name:
            req_kw["with_cmdline"] = bool(with_cmdline)
        msg = await self._call(
            self.memory.ListProcesses,
            pb.ListProcessesRequest(**req_kw),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        rows = [proto_to_dict(p) for p in msg.processes]
        if full:
            return {"processes": rows,
                    "source": str(getattr(msg, "source", "") or "agent")}
        return rows

    async def mem_scan(
        self, pid: int, pattern: bytes, mask: str = "", base: int = 0, size: int = 0,
        max_results: int = 64, space: str = "user",
    ) -> list[int]:
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        msg = await self._call(
            self.memory.Scan,
            pb.PatternScanRequest(
                pid=pid, pattern=pattern, mask=mask, base=base, size=size,
                max_results=max_results, space=sp,
            ),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return list(msg.addresses)

    async def mem_scan_stream(
        self, pid: int, pattern: bytes, mask: str = "", base: int = 0,
        size: int = 0, max_results: int = 64, space: str = "user",
    ) -> "AsyncIterator[dict[str, Any]]":
        """v0.16 (ABI v10): server-streaming pattern scan.

        Yields one dict per PatternScanChunk arriving from the agent:
        ``{addresses: [int,...], bytes_scanned, cursor, done, status?}``.
        Consumer cancels by breaking out of the iteration — gRPC tears
        down the stream and the agent's handler observes IsCancelled().
        """
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        request = pb.PatternScanRequest(
            pid=pid, pattern=pattern, mask=mask, base=base, size=size,
            max_results=max_results, space=sp,
        )
        # No client-side timeout: scan streams are inherently long. If the
        # caller wants a deadline they wrap the iteration in asyncio.wait_for
        # or break out on their own progress-timeout logic.
        call = self.memory.ScanStream(request, metadata=self._meta())
        async for chunk in call:
            out: dict[str, Any] = {
                "addresses": list(chunk.addresses),
                "bytes_scanned": int(chunk.bytes_scanned),
                "cursor": int(chunk.cursor),
                "done": bool(chunk.done),
            }
            if chunk.HasField("status") and not chunk.status.ok:
                out["error"] = chunk.status.error
            yield out

    async def vad_list(self, pid: int, *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """VAD walk of pid (kernel view; build-gated offsets)."""
        msg = await self._call(
            self.memory.VadList,
            pb.VadRequest(pid=pid, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(e) for e in msg.entries]

    async def handle_list(self, pid: int, want_names: bool = False,
                          *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Handle table of pid; names resolved only when want_names (slow)."""
        msg = await self._call(
            self.memory.HandleList,
            pb.HandleListRequest(pid=pid, want_names=want_names,
                                 limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(h) for h in msg.handles]

    # -------------------------------------- v4: phys ranges / pool scan / reg --

    async def phys_ranges(self, *, limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        """Enumerate MmGetPhysicalMemoryRanges (re-queried per call)."""
        msg = await self._call(
            self.memory.PhysicalRanges,
            pb.PhysRangesRequest(limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [{"base": r.base, "size": r.size, "kind": r.kind} for r in msg.ranges]

    async def pool_scan(self, tag_filter: int = 0, nonpaged_only: bool = False,
                        paged_only: bool = False, max_results: int = 256,
                        pattern: bytes = b"", mask: bytes = b"",
                        offset: int = 0, content_span: int = 0,
                        cursor: int = 0) -> dict[str, Any]:
        """Kernel big-pool walk with optional tag/paged/content filters.

        `pattern` (<=64 bytes, v0.31+ driver) + `content_span` (<=64 KiB,
        v0.31+ driver) drives an MmCopyMemory-backed content check on
        each surviving entry; a wildcard mask byte is 0 or '?' (0x3F).

        v0.31 Phase 3.2: `cursor` resumes a prior scan from
        ``next_cursor``; the response carries `holes`, `span_truncated`,
        `last_index`, and `next_cursor` (0 when the scan completed).
        """
        req_kwargs = {
            "tag_filter": tag_filter, "nonpaged_only": nonpaged_only,
            "paged_only": paged_only, "max_results": max_results,
            "pattern": pattern, "mask": mask,
            "offset": offset, "content_span": content_span,
        }
        probe = pb.PoolScanRequest()
        if hasattr(probe, "cursor"):
            req_kwargs["cursor"] = int(cursor)
        req = pb.PoolScanRequest(**req_kwargs)
        msg = await self._call(self.memory.PoolScan, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "required": msg.required, "considered": msg.considered,
            # v0.31 Phase 3.2 fields; 0 on pre-v0.31 agents.
            "holes": int(getattr(msg, "holes", 0) or 0),
            "span_truncated": int(getattr(msg, "span_truncated", 0) or 0),
            "last_index": int(getattr(msg, "last_index", 0) or 0),
            "next_cursor": int(getattr(msg, "next_cursor", 0) or 0),
            "entries": [{
                "va": e.virtual_address, "size": e.size_in_bytes,
                "tag": e.tag, "tag_ascii": e.tag_ascii,
                "nonpaged": e.nonpaged,
                "matched_offset": e.matched_offset,
            } for e in msg.entries],
        }

    # ------------------------------------- v5: mem streaming + agent breadcrumb --

    async def mem_read_stream(self, pid: int, address: int, size: int,
                              space: str = "user",
                              allow_fault: bool = False,
                              timeout: float | None = None):
        """Async iterator of (offset, bytes) chunks over the server-streaming
        Memory.ReadStream RPC. Removes the manual-chunk dance callers had
        to do for >4 MiB kernel reads. Caller consumes:

            async for offset, chunk in c.mem_read_stream(0, va, size, "kernel"):
                out[offset:offset+len(chunk)] = chunk

        Raises RuntimeError on any mid-stream error chunk.
        """
        if not hasattr(self.memory, "ReadStream"):
            raise RuntimeError("mem_read_stream: agent < v5 (Memory.ReadStream missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.MemoryReadRequest(pid=pid, address=address, size=size, space=sp,
                                   allow_fault=allow_fault)
        eff = self._timeout if timeout is None else (timeout if timeout > 0 else None)
        # streaming call bypasses our _call ring; we do NOT record it in
        # recent_ops (stream events already have their own audit path).
        stream = self.memory.ReadStream(req, metadata=self._meta(), timeout=eff)
        first = True
        async for chunk in stream:
            if first:
                first = False
                if chunk.HasField("status") and not chunk.status.ok:
                    raise RuntimeError(f"mem_read_stream: {chunk.status.error}")
            if chunk.HasField("status") and chunk.status.error:
                # Mid-stream error chunk: raise. eof will also be set.
                raise RuntimeError(f"mem_read_stream: {chunk.status.error}")
            if chunk.data:
                yield chunk.offset, chunk.data
            if chunk.eof:
                return

    async def mem_read_all(self, pid: int, address: int, size: int,
                           space: str = "user", allow_fault: bool = False,
                           timeout: float | None = None,
                           cap_bytes: int = 256 * 1024 * 1024) -> bytes:
        """Collect a mem_read_stream() into a single bytes. `cap_bytes` is
        a safety belt against a runaway caller — raises if size exceeds it.
        """
        if size > cap_bytes:
            raise ValueError(f"mem_read_all: size {size} > cap_bytes {cap_bytes}; "
                             "raise cap_bytes or use mem_read_stream directly")
        buf = bytearray(size)
        async for off, data in self.mem_read_stream(pid, address, size, space,
                                                     allow_fault=allow_fault,
                                                     timeout=timeout):
            end = off + len(data)
            if end > size:
                # Server sent past our end — clamp; probably a bug there
                data = data[: size - off]
                end = size
            buf[off:end] = data
        return bytes(buf)

    # ------------------------------------- v7: va_translate + memory watch --

    async def mem_va_translate(self, va: int, space: str = "kernel",
                                pid: int = 0, cr3: int = 0) -> dict[str, Any]:
        """VA -> PA via the driver's page-table walk.

        v12: `space="user"` requires `pid` — the driver attaches to that
        process and walks its tables. `cr3` (either space) forces an
        explicit root instead of the space/pid-resolved one — useful for
        foreign-address-space forensics.
        """
        if not hasattr(self.memory, "VaTranslate"):
            raise RuntimeError("mem_va_translate: agent < v7 (Memory.VaTranslate missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.VaTranslateRequest(space=sp, pid=pid, va=va, cr3=cr3)
        msg = await self._call(self.memory.VaTranslate, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "pa": msg.pa, "present": msg.present, "cr3": msg.cr3,
            "page_size_shift": msg.page_size_shift,
        }

    async def idt_list(self, all_cpus: bool = False) -> dict[str, Any]:
        """v12 per-CPU IDT dump (Memory.IdtList, ABI v12).

        Returns ``{"ok", "idt_base", "idt_limit", "entries": [row, ...]}``
        where each row keeps the raw decoded KIDTENTRY64 fields —
        cpu/vector/handler_va/selector/ist/dpl plus `idt_base` (the IDTR
        base of the CPU that row was read on; per-CPU drift is a detour
        signature for the caller to score).
        """
        if not hasattr(self.memory, "IdtList"):
            raise RuntimeError("idt_list: agent < v12 (Memory.IdtList missing)")
        msg = await self._call(self.memory.IdtList,
                               pb.IdtListRequest(all_cpus=all_cpus))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "ok": True,
            "idt_base": msg.idt_base,
            "idt_limit": msg.idt_limit,
            "entries": [{
                "cpu": e.cpu, "vector": e.vector,
                "handler_va": e.handler_va, "selector": e.selector,
                "ist": e.ist, "dpl": e.dpl,
                "idt_base": getattr(e, "idt_base", 0),
            } for e in msg.entries],
        }

    async def mem_watch_stream(self, address: int, length: int,
                               space: str = "kernel", pid: int = 0,
                               interval_ms: int = 100, duration_s: int = 60,
                               expected_hex: bytes = b"", max_events: int = 0,
                               tag: str = "") -> AsyncIterator[dict[str, Any]]:
        """Async iterator over Memory.Watch events. Yields dicts with
        {seq, ts_ms, prev, now, eof, reason, read_failed}. Terminates when
        the agent closes the stream (duration/max_events/read_failed) or
        when the caller stops iterating (client-cancel semantics).
        """
        if not hasattr(self.memory, "Watch"):
            raise RuntimeError("mem_watch_stream: agent < v7 (Memory.Watch missing)")
        sp = {"user": pb.USER, "kernel": pb.KERNEL, "physical": pb.PHYSICAL}[space]
        req = pb.WatchRequest(space=sp, pid=pid, address=address, length=length,
                              interval_ms=interval_ms, duration_s=duration_s,
                              expected_hex=expected_hex, max_events=max_events,
                              tag=tag)
        stream = self.memory.Watch(req, metadata=self._meta(),
                                   timeout=None)  # No client-side deadline
        first = True
        async for ev in stream:
            if first:
                first = False
                if ev.HasField("status") and not ev.status.ok:
                    raise RuntimeError(f"mem_watch: {ev.status.error}")
            yield {
                "seq": ev.seq,
                "ts_ms": ev.ts_ms,
                "prev": bytes(ev.prev).hex(),
                "now": bytes(ev.now).hex(),
                "eof": ev.eof,
                "reason": ev.reason,
                "read_failed": ev.read_failed,
            }
            if ev.eof:
                return

    async def mem_watch_collect(self, address: int, length: int,
                                 space: str = "kernel", pid: int = 0,
                                 interval_ms: int = 100, duration_s: int = 60,
                                 expected_hex: bytes = b"", max_events: int = 0,
                                 tag: str = "") -> dict[str, Any]:
        """Synchronous helper for one-shot MCP callers: run the watch to
        completion and return the accumulated events. For long-running or
        push-style workflows use the mem_watch_stream iterator directly."""
        events: list[dict[str, Any]] = []
        reason = ""
        async for ev in self.mem_watch_stream(
            address=address, length=length, space=space, pid=pid,
            interval_ms=interval_ms, duration_s=duration_s,
            expected_hex=expected_hex, max_events=max_events, tag=tag,
        ):
            if ev["eof"]:
                reason = ev.get("reason") or ""
                break
            events.append(ev)
            if max_events and len(events) >= max_events:
                # Client-side cap in case the agent's max_events guard
                # missed by one (defensive; the stream should EOF first).
                break
        return {"ok": True, "events": events, "count": len(events),
                "reason": reason, "tag": tag}
