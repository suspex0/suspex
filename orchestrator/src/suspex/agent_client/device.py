"""Device + telemetry + thread-inventory client methods (ABI v11).

Device.Ioctl is the actuator half of the ioctl_surface loop: send an
arbitrary CTL_CODE to a device on the target. Telemetry is read-only ETW
inventory. ThreadList is the system-wide per-thread walk (agent-side
NtQuerySystemInformation; the driver-backed enrichment rides the same RPC
once the v11 driver ships).
"""

from __future__ import annotations

from typing import Any

from ..generated import suspex_pb2 as pb
from .wire import status_dict


class DeviceMixin:
    # ------------------------------------------------------------- Device ----

    async def device_ioctl(self, device: str, code: int,
                           in_data: bytes = b"", out_size: int = 4096,
                           timeout_ms: int = 0) -> dict[str, Any]:
        """Send one IOCTL to a device. ACTUATOR — the orchestrator gates
        this behind security.allow_ioctl_send; a bad code can bugcheck the
        target. `device` accepts a DOS symlink ("\\\\.\\Name") or a raw NT
        object path ("\\Device\\Name")."""
        if self.device is None:
            return {"ok": False, "error": "agent < v11 (Device service missing)",
                    "kind": "agent_version", "hint": "rebuild + redeploy the agent"}
        msg = await self._call(
            self.device.Ioctl,
            pb.DeviceIoctlRequest(device=device, code=int(code),
                                  in_buffer=in_data, out_size=int(out_size),
                                  timeout_ms=int(timeout_ms)),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "out": bytes(msg.out_buffer),
                "bytes_returned": int(msg.bytes_returned),
                "last_error": int(msg.last_error)}

    # ---------------------------------------------------------- Telemetry ----

    async def etw_providers(self, name_filter: str = "") -> dict[str, Any]:
        """Enumerate registered ETW providers (TdhEnumerateProviders)."""
        if self.telemetry is None:
            return {"ok": False, "error": "agent < v11 (Telemetry service missing)",
                    "kind": "agent_version"}
        msg = await self._call(
            self.telemetry.Providers,
            pb.EtwProvidersRequest(name_filter=name_filter or ""),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "providers": [{"guid": p.guid, "name": p.name}
                              for p in msg.providers],
                "count": int(msg.count), "truncated": bool(msg.truncated)}

    async def etw_sessions(self, name_filter: str = "") -> dict[str, Any]:
        """Enumerate active ETW trace sessions (QueryAllTraces)."""
        if self.telemetry is None:
            return {"ok": False, "error": "agent < v11 (Telemetry service missing)",
                    "kind": "agent_version"}
        msg = await self._call(
            self.telemetry.Sessions,
            pb.EtwSessionsRequest(name_filter=name_filter or ""),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "sessions": [{"name": s.name, "logger_id": int(s.logger_id),
                              "buffers_written": int(s.buffers_written),
                              "buffers_lost": int(s.buffers_lost),
                              "events_lost": int(s.events_lost),
                              "loggers": int(s.loggers)}
                             for s in msg.sessions],
                "count": int(msg.count)}

    # ---------------------------------------------------------- ThreadList ----

    async def thread_list(self, pid: int = 0, kernel: bool = False,
                          with_context: bool = False) -> dict[str, Any]:
        """System-wide per-thread inventory (agent-side NtQuerySystemInformation;
        kernel=true routes to the driver-backed walk on v11 drivers).

        v14 `with_context`: attach a SuspendThread+GetThreadContext register
        frame per thread — the lightweight "is it really wedged" snapshot
        that avoids a dbgeng attach. Empty context_regs on threads that
        wouldn't open."""
        req_kw: dict[str, Any] = {"pid": int(pid), "kernel": bool(kernel)}
        if "with_context" in pb.ThreadListRequest.DESCRIPTOR.fields_by_name:
            req_kw["with_context"] = bool(with_context)
        msg = await self._call(
            self.memory.ThreadList,
            pb.ThreadListRequest(**req_kw),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "source": str(msg.source),
                "truncated": bool(msg.truncated),
                "count": int(msg.count),
                "threads": [{"tid": int(t.tid), "pid": int(t.pid),
                             "start_va": int(t.start_va),
                             "state": int(t.state),
                             "wait_reason": int(t.wait_reason),
                             "base_priority": int(t.base_priority),
                             "win32_start_va": int(t.win32_start_va),
                             "teb": int(t.teb),
                             "context_regs": (dict(t.context_regs)
                                             if "context_regs" in
                                                t.DESCRIPTOR.fields_by_name
                                             else {})}
                            for t in msg.threads]}

    # ------------------------------------------------------------- ObjEnum ----

    async def obj_enum(self, path: str, depth: int = 1,
                       max_entries: int = 4096) -> dict[str, Any]:
        """Kernel object-directory enumeration (driver-backed, v11)."""
        msg = await self._call(
            self.memory.ObjEnum,
            pb.ObjEnumRequest(path=path, depth=int(depth),
                              max_entries=int(max_entries)),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "count": int(msg.count), "truncated": bool(msg.truncated),
                "entries": [
                    {
                        "name": e.name,
                        "type": e.type,
                        # v1.0.1 Phase 3.1: body VA + type-index + source.
                        # Empty / 0 on pre-v1.0.1 agents.
                        "address": int(getattr(e, "address", 0) or 0),
                        "type_index": int(
                            getattr(e, "type_index", 0) or 0),
                        "source": str(getattr(e, "source", "") or ""),
                    }
                    for e in msg.entries]}

    # -------------------------------------------------------------- Events ----

    async def events_poll(self, since_seq: int = 0,
                          max_events: int = 256,
                          kinds_mask: int = 0,
                          dangerous_ok: bool = False) -> dict[str, Any]:
        """One bounded drain of the driver's notify ring (pull model).
        v12: kinds_mask filters (1<<kind); bit 6 (BP_HIT) additionally
        installs the driver's int1 hook — needs dangerous_ok."""
        msg = await self._call(
            self.events.Poll,
            pb.EventsPollRequest(since_seq=int(since_seq),
                                 max_events=int(max_events),
                                 kinds_mask=int(kinds_mask),
                                 dangerous_ok=bool(dangerous_ok)),
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "last_seq": int(msg.last_seq), "dropped": int(msg.dropped),
                "subscribed": bool(msg.subscribed),
                "bp_hook": bool(getattr(msg, "bp_hook", False)),
                "events": [self._event_dict(e) for e in msg.events]}

    async def events_disable(self) -> dict[str, Any]:
        """Unregister the driver's notify callbacks (kernel-visible state)."""
        msg = await self._call(self.events.Disable, pb.OpStatus())
        return {"ok": msg.ok, "error": msg.error}

    async def events_stats(self) -> dict[str, Any]:
        """Notify-ring snapshot: buffered/dropped/seq + registered classes."""
        msg = await self._call(self.events.Stats, pb.EventsStatsRequest())
        return {"ok": msg.status.ok, "error": msg.status.error,
                "buffered": int(msg.buffered), "dropped": int(msg.dropped),
                "seq": int(msg.seq),
                "proc_notify": bool(msg.proc_notify),
                "image_notify": bool(msg.image_notify),
                "thread_notify": bool(msg.thread_notify),
                "bp_hook": bool(getattr(msg, "bp_hook", False)),
                "bp_missed": int(getattr(msg, "bp_missed", 0))}

    def events_stream(self, kinds_mask: int = 0, interval_ms: int = 250,
                      duration_s: int = 0, max_events: int = 0,
                      dangerous_ok: bool = False):
        """Server-streaming drain of the notify ring. Returns the gRPC call
        object (async iterator of EventsStreamChunk) — the caller owns the
        iteration lifetime (orchestrator background consumer). v12:
        dangerous_ok consents to the int1 hook when kinds_mask has bit 6."""
        kwargs = dict(kinds_mask=int(kinds_mask),
                      interval_ms=int(interval_ms),
                      duration_s=int(duration_s),
                      max_events=int(max_events))
        if dangerous_ok:
            kwargs["dangerous_ok"] = True
        req = pb.EventsStreamRequest(**kwargs)
        return self.events.Stream(req, metadata=self._meta())

    @staticmethod
    def _event_dict(e) -> dict[str, Any]:
        return {"seq": int(e.seq), "ts_ms": int(e.ts_ms),
                "kind": int(e.kind), "pid": int(e.pid),
                "parent_pid": int(e.parent_pid), "tid": int(e.tid),
                "image": str(e.image), "cmdline": str(e.cmdline),
                "dropped": bool(e.dropped),
                "address": int(getattr(e, "address", 0)),
                "dr6": int(getattr(e, "dr6", 0)),
                "bp_id": int(getattr(e, "bp_id", 0)),
                "slot": int(getattr(e, "slot", 0)),
                "access": int(getattr(e, "access", 0)),
                "irql": int(getattr(e, "irql", 0))}
