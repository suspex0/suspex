"""Debug-service (and breakpoints) methods split off from AgentClient."""

from __future__ import annotations

from typing import Any, AsyncIterator

from ..generated import suspex_pb2 as pb
from .events import Event
from .wire import proto_to_dict, status_dict


class DebugMixin:
    # ---------------------------------------------------------------- Debug ----

    async def debug_launch(self, cmdline: str, workdir: str = "", break_on_entry: bool = True) -> dict[str, Any]:
        msg = await self._call(
            self.debug.Launch,
            pb.LaunchRequest(cmdline=cmdline, working_dir=workdir, break_on_entry=break_on_entry),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"pid": msg.pid, "tid": msg.initial_tid}

    async def debug_attach(self, pid: int, monitor: bool = False) -> dict[str, Any]:
        st = await self._call(self.debug.Attach, pb.AttachRequest(pid=pid, monitor=monitor))
        return status_dict(st)

    async def debug_detach(self, kill: bool = False) -> dict[str, Any]:
        st = await self._call(self.debug.Detach, pb.DetachRequest(kill=kill))
        return status_dict(st)

    async def debug_continue(self) -> dict[str, Any]:
        return status_dict(await self._call(self.debug.Continue, pb.ContinueRequest()))

    async def debug_step(self, over: bool = False, count: int = 1) -> dict[str, Any]:
        st = await self._call(
            self.debug.Step,
            pb.StepRequest(kind=pb.StepRequest.STEP_OVER if over else pb.StepRequest.STEP_INTO, count=count),
        )
        return status_dict(st)

    async def debug_regs(self) -> dict[str, Any]:
        msg = await self._call(self.debug.GetRegs, pb.GetRegsRequest())
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return proto_to_dict(msg.regs)

    async def debug_set_regs(self, **kwargs: Any) -> dict[str, Any]:
        fields = {k: v for k, v in kwargs.items() if k in pb.Registers.DESCRIPTOR.fields_by_name}
        gpr_names = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
        msg = await self._call(
            self.debug.SetRegs,
            pb.SetRegsRequest(
                registers=pb.Registers(**fields),
                apply_gprs=any(k in gpr_names for k in kwargs),
                apply_rip=bool(kwargs.get("rip")),
                apply_rflags=bool(kwargs.get("rflags")),
                apply_dr=any(k.startswith("dr") for k in kwargs),
            ),
        )
        return status_dict(msg.status)

    async def debug_threads(self) -> dict[str, Any]:
        msg = await self._call(self.debug.GetThreads, pb.GetThreadsRequest())
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"current_tid": msg.current_tid, "threads": [proto_to_dict(t) for t in msg.threads]}

    async def debug_stacktrace(self, max_frames: int = 32) -> list[dict[str, Any]]:
        msg = await self._call(self.debug.Stacktrace, pb.StacktraceRequest(max_frames=max_frames))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(f) for f in msg.frames]

    async def debug_read(self, address: int, size: int) -> bytes:
        msg = await self._call(self.debug.ReadMemory, pb.DebugReadRequest(address=address, size=size))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return bytes(msg.data)

    async def debug_write(self, address: int, data: bytes) -> dict[str, Any]:
        st = await self._call(self.debug.WriteMemory, pb.DebugWriteRequest(address=address, data=data))
        return status_dict(st)

    async def debug_regions(self, pid: int = 0, *,
                            limit: int = 0, offset: int = 0) -> list[dict[str, Any]]:
        msg = await self._call(
            self.debug.Regions,
            pb.MemoryRegionsRequest(pid=pid, limit=limit, offset=offset),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(r) for r in msg.regions]

    async def dbg_cmd(self, command: str) -> str:
        """Raw dbgeng command passthrough; returns the engine output text."""
        msg = await self._call(self.debug.ExecuteCommand,
                               pb.ExecuteCommandRequest(command=command))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return msg.output

    async def debug_events(self, from_seq: int = 0) -> AsyncIterator[dict[str, Any]]:
        async for ev in self.debug.StreamEvents(
            pb.StreamDebugEventsRequest(from_seq=from_seq), metadata=self._meta()
        ):
            d = proto_to_dict(ev)
            self.bus.publish(Event(kind="debug", data=d))
            yield d

    # ----------------------------------------------------------- Breakpoints ----

    async def bp_add(
        self, kind: str, address: int, slot: int = 0, size: int = 1, access: str = "exec",
        kernel_target: bool = False, pid: int = 0, tid: int = 0,
        global_: bool = False, dangerous_ok: bool = False,
        via_debugger: bool = False,
    ) -> dict[str, Any]:
        # v6: global=True is system-wide HW BP (arms every thread of every
        # process + newborns). Driver caps at 2 concurrent. dangerous_ok
        # is only meaningful with global=True. `global` is a Python
        # keyword, hence the trailing underscore in the kwarg.
        kwargs = dict(
            kind=pb.BpAddRequest.HW if kind == "hw" else pb.BpAddRequest.SW,
            address=address, slot=slot, size=size, access=access,
            kernel_target=kernel_target, pid=pid, tid=tid,
        )
        # Only set when True — keeps compatibility with v5 agents that
        # would ignore unknown proto3 fields but let us stay explicit.
        if global_:
            kwargs["global"] = True
        if dangerous_ok:
            kwargs["dangerous_ok"] = True
        if via_debugger:
            kwargs["via_debugger"] = True
        msg = await self._call(self.breakpoints.Add, pb.BpAddRequest(**kwargs))
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"bp_id": msg.bp_id}

    async def bp_remove(self, bp_id: int) -> dict[str, Any]:
        # v0.9.4: the agent uses errno_code=2 as an in-band "already_removed"
        # breadcrumb (retry after MCP deadline, thread-exit auto-prune,
        # double-remove — all land here with ok=true and this hint). Surface
        # it so callers can tell "we cleared it just now" apart from "it was
        # already gone."
        st = await self._call(self.breakpoints.Remove, pb.BpRemoveRequest(bp_id=bp_id))
        d = status_dict(st)
        if d.get("ok") and d.get("errno_code") == 2:
            d["already_removed"] = True
        return d

    async def bp_list(self) -> list[dict[str, Any]]:
        msg = await self._call(self.breakpoints.List, pb.BpListRequest())
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return [proto_to_dict(b) for b in msg.breakpoints]

    async def bp_set_enabled(self, bp_id: int, enabled: bool) -> dict[str, Any]:
        st = await self._call(
            self.breakpoints.SetEnabled, pb.BpSetEnabledRequest(bp_id=bp_id, enabled=enabled)
        )
        return status_dict(st)
