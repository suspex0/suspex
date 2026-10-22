"""Async gRPC client for the target agent. Unary calls + stream pumps feeding
an in-process asyncio event bus."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

import grpc

from ..caller import current_client_id
from ..generated import suspex_pb2 as pb
from ..generated import suspex_pb2_grpc as pbg
from .debug import DebugMixin
from .events import EventBus
from .exec import ExecMixin
from .files import FilesMixin
from .host import HostMixin
from .kernel import KernelMixin
from .mem import MemMixin
from .device import DeviceMixin
from .wire import _summarize_req


class AgentClient(MemMixin, DebugMixin, FilesMixin, ExecMixin, KernelMixin, HostMixin, DeviceMixin):
    _RING_CAP = 64

    def __init__(self, host: str, port: int, token: str, timeout_ms: int = 10000,
                 max_inflight: int = 16) -> None:
        # asyncio.Semaphore(0) has zero permits, so every _call would
        # block on `async with self._sem` forever with no diagnosable
        # error. Refuse the misconfig up front rather than shipping a
        # client whose every gRPC operation silently hangs.
        if max_inflight < 1:
            raise ValueError(
                f"max_inflight must be >= 1 (got {max_inflight}); use a "
                "positive cap to bound in-flight gRPC calls"
            )
        self._target = f"{host}:{port}"
        self._token = token
        self._timeout = timeout_ms / 1000.0
        self._channel: grpc.aio.Channel | None = None
        self.agent = None
        self.memory = None
        self.debug = None
        self.breakpoints = None
        self.files = None
        self.exec_ = None
        self.bus = EventBus()
        # Ring buffer of the last N gRPC calls we sent to the agent.
        # Records what was in flight when the transport dies or the agent
        # SCM-restart budget is exhausted, so the "did the IOCTL complete"
        # question has an answer even if the agent never came back.
        self._recent_ops: list[dict[str, Any]] = []
        # Per-view in-flight concurrency cap. Bulk fan-out (e.g. multi-region
        # scans, VAD-then-read loops) can stampede the agent's single IOCTL
        # thread if left unbounded; the semaphore keeps at most
        # `max_inflight` gRPC calls outstanding at any moment, while the
        # counter is exposed in `recent_ops` so operators can see contention.
        self._max_inflight = max_inflight
        self._sem = asyncio.Semaphore(max_inflight)
        self._inflight_count: int = 0
        # Phase 0.2: last-seen bookkeeping so target_manage(action="targets")
        # can render {endpoint, state, last_seen_ts, last_op_ts} per view for
        # deterministic reconnect after a wedge. last_seen_ts is any successful
        # call; last_op_ts is the last non-Status call.
        self._last_seen_ts: float = 0.0
        self._last_op_ts: float = 0.0
        self._connected_ts: float = 0.0

    @property
    def endpoint(self) -> str:
        return self._target

    @property
    def host(self) -> str:
        return self._target.rsplit(":", 1)[0]

    @property
    def port(self) -> int:
        return int(self._target.rsplit(":", 1)[1])

    @property
    def token(self) -> str:
        return self._token

    @property
    def timeout_ms(self) -> int:
        return int(self._timeout * 1000)

    @property
    def last_seen_ts(self) -> float:
        return self._last_seen_ts

    @property
    def last_op_ts(self) -> float:
        return self._last_op_ts

    @property
    def connected_ts(self) -> float:
        return self._connected_ts

    async def connect(self) -> None:
        # v14: channel keepalive — after a target reboot the TCP channel
        # used to sit half-dead indefinitely, making a stale view look
        # alive until the next call timed out. Pings let the channel's
        # connectivity state actually transition.
        self._channel = grpc.aio.insecure_channel(
            self._target,
            options=[
                ("grpc.keepalive_time_ms", 20000),
                ("grpc.keepalive_timeout_ms", 10000),
                ("grpc.keepalive_permit_without_calls", 1),
                ("grpc.http2.max_pings_without_data", 0),
            ])
        await self._channel.channel_ready()
        self._connected_ts = time.time()
        self.agent = pbg.AgentStub(self._channel)
        self.memory = pbg.MemoryStub(self._channel)
        self.debug = pbg.DebugStub(self._channel)
        self.breakpoints = pbg.BreakpointsStub(self._channel)
        self.files = pbg.FilesStub(self._channel)
        self.exec_ = pbg.ExecStub(self._channel)
        # v4 additions — registry service always registered, physical-ranges /
        # pool-scan live on Memory. Skip gracefully if the target agent
        # predates v4 (RegistryStub / PhysicalRanges / PoolScan will just
        # return UNIMPLEMENTED on call).
        self.registry = pbg.RegistryStub(self._channel) if hasattr(pbg, "RegistryStub") else None
        # v8: driver-backed wedge-detector. Absent on pre-v8 agents; the
        # watchdog_manage MCP tool surfaces "agent < v8" cleanly in that case.
        self.watchdog = (pbg.WatchdogStub(self._channel)
                         if hasattr(pbg, "WatchdogStub") else None)
        # v11: Device.Ioctl (usermode actuator) + Telemetry (ETW query-only).
        # Absent on pre-v11 agents; the MCP tools surface "agent < v11".
        self.device = (pbg.DeviceStub(self._channel)
                       if hasattr(pbg, "DeviceStub") else None)
        self.telemetry = (pbg.TelemetryStub(self._channel)
                          if hasattr(pbg, "TelemetryStub") else None)
        # v11: Events (driver notify ring — the agent's "ears"). Absent on
        # pre-v11 agents; event_manage surfaces "agent < v11" in that case.
        self.events = (pbg.EventsStub(self._channel)
                       if hasattr(pbg, "EventsStub") else None)

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = None

    def _meta(self) -> list[tuple[str, str]]:
        return [("authorization", f"Bearer {self._token}")] if self._token else []

    async def _call(self, fn: Callable[..., Awaitable[Any]], request: Any,
                    timeout: float | None = None) -> Any:
        """Timeout override: per-call `timeout` (seconds) beats the client default.
        None -> use the client default; 0 -> no timeout (bulk ops on slow paths).

        Also records the attempt in a small ring so post-crash forensics
        (`recent_ops()`) can show what was in flight when the agent died.
        """
        import time
        eff = self._timeout if timeout is None else (timeout if timeout > 0 else None)
        method = getattr(fn, "_method", "") or getattr(fn, "__qualname__", str(fn))
        if isinstance(method, bytes):
            method = method.decode("utf-8", "replace")
        entry: dict[str, Any] = {
            "t_start": time.time(), "method": method, "timeout_s": eff,
            "req_summary": _summarize_req(request), "status": "pending",
            "inflight_at_start": self._inflight_count,
            "max_inflight": self._max_inflight,
            "client_id": current_client_id(),
        }
        self._recent_ops.append(entry)
        if len(self._recent_ops) > self._RING_CAP:
            del self._recent_ops[: len(self._recent_ops) - self._RING_CAP]
        async with self._sem:
            self._inflight_count += 1
            try:
                result = await fn(request, metadata=self._meta(), timeout=eff)
            except Exception as exc:
                entry["status"] = "error"
                entry["error"] = f"{type(exc).__name__}: {exc}"
                entry["t_end"] = time.time()
                entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)
                raise
            finally:
                self._inflight_count -= 1
            # v0.16: guard once for the (rare) case where the gRPC awaitable
            # resolves to None — a stream close mid-call, or a stub that was
            # torn down between attach and dispatch. Downstream callers all
            # dereference `.status.ok` on the return value; without this
            # guard they'd surface AttributeError('NoneType' object has no
            # attribute 'status') with no hint about which RPC actually
            # failed. Raise a labelled RuntimeError instead so recent_ops
            # and the caller-facing error tell the same story.
            if result is None:
                entry["status"] = "error"
                entry["error"] = f"agent RPC {method} returned no message"
                entry["t_end"] = time.time()
                entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)
                raise RuntimeError(
                    f"agent RPC {method} returned no message; likely a "
                    "stream close mid-call — retry, or check "
                    "target_manage(action='recent_ops') for what was in "
                    "flight")
            entry["status"] = "ok"
            entry["t_end"] = time.time()
            entry["latency_s"] = round(entry["t_end"] - entry["t_start"], 3)
            # Phase 0.2: stamp last-seen (any success) and last-op (non-Status).
            self._last_seen_ts = entry["t_end"]
            if "Status" not in method:
                self._last_op_ts = entry["t_end"]
            return result

    def recent_ops(self, limit: int = 32) -> list[dict[str, Any]]:
        """Last-N (default 32, cap 64) gRPC attempts. Use after an agent
        crash to see what was in flight and its latency at wedge time."""
        return list(self._recent_ops[-limit:])
