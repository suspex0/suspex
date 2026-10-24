"""Exec-service methods (shells, run, detached) split off from AgentClient."""

from __future__ import annotations

from typing import Any

from ..generated import suspex_pb2 as pb
from .wire import status_dict


class ExecMixin:
    # ------------------------------------------------------------------ Exec ----

    async def run_exe(self, exe: str, args: list[str] | None = None, workdir: str = "",
                      timeout_ms: int = 30000) -> dict[str, Any]:
        # v14: wire deadline must outlive the agent-side timeout — the old
        # always-10s deadline abandoned the call while the agent kept
        # burning a poller for the full 30 s (the exec-wedge amplifier).
        msg = await self._call(
            self.exec_.RunExe,
            pb.RunExeRequest(exe=exe, args=args or [], working_dir=workdir, timeout_ms=timeout_ms),
            timeout=timeout_ms / 1000.0 + 10,
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {
            "exit_code": msg.exit_code,
            "stdout": msg.stdout_data.decode("utf-8", "replace"),
            "stderr": msg.stderr_data.decode("utf-8", "replace"),
            "timed_out": bool(msg.timed_out),
        }

    async def run_shell(self, command: str, shell: str = "cmd", workdir: str = "",
                        timeout_ms: int = 30000) -> dict[str, Any]:
        # v0.31 Phase 2.3: PowerShell goes through -EncodedCommand on new
        # agents to sidestep the double-parse mangling (quotes, backticks,
        # newlines, non-ASCII). Legacy agents without the field continue
        # on the `command=` string path.
        req_kwargs = {
            "shell": pb.POWERSHELL if shell == "powershell" else pb.CMD,
            "command": command,
            "working_dir": workdir,
            "timeout_ms": timeout_ms,
        }
        if shell == "powershell":
            try:
                import base64 as _b64
                enc = _b64.b64encode(
                    command.encode("utf-16-le")).decode("ascii")
                # Only pass encoded_command when the proto has the field —
                # a pre-v0.31 generated pb2 lacks it; the request builder
                # will reject the unknown kwarg.
                probe = pb.RunShellRequest()
                if hasattr(probe, "encoded_command"):
                    req_kwargs["encoded_command"] = enc
                    # Keep `command` as a human-readable breadcrumb for
                    # the agent's op log; the agent prefers encoded.
            except Exception:  # noqa: BLE001 — fall back to plain command
                pass
        msg = await self._call(
            self.exec_.RunShell,
            pb.RunShellRequest(**req_kwargs),
            timeout=timeout_ms / 1000.0 + 10,
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"exit_code": msg.exit_code, "output": msg.output.decode("utf-8", "replace")}

    async def start_shell(self, shell: str = "cmd", workdir: str = "") -> dict[str, Any]:
        msg = await self._call(
            self.exec_.StartShell,
            pb.StartShellRequest(shell=pb.POWERSHELL if shell == "powershell" else pb.CMD,
                                 working_dir=workdir),
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"session_id": msg.session_id}

    async def shell_write(self, session_id: int, data: str) -> dict[str, Any]:
        st = await self._call(
            self.exec_.ConsoleWrite, pb.WriteConsoleRequest(session_id=session_id, input=data.encode())
        )
        return status_dict(st)

    async def shell_read(self, session_id: int, timeout_ms: int = 1000) -> dict[str, Any]:
        # v14: deadline = requested long-poll + slack (was the default 10 s,
        # which truncated every read_console that asked for more).
        msg = await self._call(
            self.exec_.ConsoleRead,
            pb.ReadConsoleRequest(session_id=session_id, timeout_ms=timeout_ms),
            timeout=timeout_ms / 1000.0 + 10,
        )
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"data": msg.data.decode("utf-8", "replace"), "eof": msg.eof}

    async def shell_stop(self, session_id: int) -> dict[str, Any]:
        return status_dict(await self._call(self.exec_.StopShell, pb.ShellSessionRequest(session_id=session_id)))

    async def list_shells(self) -> dict[str, Any]:
        """v14: live shell session ids — the recovery path when a caller's
        session_id got mangled in transit or the shell table drifted."""
        if not hasattr(pb, "ListShellsRequest") or not hasattr(self.exec_, "ListShells"):
            return {"ok": False,
                    "error": "list_shells: agent < v14 (Exec.ListShells missing)"}
        msg = await self._call(self.exec_.ListShells, pb.ListShellsRequest())
        if not msg.status.ok:
            return {"ok": False, "error": msg.status.error}
        return {"ok": True, "session_ids": list(msg.session_ids)}

    async def kill_process(self, pid: int) -> dict[str, Any]:
        return status_dict(await self._call(self.exec_.KillProcess, pb.KillProcessRequest(pid=pid)))

    async def suspend_process(self, pid: int) -> dict[str, Any]:
        """Quiesce a target (NtSuspendProcess). Pair with resume_process."""
        return status_dict(await self._call(self.exec_.Suspend, pb.PidRequest(pid=pid)))

    async def resume_process(self, pid: int) -> dict[str, Any]:
        return status_dict(await self._call(self.exec_.Resume, pb.PidRequest(pid=pid)))

    async def call_function(self, *, pid: int = 0, target_va: int,
                            args: list[int] | None = None, space: str = "user",
                            timeout_ms: int = 0, flags: int = 0) -> dict[str, Any]:
        # v15: synchronous in-context function call. Gated orchestrator-side
        # by security.allow_function_call (the tool layer refuses first).
        msg = await self._call(
            self.exec_.CallFunction,
            pb.CallFunctionRequest(
                pid=pid, target_va=int(target_va), args=[int(a) for a in (args or [])],
                space=pb.CALL_KERNEL if space == "kernel" else pb.CALL_USER,
                timeout_ms=int(timeout_ms), flags=int(flags)),
            timeout=(timeout_ms or 30000) / 1000.0 + 10,   # v14 wire-deadline rule
        )
        return {"ok": msg.status.ok, "error": msg.status.error,
                "return_value": int(msg.return_value),
                "last_error": int(msg.last_error),
                "exit_code": int(msg.exit_code),
                "timed_out": bool(msg.timed_out),
                "exception": bool(msg.exception),
                "exception_code": int(msg.exception_code),
                "thread_tid": int(msg.thread_tid),
                "stub_va": int(msg.stub_va)}

    # --------------------------------------- v7: detached execution family --

    async def run_detached(self, cmdline: str, workdir: str = "",
                           stdout_path: str = "", stderr_path: str = "",
                           hidden_window: bool = True) -> dict[str, Any]:
        if not hasattr(self.exec_, "RunDetached"):
            raise RuntimeError("run_detached: agent < v7 (Exec.RunDetached missing)")
        req = pb.RunDetachedRequest(cmdline=cmdline, working_dir=workdir,
                                     stdout_path=stdout_path,
                                     stderr_path=stderr_path,
                                     hidden_window=hidden_window)
        msg = await self._call(self.exec_.RunDetached, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"ok": True, "handle_id": msg.handle_id, "pid": msg.pid,
                "stdout_path": msg.stdout_path, "stderr_path": msg.stderr_path,
                "started_ts": msg.started_ts,
                # v14: the detached log files are opened share R/W/D, so a
                # LogFollow subscribes fine — most callers never realised
                # polling wasn't the only option. Surfaced for discovery;
                # exec_manage(action='detached_follow') wraps it.
                "follow_hint": {
                    "action": "follow_start",
                    "remote_path": msg.stdout_path,
                    "note": ("detached logs are share-opened; follow_start "
                             "subscribes for live chunks. Child-side CRT "
                             "buffering may delay writes — the agent can't "
                             "flush another process's stdio."),
                }}

    async def detached_status(self, handle_id: str) -> dict[str, Any]:
        req = pb.DetachedHandleRequest(handle_id=handle_id)
        msg = await self._call(self.exec_.DetachedStatus, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"ok": True, "running": msg.running, "exit_code": msg.exit_code,
                "stdout_size": msg.stdout_size, "stderr_size": msg.stderr_size,
                "exited_ts": msg.exited_ts, "pid": msg.pid,
                "stdout_path": msg.stdout_path, "stderr_path": msg.stderr_path}

    async def detached_tail(self, handle_id: str, bytes_wanted: int = 65536,
                             stderr_too: bool = True) -> dict[str, Any]:
        req = pb.DetachedTailRequest(handle_id=handle_id, bytes=bytes_wanted,
                                      stderr_too=stderr_too)
        msg = await self._call(self.exec_.DetachedTail, req)
        if not msg.status.ok:
            raise RuntimeError(msg.status.error)
        return {"ok": True,
                "stdout_tail": msg.stdout_tail.decode("utf-8", "replace"),
                "stderr_tail": msg.stderr_tail.decode("utf-8", "replace"),
                "stdout_total": msg.stdout_total,
                "stderr_total": msg.stderr_total}

    async def detached_kill(self, handle_id: str) -> dict[str, Any]:
        req = pb.DetachedHandleRequest(handle_id=handle_id)
        return status_dict(await self._call(self.exec_.DetachedKill, req))
