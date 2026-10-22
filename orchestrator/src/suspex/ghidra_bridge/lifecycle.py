"""Lifecycle mixin: spawn, dispatch and tear down the ghidra shim."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .errors import GhidraBridgeError

log = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"


class GhidraLifecycleMixin:
    """Owns supervisor spawn, MCP handshake, dispatcher and shutdown."""

    # ------------------------------------------------------------ lifecycle ----

    @staticmethod
    def _resolve_exe(exe: str) -> str | None:
        if Path(exe).exists():
            return exe
        found = shutil.which(exe)
        if found:
            return found
        return None

    @staticmethod
    def _orchestrator_dir() -> Path:
        return Path(__file__).resolve().parents[3]

    def _repo_shim_command(self) -> list[str] | None:
        """Locate the repo-local ghidra shim launch:

            <python-with-mcp> <orchestrator>/ghidra_stdio_shim.py

        Interpreter resolution order:
          1. ``SUSPX_GHIDRA_SHIM_PYTHON`` env (explicit shim override —
             the shim itself needs only ``mcp``, not pyghidra; the JVM
             deps live in the BACKEND interpreter).
          2. ``cfg.backend_python`` — if the caller pointed us at a
             pyghidra-ready interpreter it certainly has mcp too.
          3. ``<orchestrator>/.ghidra-venv`` convention
             (``SUSPX_GHIDRA_VENV`` may point elsewhere).
          4. ``sys.executable`` — the orchestrator's own env; works when
             ``mcp`` client/server modules are importable there.
        """
        orchestrator_dir = self._orchestrator_dir()
        shim = orchestrator_dir / "ghidra_stdio_shim.py"
        if not shim.is_file():
            return None
        shim_py = os.environ.get("SUSPX_GHIDRA_SHIM_PYTHON", "")
        if shim_py and Path(shim_py).is_file():
            return [shim_py, str(shim)]
        if self.cfg.backend_python and Path(self.cfg.backend_python).is_file():
            return [self.cfg.backend_python, str(shim)]
        venv_roots: list[Path] = []
        env_venv = os.environ.get("SUSPX_GHIDRA_VENV", "")
        if env_venv:
            venv_roots.append(Path(env_venv))
        venv_roots.append(orchestrator_dir / ".ghidra-venv")
        for root in venv_roots:
            for cand in (root / "Scripts" / "python.exe",
                         root / "bin" / "python",
                         root / "bin" / "python3"):
                if cand.is_file():
                    return [str(cand), str(shim)]
        return [sys.executable, str(shim)]

    def precheck(self) -> None:
        """Cheap, actionable prerequisite checks before spawning anything.

        The shim itself needs only ``mcp`` — Ghidra/JDK/pyghidra are the
        BACKEND child's problem, and missing ones surface as an
        actionable ``ghidra_open`` error naming exactly which env var to
        set. What IS fatal here: no runnable shim command at all.
        """
        if self.cfg.command:
            exe = self.cfg.command[0]
            resolved = self._resolve_exe(exe)
            if resolved is None:
                raise GhidraBridgeError(
                    f"ghidra_bridge: '{exe}' not found on PATH — fix "
                    "ghidra.command in the config or clear it to use the "
                    "repo shim."
                )
            if resolved != exe:
                self.cfg.command[0] = resolved
            return
        shim_cmd = self._repo_shim_command()
        if shim_cmd is None:
            raise GhidraBridgeError(
                "ghidra_bridge: ghidra_stdio_shim.py missing from "
                f"{self._orchestrator_dir()} — the repo is incomplete; "
                "set ghidra.command to a working supervisor command."
            )
        log.info("ghidra_bridge: shim command: %s", shim_cmd)
        self.cfg.command = list(shim_cmd)
        # Soft precheck on the Ghidra install — not fatal (env may carry
        # GHIDRA_INSTALL_DIR globally) but warn early so the operator
        # doesn't discover it at first ghidra_open.
        if self.cfg.ghidra_dir and not Path(self.cfg.ghidra_dir).is_dir():
            raise GhidraBridgeError(
                f"ghidra_bridge: ghidra.ghidra_dir "
                f"{self.cfg.ghidra_dir!r} does not exist — point it at a "
                "real Ghidra install or leave empty and export "
                "GHIDRA_INSTALL_DIR."
            )
        if not (self.cfg.ghidra_dir
                or os.environ.get("GHIDRA_INSTALL_DIR")):
            log.warning(
                "ghidra_bridge: neither ghidra.ghidra_dir nor "
                "GHIDRA_INSTALL_DIR is set — ghidra_open will fail until "
                "a Ghidra install is configured")

    def _shim_env(self) -> dict:
        """Child env for the shim proc: inherit everything, then stamp the
        Ghidra knobs the shim forwards to the backend child."""
        env = dict(os.environ)
        env["SUSPX_MCP_SPILL_DIR"] = str(
            (self.artifacts_dir / "spill").resolve())
        env["SUSPX_ARTIFACTS_DIR"] = str(self.artifacts_dir.resolve())
        if self.cfg.ghidra_dir:
            env["SUSPX_GHIDRA_DIR"] = self.cfg.ghidra_dir
        if self.cfg.java_home:
            env["SUSPX_GHIDRA_JAVA_HOME"] = self.cfg.java_home
        project_dir = (self.cfg.project_dir
                       or str(self.artifacts_dir / "ghidra_project"))
        env["SUSPX_GHIDRA_PROJECT_DIR"] = project_dir
        env["SUSPX_GHIDRA_PROJECT_NAME"] = self.cfg.project_name or "suspex"
        if self.cfg.heap_mb:
            env["SUSPX_GHIDRA_HEAP_MB"] = str(self.cfg.heap_mb)
        if self.cfg.backend_python:
            env["SUSPX_GHIDRA_BACKEND_PYTHON"] = self.cfg.backend_python
        return env

    async def ensure_started(self) -> None:
        # lock is NOT re-entrant: never acquire it when the supervisor is
        # already up (nested ensure_started calls from call paths would
        # otherwise self-deadlock)
        if self._proc is not None and self._proc.returncode is None:
            return
        async with self._lock:
            if self._proc is not None and self._proc.returncode is None:
                return
            self.precheck()
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            log.info("spawning ghidra shim: %s", self.cfg.command)
            try:
                # limit=32 MiB: same reason as the IDA bridge — a single
                # decompile serialises to one JSON-RPC line that exceeds
                # the default 64 KiB asyncio stream cap.
                self._proc = await asyncio.create_subprocess_exec(
                    *self.cfg.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self.artifacts_dir),
                    env=self._shim_env(),
                    limit=32 * 1024 * 1024,
                )
            except OSError as exc:
                raise GhidraBridgeError(
                    f"ghidra_bridge: failed to spawn supervisor: {exc}") from exc
            try:
                await self._initialize()
            except GhidraBridgeError:
                await self.stop()
                raise
            # adopt any project programs still held by a persistent
            # backend from a previous supervisor run
            await self.refresh_sessions()
            # load the on-disk manifest so a session-scoped call against
            # a pre-restart name lazy-reopens instead of raising
            # unknown-name.
            self.restore_from_manifest()

    async def stop(self) -> None:
        # Cancel in-flight open tasks and drain their exceptions BEFORE
        # killing the supervisor (same reasoning as the IDA bridge).
        pending = [t for (t, _) in self._pending_opens.values()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._pending_opens.clear()
        if self._dispatcher_task is not None:
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._dispatcher_task = None
        self._fail_pending(GhidraBridgeError(
            "ghidra_bridge: supervisor stopped before response arrived"))
        if self._proc is not None and self._proc.returncode is None:
            try:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
            except ProcessLookupError:
                pass
        self._proc = None

    # ------------------------------------------------------------- MCP wire ----

    async def _dispatcher(self) -> None:
        """Own stdout.readline() and route responses to per-rid futures."""
        assert self._proc is not None and self._proc.stdout is not None
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    stderr_tail = await self._stderr_tail()
                    exc = GhidraBridgeError(
                        "ghidra_bridge: ghidra shim exited before "
                        f"responding. stderr: {stderr_tail}"
                    )
                    self._fail_pending(exc)
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("ghidra_bridge: non-JSON stdout line: %r",
                              line[:200])
                    continue
                rid = msg.get("id")
                if rid is None:
                    continue
                fut = self._pending_responses.pop(rid, None)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
        except asyncio.CancelledError:
            self._fail_pending(GhidraBridgeError(
                "ghidra_bridge: dispatcher cancelled during shutdown"))
            raise
        except Exception as exc:  # noqa: BLE001 - propagate to waiters
            self._fail_pending(exc)
            raise

    def _fail_pending(self, exc: BaseException) -> None:
        for fut in list(self._pending_responses.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending_responses.clear()

    async def _stderr_tail(self, limit: int = 2000) -> str:
        if self._proc is None or self._proc.stderr is None:
            return ""
        try:
            data = await asyncio.wait_for(self._proc.stderr.read(limit),
                                          timeout=2)
            return data.decode("utf-8", "replace").strip()
        except asyncio.TimeoutError:
            return ""

    @staticmethod
    def _humanize_startup_failure(stderr: str) -> str:
        s = stderr.lower()
        if "no module named" in s and "mcp" in s:
            return (
                "ghidra_bridge: the shim interpreter lacks the 'mcp' "
                "package. Point ghidra.backend_python (or "
                "SUSPX_GHIDRA_SHIM_PYTHON / .ghidra-venv) at an env with "
                "mcp installed, or `uv pip install mcp` into the "
                "orchestrator env."
            )
        if "ghidra_install_dir" in s or "ghidra_dir" in s:
            return (
                "ghidra_bridge: Ghidra install not found. Set "
                "ghidra.ghidra_dir in the config or export "
                "GHIDRA_INSTALL_DIR; the backend also needs a JDK "
                "(ghidra.java_home or JAVA_HOME)."
            )
        if "java" in s or "jvm" in s or "jpype" in s:
            return (
                "ghidra_bridge: JVM/JPype failure — install a JDK and set "
                "ghidra.java_home (or JAVA_HOME); pyghidra + jpype1 must "
                "be importable in the backend interpreter "
                "(ghidra.backend_python)."
            )
        if "no module named" in s or "pyghidra" in s:
            return (
                "ghidra_bridge: pyghidra unavailable in the backend "
                "interpreter. `uv sync --extra ghidra` (or `uv pip "
                "install pyghidra jpype1`) into the env pointed at by "
                "ghidra.backend_python / .ghidra-venv."
            )
        return f"ghidra_bridge: supervisor startup failed. stderr: {stderr}"

    async def _initialize(self) -> None:
        assert self._proc is not None
        # Start the dispatcher BEFORE the first request: `_call` waits on
        # `_pending_responses[rid]`, which the dispatcher populates.
        self._dispatcher_task = asyncio.create_task(self._dispatcher())
        try:
            await self._call("initialize", {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "suspex0-orchestrator", "version": "0.1.0"},
            }, timeout=30)
        except GhidraBridgeError as exc:
            stderr = await self._stderr_tail()
            raise GhidraBridgeError(
                self._humanize_startup_failure(stderr or str(exc))) from exc
        self._proc.stdin.write(
            (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode()
        )
        await self._proc.stdin.drain()
        # cache tool inventory
        try:
            result = await self._call("tools/list", {}, timeout=30)
            for tool in result.get("tools", []):
                self._tools[tool["name"]] = tool
        except GhidraBridgeError as exc:
            raise GhidraBridgeError(
                self._humanize_startup_failure(str(exc))) from exc

    async def _call(self, method: str, params: dict[str, Any], timeout: float = 120) -> Any:
        if self._proc is None or self._proc.returncode is not None:
            raise GhidraBridgeError("ghidra_bridge: supervisor not running")
        rid = self._next_id
        self._next_id += 1
        loop = asyncio.get_event_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending_responses[rid] = fut
        req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        try:
            self._proc.stdin.write((json.dumps(req) + "\n").encode())
            await self._proc.stdin.drain()
            try:
                msg = await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                raise GhidraBridgeError(
                    f"ghidra_bridge: timeout waiting for {method}") from None
        finally:
            self._pending_responses.pop(rid, None)
        if "error" in msg:
            err = msg["error"]
            raise GhidraBridgeError(
                f"ghidra_bridge: {method} error: {json.dumps(err)[:500]}")
        return msg.get("result")
