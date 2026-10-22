"""Lifecycle mixin: spawn, dispatch and tear down the idalib-mcp supervisor."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from .errors import IdaBridgeError

log = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"


class IdaLifecycleMixin:
    """Owns supervisor spawn, MCP handshake, dispatcher and shutdown."""

    # ------------------------------------------------------------ lifecycle ----

    @staticmethod
    def _resolve_exe(exe: str) -> str | None:
        if Path(exe).exists():
            return exe
        found = shutil.which(exe)
        if found:
            return found
        if exe == "uv":

            candidates = [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "uv" / "uv.exe",
                Path(os.environ.get("USERPROFILE", "")) / ".local" / "bin" / "uv.exe",
            ]
            scripts = Path(os.environ.get("APPDATA", "")) / "Python"
            if scripts.is_dir():
                candidates.extend(scripts.glob("Python*/Scripts/uv.exe"))
            for c in candidates:
                if c.is_file():
                    return str(c)
        return None

    @staticmethod
    def _default_uv_command(command: list[str]) -> bool:
        """True when `command` is the stock ``uv run idalib-mcp [--stdio]``
        shape — i.e. the caller didn't point uv at a specific project."""
        if not command or "idalib-mcp" not in command:
            return False
        uv_flags = {"--project", "--directory", "--with", "--python",
                    "--index", "--no-default-groups"}
        return not any(p in uv_flags or p.startswith("--project=")
                       or p.startswith("--directory=") for p in command)

    @staticmethod
    def _repo_shim_command() -> list[str] | None:
        """Locate the repo-local idalib shim launch:

            <orchestrator>/.ida-mcp-venv/Scripts/python.exe
                <orchestrator>/idalib_stdio_shim.py

        ``uv run idalib-mcp`` can never work out of the box for suspex0 —
        the suspex0 pyproject doesn't provide that script — but the repo
        ships a pre-built venv next to the orchestrator that runs the
        stdio<->SSE shim directly (that's what configs/local.yaml wires).
        ``SUSPX_IDA_VENV`` points at an alternate venv root.
        """
        orchestrator_dir = Path(__file__).resolve().parents[3]
        shim = orchestrator_dir / "idalib_stdio_shim.py"
        if not shim.is_file():
            return None
        venv_roots: list[Path] = []
        env_venv = os.environ.get("SUSPX_IDA_VENV", "")
        if env_venv:
            venv_roots.append(Path(env_venv))
        venv_roots.append(orchestrator_dir / ".ida-mcp-venv")
        for root in venv_roots:
            for cand in (root / "Scripts" / "python.exe",
                         root / "bin" / "python",
                         root / "bin" / "python3"):
                if cand.is_file():
                    return [str(cand), str(shim)]
        return None

    def precheck(self) -> None:
        """Cheap, actionable prerequisite checks before spawning anything."""
        exe = self.cfg.command[0] if self.cfg.command else "uv"
        resolved = self._resolve_exe(exe)
        if resolved is None:
            # `uv` missing is only fatal when a repo shim isn't available —
            # the stock command gets substituted for it below.
            shim_cmd = None
            if exe in ("uv", "uvx") and self._default_uv_command(self.cfg.command):
                shim_cmd = self._repo_shim_command()
            if shim_cmd is not None:
                log.info("ida_bridge: uv not on PATH; substituting repo "
                         "shim command %s", shim_cmd)
                self.cfg.command = list(shim_cmd)
                return self.precheck()
            raise IdaBridgeError(
                f"ida_bridge: '{exe}' not found on PATH. Install uv (https://docs.astral.sh/uv/) "
                "or fix ida.command in the config."
            )
        if resolved != exe:
            self.cfg.command[0] = resolved
        if self.cfg.ida_path:
            ida = Path(self.cfg.ida_path)
            if not ida.exists():
                raise IdaBridgeError(
                    f"ida_bridge: ida.path '{self.cfg.ida_path}' does not exist on this host"
                )
            activate = ida / "idalib" / "python" / "py-activate-idalib.py"
            if not activate.exists():
                raise IdaBridgeError(
                    f"ida_bridge: idalib not found under '{self.cfg.ida_path}\\idalib'. "
                    "IDA Pro 8.3+/9 with the idalib component is required; activate it once with "
                    f"'{activate}' (run with the IDA python)."
                )
        if Path(resolved).name.lower() in ("uv.exe", "uvx.exe", "uv", "uvx"):
            if len(self.cfg.command) < 2 or not any(
                "idalib-mcp" in part for part in self.cfg.command[1:]
            ):
                raise IdaBridgeError(
                    "ida_bridge: expected the ida-pro-mcp 'idalib-mcp' supervisor in ida.command"
                )
            # The default `uv run idalib-mcp` fails on a bare suspex0
            # checkout — suspex0's own pyproject doesn't ship that script.
            # When the repo-local .ida-mcp-venv + idalib_stdio_shim.py are
            # present, run them directly instead (same command
            # configs/local.yaml uses).
            if self._default_uv_command(self.cfg.command):
                shim_cmd = self._repo_shim_command()
                if shim_cmd is not None:
                    log.info("ida_bridge: substituting repo shim command "
                             "for 'uv run idalib-mcp': %s", shim_cmd)
                    self.cfg.command = list(shim_cmd)

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
            log.info("spawning idalib-mcp supervisor: %s", self.cfg.command)
            try:
                # limit=32 MiB: the default asyncio.StreamReader cap is
                # 64 KiB per line, and a single decompile_function of a
                # 100 KB function serialises to one JSON-RPC line that
                # exceeds it -> "Separator is found, but chunk is longer
                # than limit". 32 MiB comfortably covers any reasonable
                # single tool result even before the shim chunks big
                # payloads via the JOBS cache.
                # v0.14: hand the shim the same spill directory the
                # orchestrator picks so its .listing artifacts land where
                # `file_manage(action='read_artifact', sha256=...)` will
                # look for them. Preserves any pre-existing env the
                # process inherited (PATH, symbol server, etc.).
                import os as _os
                shim_env = dict(_os.environ)
                shim_env["SUSPX_MCP_SPILL_DIR"] = str(
                    (self.artifacts_dir / "spill").resolve()
                )
                self._proc = await asyncio.create_subprocess_exec(
                    *self.cfg.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(self.artifacts_dir),
                    env=shim_env,
                    limit=32 * 1024 * 1024,
                )
            except OSError as exc:
                raise IdaBridgeError(f"ida_bridge: failed to spawn supervisor: {exc}") from exc
            try:
                await self._initialize()
            except IdaBridgeError:
                await self.stop()
                raise
            # adopt any databases still held by persistent workers from a
            # previous supervisor run
            await self.refresh_sessions()
            # v0.17 C1-4: load the on-disk manifest so a session-scoped
            # call against a pre-restart name lazy-reopens instead of
            # raising unknown-name. Safe to call every ensure_started
            # because the manifest is a name->path lookup — no shim
            # traffic — and _manifest_sessions is idempotent.
            self.restore_from_manifest()

    async def stop(self) -> None:
        # Cancel in-flight open tasks and drain their exceptions BEFORE
        # killing the supervisor. Otherwise their `_call`s would see stdout
        # close and raise `supervisor exited before responding`; with no
        # one awaiting them, that surfaces as noisy `Task exception was
        # never retrieved` warnings and a later `open_status(name)` would
        # flip from a truthful pending/ready to a misleading error.
        pending = [t for (t, _) in self._pending_opens.values()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._pending_opens.clear()
        # Cancel dispatcher next so it stops trying to route responses
        # into futures that will never be awaited.
        if self._dispatcher_task is not None:
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._dispatcher_task = None
        # Clear any remaining response futures so they don't keep waiters
        # hanging past teardown.
        self._fail_pending(IdaBridgeError(
            "ida_bridge: supervisor stopped before response arrived"))
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
        """Own stdout.readline() and route responses to per-rid futures.

        Every `_call` registers a future in `_pending_responses[rid]` and
        awaits it; this single coroutine owns the actual reader. That way
        concurrent callers (e.g. a shielded idb_open still running while a
        later ida_manage(list) fires) never both hit `readline()` --
        asyncio's StreamReader explicitly forbids that and would raise
        `RuntimeError('readline() called while another coroutine is
        already waiting for incoming data')`.
        """
        assert self._proc is not None and self._proc.stdout is not None
        try:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    stderr_tail = await self._stderr_tail()
                    exc = IdaBridgeError(
                        "ida_bridge: idalib-mcp supervisor exited before responding. "
                        f"stderr: {stderr_tail}"
                    )
                    self._fail_pending(exc)
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("ida_bridge: non-JSON stdout line: %r", line[:200])
                    continue
                rid = msg.get("id")
                if rid is None:
                    # notifications don't carry an id; nothing to route to
                    continue
                fut = self._pending_responses.pop(rid, None)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
        except asyncio.CancelledError:
            self._fail_pending(IdaBridgeError(
                "ida_bridge: dispatcher cancelled during shutdown"))
            raise
        except Exception as exc:  # noqa: BLE001 - propagate to all waiters
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
            data = await asyncio.wait_for(self._proc.stderr.read(limit), timeout=2)
            return data.decode("utf-8", "replace").strip()
        except asyncio.TimeoutError:
            return ""

    @staticmethod
    def _humanize_startup_failure(stderr: str) -> str:
        s = stderr.lower()
        if "license" in s or "licens" in s:
            return (
                "ida_bridge: IDA licensing failure. idalib requires a licensed IDA Pro "
                "8.3+/9 install; ensure ida.bin/idat licensing is valid on this host."
            )
        if "activate" in s or "idalib" in s and "not" in s:
            return (
                "ida_bridge: idalib not activated. Run "
                '"<IDA install>\\idalib\\python\\py-activate-idalib.py" once, then retry.'
            )
        if "no module named" in s or "uv" in s:
            return (
                "ida_bridge: idalib-mcp unavailable via uv. Point ida.command at the "
                "repo-local shim — <orchestrator>/.ida-mcp-venv/Scripts/python.exe "
                "idalib_stdio_shim.py — or install ida-pro-mcp so "
                "`uv run idalib-mcp --help` works."
            )
        return f"ida_bridge: supervisor startup failed. stderr: {stderr}"

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
        except IdaBridgeError as exc:
            stderr = await self._stderr_tail()
            raise IdaBridgeError(self._humanize_startup_failure(stderr or str(exc))) from exc
        # notifications/init response both fine; then send initialized notification
        self._proc.stdin.write(
            (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode()
        )
        await self._proc.stdin.drain()
        # cache tool inventory
        try:
            result = await self._call("tools/list", {}, timeout=30)
            for tool in result.get("tools", []):
                self._tools[tool["name"]] = tool
        except IdaBridgeError as exc:
            raise IdaBridgeError(self._humanize_startup_failure(str(exc))) from exc

    async def _call(self, method: str, params: dict[str, Any], timeout: float = 120) -> Any:
        if self._proc is None or self._proc.returncode is not None:
            raise IdaBridgeError("ida_bridge: supervisor not running")
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
                raise IdaBridgeError(f"ida_bridge: timeout waiting for {method}") from None
        finally:
            # If wait_for timed out or drain failed, unwire the future so
            # the dispatcher doesn't try to fulfill a stale entry.
            self._pending_responses.pop(rid, None)
        if "error" in msg:
            err = msg["error"]
            raise IdaBridgeError(f"ida_bridge: {method} error: {json.dumps(err)[:500]}")
        return msg.get("result")
