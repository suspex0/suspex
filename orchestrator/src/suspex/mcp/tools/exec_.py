"""Exec tool registration for the suspex0 MCP server.

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


def _call_status(r: dict[str, Any]) -> str:
    """exec_manage(action='call') status field — timeout | exception |
    completed | incomplete."""
    if r.get("timed_out"):
        return "timeout"
    if r.get("exception"):
        return "exception"
    if r.get("ok"):
        return "completed"
    return "incomplete"


async def _resolve_call_target(address: Any, space: str, client, pid: int) -> int:
    """Resolve the exec_manage call target: plain int/'0x…' → _addr;
    'module+offset' → module-list lookup; 'module!export' → export walk."""
    if isinstance(address, str):
        s = address.strip()
        if "!" in s and not s.lower().startswith("0x"):
            mod, _, exp = s.partition("!")
            mod = mod.strip()
            exp = exp.strip()
            if not mod or not exp:
                raise ValueError(f"call: {address!r} not valid module!export notation")
            exports = await client.mem_exports(pid, mod, kernel=(space == "kernel"))
            want = exp.lower()
            for e in exports:
                nm = str(e.get("name", "")).lower()
                if nm == want:
                    return int(_addr(e.get("address"), name="address"))
            listed = ", ".join(str(e.get("name", "?")) for e in exports[:5])
            raise ValueError(
                f"call: export {exp!r} not found in {mod!r} "
                f"(sample: {listed or 'none'})")
        if "+" in s:
            return await _addr_resolve(address, client,
                                       kernel=(space == "kernel"), pid=pid)
    return _addr(address, "address")


def _sniff_script_shell(script: str, local_path: str) -> str:
    """Best-effort shell detection for ``run_script`` when the caller left
    ``shell`` unset. A ``local_path`` extension wins; inline text is scored
    on language markers. Returns "" when nothing is recognizable (caller
    falls back to 'cmd', the historical default).
    """
    import re as _re

    if local_path:
        ext = local_path.rsplit(".", 1)[-1].lower() if "." in local_path else ""
        if ext == "ps1":
            return "powershell"
        if ext in ("py", "pyw"):
            return "python"
        if ext in ("bat", "cmd"):
            return "cmd"
    head = (script or "")[:8192]
    if not head.strip():
        return ""
    # Python first — its markers don't overlap the shell ones.
    if _re.search(r"(?m)^\s*(import\s+\w|from\s+\w+\s+import|"
                  r"def\s+\w+\(|#!\S*python)", head):
        return "python"
    # Unambiguous batch markers short-circuit to cmd.
    if _re.search(r"(?im)^\s*(@?echo\s+off|setlocal\b|goto\s+:?\w+|"
                  r"if\s+exist\s)", head) or _re.search(r"%~?[%\w]", head):
        return "cmd"
    score = 0
    if _re.search(r"(?im)^\s*(param|function)\s*[\(\{]", head):
        score += 2
    if _re.search(r"(?im)^\s*#requires|<#", head):
        score += 2
    if _re.search(
            r"\b(Get|Set|New|Write|Invoke|Select|Where|ForEach|Start|Stop|"
            r"Test|Resolve|Convert|Out|Read|Remove|Copy|Move|Add|Clear|"
            r"Enter|Exit|Find|Format|Measure|Mount|Save|Send|Split|Join|"
            r"Group|Sort|Compare|Expand|Export|Import|Enable|Disable|"
            r"Register|Rename|Restart|Restore|Uninstall|Unregister|Update|"
            r"Wait|Watch)-[A-Za-z]+", head):
        score += 2
    if _re.search(r"\$\w+\s*=", head):
        score += 1
    if _re.search(r"(?i)\s-(eq|ne|gt|lt|ge|le|match|like|contains|"
                  r"replace|split|join)\b", head):
        score += 1
    return "powershell" if score >= 2 else ""


async def _exec_deadline(coro, timeout_s: float):
    """v0.25: orchestrator-side per-call deadline. ``asyncio.wait_for``
    cancels the coroutine, which cancels the in-flight gRPC call — the
    same effect as the wire ``timeout=`` kwarg that not every
    agent_client method exposes. ``0`` disables."""
    if not timeout_s or timeout_s <= 0:
        return await coro
    return await asyncio.wait_for(coro, timeout=timeout_s)


def _deadline_err(action: str, timeout_s: float, hint: str) -> str:
    return _j({"ok": False, "kind": "deadline_exceeded",
               "error": (f"{action}: no response within "
                         f"timeout_s={timeout_s}"),
               "hint": hint})


_DETACHED_DEADLINE_HINT = ("spawn may have succeeded — check detached "
                           "handles / detached_status / detached_tail "
                           "before retrying")
_RUN_DEADLINE_HINT = ("sync run_* enforces timeout_ms on the agent (child "
                      "process gets killed on expiry) AND an outer "
                      "timeout_s on the orchestrator — raising timeout_s "
                      "alone no longer stretches the child window: pass "
                      "timeout_ms = min(timeout_s*1000, mcp_budget) too, "
                      "or switch to exec_manage(action='run_detached') "
                      "for anything that can hang (poll detached_status "
                      "/ detached_tail)")


# v0.31 Phase 1.3: when the caller raised timeout_s above the default 30s
# but left timeout_ms at its default 30000, derive a matching timeout_ms
# so the agent-side process deadline keeps up with the orchestrator-side
# await deadline. Capped at the MCP response-budget ceiling to leave room
# for round-trip encode/transfer.
_EXEC_TIMEOUT_MS_DEFAULT = 30000
_EXEC_TIMEOUT_MS_CEILING_MS = 115_000  # MCP host hard deadline is ~120s


def _effective_timeout_ms(timeout_ms: int, timeout_s: float) -> int:
    """Phase 1.3: reconcile the agent-side child deadline with the outer
    orchestrator await deadline. When ``timeout_ms`` is still the default
    30000 but ``timeout_s`` was raised, grow ``timeout_ms`` to match
    (capped at the host budget). Explicit non-default ``timeout_ms``
    always wins."""
    if timeout_ms != _EXEC_TIMEOUT_MS_DEFAULT:
        return int(timeout_ms)
    if timeout_s <= 0 or timeout_s * 1000 <= _EXEC_TIMEOUT_MS_DEFAULT:
        return int(timeout_ms)
    return int(min(timeout_s * 1000, _EXEC_TIMEOUT_MS_CEILING_MS))


# v0.22: module-level so the lazy action-enum annotation resolves.
EXEC_ACTIONS = ["run_exe", "run_powershell", "run_cmd", "start_shell",
                "write_console", "read_console", "stop_shell",
                "shells",
                "kill_process", "suspend", "resume",
                # v15: remote function call (gate: security.allow_function_call)
                "call",
                "run_detached", "detached_status", "detached_tail",
                "detached_kill", "detached_follow",
                # v0.13 dev-feedback:
                "run_script",
                # v0.22 discoverability:
                "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``exec_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------- exec_manage --

    class ExecArgs(BaseModel):
        action: str = Field(description="run_exe|run_powershell|run_cmd|start_shell|write_console|"
                                        "read_console|stop_shell|kill_process|suspend|resume|"
                                        "run_detached|detached_status|detached_tail|detached_kill|"
                                        "run_script")
        exe: str = ""
        args_list: list[str] = Field(default_factory=list)
        command: str = ""
        workdir: str = ""
        timeout_ms: int = 30000
        shell: str = Field(default="", description="start_shell/run_script: "
                                                   "cmd|powershell|python — "
                                                   "empty auto-detects")
        session_id: int = 0
        data: str = ""
        pid: int = 0
        script_b64: str = Field(default="", description="base64 UTF-16LE "
                                                        "script (decoded "
                                                        "server-side)")
        handle_id: str = Field(default="", description="detached_*: the "
                                                       "handle from "
                                                       "run_detached")
        stdout_path: str = Field(default="", description="run_detached: redirect stdout")
        stderr_path: str = Field(default="", description="run_detached: redirect stderr")
        tail_bytes: int = Field(default=65536, description="detached_tail: bytes of log end")
        local_path: str = Field(default="", description="run_script: local "
                                                        "script to "
                                                        "upload+run")
        script: str = Field(default="", description="run_script: inline script text")
        background: bool = Field(default=False, description="run via "
                                                            "run_detached, "
                                                            "return "
                                                            "handle_id")
        # v0.25: orchestrator-side per-call gRPC deadline. 0 = each client
        # method's built-in deadline. Distinct from timeout_ms (the
        # agent-side child-kill cap); applies to run_exe/run_shell/
        # run_detached.
        timeout_s: float = Field(default=0.0, description="orchestrator-side "
                                                          "call deadline (s)")
        force: bool = Field(default=False,
                            description="override foreign_owned on "
                                        "shell/detached handles; kernel "
                                        "call: skip module-range checks")
        # v15: exec_manage(action='call') — remote function call in target
        # context (gate: security.allow_function_call). `name` selects the
        # target view; `address` accepts an int, 'module+offset' or
        # 'module!export'; `call_args` are the ms64 args.
        name: str = Field(default="", description="target view: '' = "
                                                  "focused/default machine "
                                                  "kernel; '<machine>.<kind>' "
                                                  "for a specific view")
        space: str = Field(default="user", description="call: 'user' | "
                                                       "'kernel'")
        address: Any = Field(default=0, description="call: function VA — "
                                                    "int, '0x…', "
                                                    "'module+offset' or "
                                                    "'module!export'")
        call_args: list = Field(default_factory=list, description="call: up "
                                                                  "to 16 "
                                                                  "fixed64 "
                                                                  "args (ms64 "
                                                                  "order)")
        kill_on_timeout: bool = Field(default=False, description="call: on "
                                                                 "user-space "
                                                                 "timeout, "
                                                                 "TerminateThread "
                                                                 "the "
                                                                 "injected "
                                                                 "thread + "
                                                                 "free the "
                                                                 "page")

    _EXEC_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "exec_manage(action='actions')"},
        "run_exe": {"one_liner": "spawn an exe on the target, capture "
                                 "stdout/stderr (timeout_ms bounded; "
                                 "background=true detaches)",
                    "key_args": "exe, args_list, workdir, timeout_ms, "
                                "background, timeout_s",
                    "example": "exec_manage(action='run_exe', exe='whoami.exe', "
                               "timeout_ms=10000)"},
        "run_powershell": {"one_liner": "run a PowerShell command "
                                        "(quotes/& survive badly through "
                                        "the double parse — script_b64= "
                                        "(-EncodedCommand, UTF-16LE "
                                        "base64) bypasses quoting "
                                        "entirely; background=true "
                                        "detaches)",
                           "key_args": "command | script_b64, timeout_ms, "
                                       "background, timeout_s",
                           "example": "exec_manage(action='run_powershell', "
                                      "command='Get-Process -Name lsass')"},
        "run_cmd": {"one_liner": "run a cmd.exe command (double quotes "
                                 "and & get mangled through the double "
                                 "parse — non-trivial commands belong "
                                 "on run_script, which uploads the "
                                 "script verbatim; background=true "
                                 "detaches)",
                    "key_args": "command, timeout_ms, background, timeout_s",
                    "example": "exec_manage(action='run_cmd', command='dir C:\\\\')"},
        "start_shell": {"one_liner": "open a persistent interactive shell "
                                     "session on the target",
                        "key_args": "shell ('cmd'|'powershell')",
                        "example": "exec_manage(action='start_shell', "
                                   "shell='powershell')"},
        "write_console": {"one_liner": "send input to a shell session",
                          "key_args": "session_id, data",
                          "example": "exec_manage(action='write_console', "
                                     "session_id=3, data='dir\\n')"},
        "read_console": {"one_liner": "read buffered output from a shell "
                                      "session",
                         "key_args": "session_id",
                         "example": "exec_manage(action='read_console', "
                                    "session_id=3)"},
        "stop_shell": {"one_liner": "close a shell session",
                       "key_args": "session_id",
                       "example": "exec_manage(action='stop_shell', "
                                  "session_id=3)"},
        "shells": {"one_liner": "list live shell session ids on the agent",
                       "key_args": "none",
                       "example": "exec_manage(action='shells')"},
        "kill_process": {"one_liner": "terminate a target pid",
                         "key_args": "pid",
                         "example": "exec_manage(action='kill_process', "
                                    "pid=1234)"},
        "suspend": {"one_liner": "suspend a target pid",
                    "key_args": "pid",
                    "example": "exec_manage(action='suspend', pid=1234)"},
        "resume": {"one_liner": "resume a suspended pid",
                   "key_args": "pid",
                   "example": "exec_manage(action='resume', pid=1234)"},
        "call": {"one_liner": "call a function in target context and read "
                              "rax (gate: security.allow_function_call)",
                 "key_args": ("address (int | '0x…' | 'module+offset' | "
                              "'module!export'), space ('user'|'kernel'), "
                              "pid (user), call_args, timeout_ms, "
                              "kill_on_timeout, force, name (view selector)"),
                 "example": ("exec_manage(action='call', space='user', "
                             "address='kernel32!GetCurrentProcessId', "
                             "pid=1234)")},
        "run_detached": {"one_liner": "spawn detached w/ per-handle log "
                                      "files — survives MCP timeouts",
                         "key_args": "command (cmdline), workdir, "
                                     "stdout_path, stderr_path, timeout_s",
                         "example": "exec_manage(action='run_detached', "
                                    "command='long_task.exe')"},
        "detached_status": {"one_liner": "poll a detached handle",
                            "key_args": "handle_id",
                            "example": "exec_manage(action='detached_status', "
                                       "handle_id='h1')"},
        "detached_tail": {"one_liner": "tail a detached job's stdout/stderr "
                                       "log files",
                          "key_args": "handle_id, tail_bytes",
                          "example": "exec_manage(action='detached_tail', "
                                     "handle_id='h1')"},
        "detached_kill": {"one_liner": "kill a detached job",
                          "key_args": "handle_id",
                          "example": "exec_manage(action='detached_kill', "
                                     "handle_id='h1')"},
        "detached_follow": {"one_liner": "subscribe to a detached job's "
                                         "stdout/stderr via follow_start "
                                         "plus exit status — change-notify "
                                         "instead of polling",
                            "key_args": "handle_id",
                            "example": "exec_manage(action='detached_follow', "
                                       "handle_id='h1')"},
        "run_script": {"one_liner": "run an orchestrator-side script file "
                                    "against the target",
                       "key_args": "local_path | script",
                       "example": "exec_manage(action='run_script', "
                                  "local_path='scripts/x.ps1')"},
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def exec_manage(action: Annotated[str, Field(json_schema_extra={"enum": EXEC_ACTIONS})],
                          exe: str = "", args_list: list[str] | None = None,
                          command: str = "", workdir: str = "", timeout_ms: int = 30000,
                          shell: str = "", session_id: int = 0, data: str = "",
                          pid: int = 0, script_b64: str = "",
                          handle_id: str = "",
                          stdout_path: str = "", stderr_path: str = "",
                          tail_bytes: int = 65536,
                          local_path: str = "", script: str = "",
                          background: bool = False,
                          timeout_s: float = 0.0,
                          force: bool = False,
                          name: str = "",
                          space: str = "user",
                          address: Any = 0,
                          call_args: list | None = None,
                          kill_on_timeout: bool = False) -> str:
        """Process execution: run_exe/run_cmd/run_powershell (sync),
        run_script (upload+run), run_detached + detached_* handles,
        start_shell/write_console/read_console persistent shells,
        kill_process, suspend/resume, call (in-context function call —
        gated by security.allow_function_call).

        Anything that CAN hang belongs on run_detached or background=true
        — the sync verbs lose stdout to DEADLINE_EXCEEDED. Anything beyond
        a trivial one-liner belongs on run_script (the cmd/powershell
        double parse mangles quoting). Per-verb help:
        exec_manage(action='actions')."""
        args_list = args_list or []
        args = {"action": action, "exe": exe, "command": command, "pid": pid}

        async def run() -> str:
            nonlocal action, script, shell
            # v0.22: discovery verb — pure compute, before require_client.
            if action == "actions":
                return _actions_help("exec_manage", _EXEC_ACTION_HELP)
            # v0.21 dev-feedback: `script_b64` used to feed
            # `powershell -EncodedCommand`, which corrupted long payloads
            # mid-stream (padding/terminator bugs). Decode it here and run
            # the result through the run_script upload path — a file can't
            # get mangled by command-line quoting.
            if script_b64 and action in ("run_powershell", "run_script"):
                import base64 as _b64
                try:
                    decoded = _b64.b64decode(script_b64, validate=True) \
                        .decode("utf-16-le")
                except Exception as exc:
                    return _j({"ok": False, "kind": "bad_script_b64",
                               "error": f"script_b64 decode failed: {exc}",
                               "hint": "expected base64 of UTF-16LE text "
                                       "(the -EncodedCommand format); or pass "
                                       "script= with shell='powershell' to "
                                       "run_script instead"})
                action = "run_script"
                script = decoded
                shell = shell or "powershell"
            # v0.27: name= resolves machine.view; the canonical key also
            # namespaces the exec_shell/exec_detached ownership tags below.
            try:
                view = ctx.session.resolve_view_name(name)
            except Exception as exc:
                if not name:
                    raise  # ambiguous/no-target: keep the original error
                # v0.28: a job-name-looking name= here reads as "name my
                # detached job" but selects a target view — say so
                # instead of a bare unknown-machine error.
                return _j({
                    "ok": False, "kind": "bad_arg",
                    "error": f"exec_manage {action}: name selector "
                             f"{name!r} failed to resolve: {exc}",
                    "hint": ("exec_manage name= selects a target VIEW "
                             "('lab2.kernel'), not a job/label name — "
                             "drop it for run_detached; use handle_id= "
                             "for detached_status/tail/kill")})
            if action == "call":
                # The space/view-kind gate below must fire before
                # connectivity — a refused kernel-space call on a user
                # view reports bad_arg, not not_connected.
                c = ctx.session.clients.get(view)
            else:
                c = ctx.session.require_client(view)
            # v0.25: background=true detaches the shell/run verbs through
            # run_detached — same cmdline assembly as run_script's. The
            # child survives the MCP call returning; stdout/stderr land in
            # the agent's per-handle log files.
            if background and action in ("run_exe", "run_powershell",
                                         "run_cmd"):
                if not hasattr(c, "run_detached"):
                    return _j({"ok": False,
                               "error": ("background=true needs agent >= v7 "
                                         "(Exec.RunDetached)."),
                               "hint": ("drop background=true, or rebuild "
                                        "the agent — fallback: start_shell "
                                        "+ write_console + read_console")})
                if action == "run_exe":
                    spawn_exe = exe or command
                    spawn_args = list(args_list)
                elif action == "run_powershell":
                    spawn_exe = "powershell.exe"
                    spawn_args = ["-NoProfile", "-Command", command]
                else:
                    spawn_exe = "cmd.exe"
                    spawn_args = ["/c", command]
                if not spawn_exe or (action != "run_exe" and not command):
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"{action} background=true: "
                                        "command/exe is empty"})
                cmdline = f'"{spawn_exe}"' + "".join(
                    f' "{a}"' if " " in a else f" {a}" for a in spawn_args)
                try:
                    r = await _exec_deadline(
                        c.run_detached(cmdline, workdir,
                                       stdout_path, stderr_path),
                        timeout_s)
                except asyncio.TimeoutError:
                    return _deadline_err(action, timeout_s,
                                         _DETACHED_DEADLINE_HINT)
                except Exception as exc:
                    return _j({"ok": False, **_enrich_error(
                        "exec_manage", action, str(exc))})
                hid = r.get("handle_id") if isinstance(r, dict) else None
                if hid and ctx.ownership is not None:
                    await ctx.ownership.claim(
                        f"exec_detached:{view}", hid, current_client_id())
                out = dict(r) if isinstance(r, dict) else {"ok": True,
                                                           "result": r}
                out["ok"] = out.get("ok", True)
                out["background"] = True
                out["hint"] = ("detached spawn — poll exec_manage("
                               "action='detached_status'|'detached_tail', "
                               f"handle_id='{hid}'); kill with "
                               "detached_kill")
                return _j(out)
            if action == "run_exe":
                # v0.31 Phase 1.3: honor timeout_s when timeout_ms is at
                # its default — a caller that raised timeout_s but left
                # timeout_ms alone used to see the orchestrator wait N
                # seconds while the agent killed the child at 30s.
                _eff_ms = _effective_timeout_ms(timeout_ms, timeout_s)
                try:
                    r = await _exec_deadline(
                        c.run_exe(exe, args_list, workdir, _eff_ms),
                        timeout_s)
                except asyncio.TimeoutError:
                    return _deadline_err(action, timeout_s,
                                         _RUN_DEADLINE_HINT)
                except Exception as exc:
                    e = _enrich_error("exec_manage", "run_exe", str(exc))
                    if e.get("kind") == "deadline_exceeded":
                        e["hint"] = ("switch to exec_manage(action='run_detached') "
                                     "for long-running / potentially-hanging commands; "
                                     "poll with detached_status / detached_tail")
                    return _j({"ok": False, **e})
                if r.get("timed_out"):
                    r["hint"] = ("agent enforced timeout_ms; if the child "
                                 "wedged the target, prefer run_detached "
                                 "next time — it survives child hangs")
                return _j(r)
            if action == "run_script":
                # v0.13 dev-feedback: first-class upload-and-run. Blessed path
                # for anything non-trivial (nested-cmd quoting breaks on
                # $/`/quotes; script_b64 is decoded into this path above).
                import os as _os
                import secrets as _secrets
                import tempfile as _tempfile
                from pathlib import Path as _P
                src = local_path
                if not src and not script:
                    return _j({"ok": False,
                                "error": "run_script: local_path or script required"})
                # v0.21: shell auto-detect. Previously shell defaulted to
                # 'cmd' and a .ps1 got run as a batch file — PowerShell
                # bodies had to pass shell='powershell' explicitly.
                eff_shell = shell or _sniff_script_shell(script, src) or "cmd"
                if not src:
                    scratch = _os.environ.get("CLAUDE_SCRATCHPAD") or _tempfile.gettempdir()
                    ext = ".ps1" if eff_shell == "powershell" \
                        else (".cmd" if eff_shell == "cmd" else ".py")
                    src = str(_P(scratch) / f"suspex_{_secrets.token_hex(6)}{ext}")
                    _P(src).write_text(script, encoding="utf-8")
                ext = _P(src).suffix or \
                    (".ps1" if eff_shell == "powershell" else ".cmd")
                remote_name = f"suspex_{_secrets.token_hex(6)}{ext}"
                remote_full = f"C:\\Windows\\Temp\\{remote_name}"
                try:
                    await c.file_upload(src, remote_full)
                except Exception as exc:
                    return _j({"ok": False, **_enrich_error(
                        "exec_manage", "run_script", f"upload failed: {exc}")})
                exe_map = {"powershell": "powershell.exe", "cmd": "cmd.exe",
                            "python": "python.exe"}
                shell_exe = exe_map.get(eff_shell, eff_shell + ".exe")
                shell_args_map = {
                    "powershell": ["-NoProfile", "-ExecutionPolicy", "Bypass",
                                    "-File", remote_full],
                    "cmd":        ["/c", remote_full],
                    "python":     [remote_full],
                }
                spawn_args = shell_args_map.get(eff_shell, [remote_full]) \
                    + list(args_list or [])
                result: dict[str, Any]
                try:
                    if background:
                        cmdline = f'"{shell_exe}"' + "".join(
                            f' "{a}"' if " " in a else f" {a}" for a in spawn_args)
                        result = await _exec_deadline(
                            c.run_detached(cmdline, workdir=workdir),
                            timeout_s)
                    else:
                        _eff_ms = _effective_timeout_ms(timeout_ms, timeout_s)
                        result = await _exec_deadline(
                            c.run_exe(shell_exe, spawn_args, workdir, _eff_ms),
                            timeout_s)
                except Exception as exc:
                    try: await c.file_delete(remote_full, no_trash=True)
                    except Exception: pass
                    return _j({"ok": False, **_enrich_error(
                        "exec_manage", "run_script", str(exc))})
                # Best-effort cleanup of the remote script file.
                try:
                    await c.file_delete(remote_full, no_trash=True)
                except Exception:
                    pass
                out = dict(result) if isinstance(result, dict) else {"result": result}
                out["ok"] = out.get("ok", True)
                out.setdefault("uploaded", remote_full)
                out["shell"] = eff_shell
                out["hint"] = ("run_script is the blessed path for non-trivial "
                                "scripts. For anything that can hang, pass "
                                "background=true and poll detached_status.")
                return _j(out)
            if action == "run_powershell":
                # script_b64 was decoded into the run_script path above —
                # what remains here is a plain command line.
                # v0.31 Phase 1.8: auto-route long / multi-line /
                # non-ASCII `command=` through the run_script upload
                # path. `powershell -Command <quoted>` collapses on
                # embedded quotes, backticks, newlines, or non-ASCII
                # (codepage mangling); a file on disk sidesteps every
                # one of those. The threshold is intentionally
                # conservative — a one-liner stays on the fast path.
                def _needs_upload(cmd: str) -> bool:
                    if not cmd:
                        return False
                    if len(cmd) > 1024:
                        return True
                    if "\n" in cmd or "\r" in cmd:
                        return True
                    try:
                        cmd.encode("ascii")
                    except UnicodeEncodeError:
                        return True
                    return False
                if _needs_upload(command):
                    # Fall through to the run_script upload path with
                    # the PowerShell body as the script. action rewrite
                    # is the shortest route — keeps the rest of the
                    # run_script branch unchanged.
                    action = "run_script"
                    script = command
                    shell = shell or "powershell"
                    # Reuse the fast path's recursion by re-entering run().
                    return await run()
                _eff_ms = _effective_timeout_ms(timeout_ms, timeout_s)
                try:
                    return _j(await _exec_deadline(
                        c.run_shell(command, "powershell", workdir,
                                    _eff_ms), timeout_s))
                except asyncio.TimeoutError:
                    return _deadline_err(action, timeout_s,
                                         _RUN_DEADLINE_HINT)
            if action == "run_cmd":
                _eff_ms = _effective_timeout_ms(timeout_ms, timeout_s)
                try:
                    return _j(await _exec_deadline(
                        c.run_shell(command, "cmd", workdir, _eff_ms),
                        timeout_s))
                except asyncio.TimeoutError:
                    return _deadline_err(action, timeout_s,
                                         _RUN_DEADLINE_HINT)
            if action == "start_shell":
                r = await c.start_shell(shell or "cmd", workdir)
                sid = r.get("session_id") if isinstance(r, dict) else None
                if sid is not None and ctx.ownership is not None:
                    await ctx.ownership.claim(
                        f"exec_shell:{view}", str(sid), current_client_id())
                return _j(r)
            if action == "shells":
                # v14: live session ids — recovery when a session_id got
                # stripped in transit or the table drifted.
                return _j(await c.list_shells())
            if action in ("write_console", "read_console", "stop_shell"):
                # v14: reject a missing/stripped session_id up front with
                # the live ids attached — a 0 that arrives via arg loss is
                # indistinguishable from a dead session without this.
                if not isinstance(session_id, int) or session_id <= 0:
                    live = await c.list_shells()
                    return _j({
                        "ok": False, "kind": "bad_arg",
                        "error": (f"{action}: session_id must be a positive "
                                  f"int (got {session_id!r}); live sessions "
                                  f"on the agent: {live.get('session_ids')}"),
                        "hint": ("if you DID pass session_id, the value was "
                                 "stripped between client and server — see "
                                 "received_args on this error's envelope"),
                    })
                if ctx.ownership is not None:
                    foreign = await ctx.ownership.is_foreign_or_none(
                        f"exec_shell:{view}", str(session_id),
                        current_client_id())
                    if foreign is True and not force:
                        owner = await ctx.ownership.owner_of(
                            f"exec_shell:{view}", str(session_id))
                        return _j({
                            "ok": False, "kind": "foreign_owned",
                            "resource": "exec_shell",
                            "view": view,
                            "session_id": session_id,
                            "owned_by": owner,
                            "hint": "another client owns this shell session; "
                                    "pass force=true to override or coordinate "
                                    "with the owner",
                        })
                if action == "write_console":
                    return _j(await c.shell_write(session_id, data + "\n"))
                if action == "read_console":
                    return _j(await c.shell_read(session_id, timeout_ms))
                # stop_shell
                r = await c.shell_stop(session_id)
                if isinstance(r, dict) and r.get("ok") and ctx.ownership is not None:
                    await ctx.ownership.release(
                        f"exec_shell:{view}", str(session_id))
                return _j(r)
            if action == "kill_process":
                return _j(await c.kill_process(pid))
            if action == "suspend":
                return _j(await c.suspend_process(pid))
            if action == "resume":
                return _j(await c.resume_process(pid))
            if action == "call":
                # v15: in-context function call — the strongest actuator in
                # the stack. Gate mirrors device_manage ioctl.
                if not getattr(ctx.cfg.security, "allow_function_call", False):
                    return _j({"ok": False, "kind": "not_allowed",
                               "error": ("exec_manage call: disabled "
                                         "(security.allow_function_call="
                                         "false) — remote function "
                                         "execution runs attacker-chosen "
                                         "code in target context"),
                               "hint": ("enable security.allow_function_call "
                                        "in the orchestrator config once the "
                                        "target is known-good")})
                if space not in ("user", "kernel"):
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"call: space must be 'user' or "
                                        f"'kernel' (got {space!r})"})
                if space == "kernel" and ctx.session.view_kind_of(view) != "kernel":
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "call: kernel calls need the "
                                        "driver-backed view (pass name='kernel' "
                                        "or omit name)"})
                if space == "user" and not pid:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "call: pid required for user space"})
                try:
                    c = ctx.session.require_client(name)
                except RuntimeError as exc:
                    return _j({"ok": False, "kind": "not_connected",
                               "error": str(exc)})
                argv = [_addr(a, "arg") for a in (call_args or [])]
                if len(argv) > 16:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"call: argc={len(argv)} > 16"})
                try:
                    addr = await _resolve_call_target(address, space, c, pid)
                except Exception as exc:  # noqa: BLE001 - resolution failures are user-facing
                    return _j({"ok": False, "kind": "bad_target",
                               "error": f"call: {exc}"})
                flags = (1 if kill_on_timeout else 0) | (2 if force else 0)
                try:
                    r = await c.call_function(
                        pid=pid, target_va=addr, args=argv, space=space,
                        timeout_ms=timeout_ms, flags=flags)
                except Exception as exc:  # noqa: BLE001 - UNIMPLEMENTED == agent_old
                    msg = str(exc)
                    if "UNIMPLEMENTED" in msg:
                        return _j({"ok": False, "kind": "agent_old",
                                   "error": f"call: {msg}",
                                   "hint": "rebuild agent with proto v15 "
                                           "(Exec.CallFunction)"})
                    return _j({"ok": False, "kind": "call_failed",
                               "error": msg})
                out: dict[str, Any] = {
                    "ok": r.get("ok", False),
                    "status": _call_status(r),
                    "error": r.get("error", ""),
                    "return_value": r.get("return_value", 0),
                    "return_value_hex": hex(int(r.get("return_value", 0))),
                    "last_error": r.get("last_error", 0),
                    "exit_code": r.get("exit_code", 0),
                    "timed_out": bool(r.get("timed_out")),
                    "exception": bool(r.get("exception")),
                    "exception_code": r.get("exception_code", 0),
                    "thread_tid": r.get("thread_tid", 0),
                    "stub_va": r.get("stub_va", 0),
                }
                if r.get("timed_out"):
                    out["hint"] = (
                        "thread terminated and stub page freed "
                        "(kill_on_timeout)"
                        if kill_on_timeout else
                        "thread left running — inspect "
                        "thread_tid / stub_va; free the page with "
                        "mem_rw(action='free'); retry with "
                        "kill_on_timeout=true to terminate + free")
                elif r.get("exception"):
                    out["hint"] = ("unhandled exception in the callee / SEH "
                                   "capture — see exception_code")
                return _j_hex(out)
            # ---- Phase 1.4: detached execution family (agent >= v7) ----
            if action == "run_detached":
                if not hasattr(c, "run_detached"):
                    return _j({"ok": False,
                               "error": "run_detached needs agent >= v7 (Exec.RunDetached).",
                               "hint": "fallback: start_shell + write_console(cmd) + read_console"})
                cmdline = exe or command
                if args_list:
                    cmdline = cmdline + " " + " ".join(
                        (f'"{a}"' if " " in a else a) for a in args_list)
                try:
                    r = await _exec_deadline(
                        c.run_detached(cmdline, workdir, stdout_path,
                                       stderr_path), timeout_s)
                except asyncio.TimeoutError:
                    return _deadline_err(action, timeout_s,
                                         _DETACHED_DEADLINE_HINT)
                hid = r.get("handle_id") if isinstance(r, dict) else None
                if hid and ctx.ownership is not None:
                    await ctx.ownership.claim(
                        f"exec_detached:{view}", hid, current_client_id())
                if isinstance(r, dict) and r.get("ok"):
                    # v0.28: surface the transport reality up front —
                    # this used to hide in detached_follow's hint, and
                    # agents kept polling detached_status hopefully.
                    r.setdefault("warnings", []).append(
                        "detached stdout is EXIT-ONLY for CRT-buffered "
                        "children (PowerShell/cmd write nothing to the "
                        "log until the process exits) — have the script "
                        "tee to its own log file and poll that with "
                        "file_manage(action='read'), or use "
                        "detached_follow for change-notify")
                return _j(r)
            if action == "detached_follow":
                # v14: the detached logs are share-opened on the agent, so
                # LogFollow subscribes fine — wraps detached_status +
                # follow_start into one call (change-notify, not polling).
                if not handle_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "detached_follow: handle_id is required "
                                        "(got empty string)"})
                if not hasattr(c, "detached_status"):
                    return _j({"ok": False, "error": "agent < v7"})
                if ctx.ownership is not None:
                    foreign = await ctx.ownership.is_foreign_or_none(
                        f"exec_detached:{view}", handle_id,
                        current_client_id())
                    if foreign is True and not force:
                        owner = await ctx.ownership.owner_of(
                            f"exec_detached:{view}", handle_id)
                        return _j({
                            "ok": False, "kind": "foreign_owned",
                            "resource": "exec_detached",
                            "view": view,
                            "handle_id": handle_id,
                            "owned_by": owner,
                            "hint": "another client owns this detached handle; "
                                    "pass force=true to override or coordinate "
                                    "with the owner",
                        })
                st = await c.detached_status(handle_id)
                out: dict[str, Any] = {
                    "ok": True, "handle_id": handle_id,
                    "running": st.get("running"),
                    "exit_code": st.get("exit_code"),
                    "pid": st.get("pid"),
                    "follows": {},
                }
                for which in ("stdout", "stderr"):
                    p = st.get(which + "_path")
                    if not p:
                        continue
                    fr = await _follow_start(
                        ctx, c, p,
                        from_offset=-1, initial_tail_bytes=65536,
                        poll_interval_ms=200, max_chunk_bytes=65536,
                        line_align=True, follow_rotation=True,
                        duration_s=600, max_bytes=0, ring_cap=256)
                    out["follows"][which] = fr
                out["hint"] = ("poll with file_manage(action='follow_poll', "
                               "follow_id=…); child-side CRT buffering can "
                               "delay writes — the agent can't flush another "
                               "process's stdio")
                return _j(out)
            if action in ("detached_status", "detached_tail", "detached_kill"):
                if not hasattr(c, action):
                    return _j({"ok": False, "error": "agent < v7"})
                if not handle_id:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"{action}: handle_id is required "
                                        "(got empty string)"})
                if ctx.ownership is not None:
                    foreign = await ctx.ownership.is_foreign_or_none(
                        f"exec_detached:{view}", handle_id,
                        current_client_id())
                    if foreign is True and not force:
                        owner = await ctx.ownership.owner_of(
                            f"exec_detached:{view}", handle_id)
                        return _j({
                            "ok": False, "kind": "foreign_owned",
                            "resource": "exec_detached",
                            "view": view,
                            "handle_id": handle_id,
                            "owned_by": owner,
                            "hint": "another client owns this detached handle; "
                                    "pass force=true to override or coordinate "
                                    "with the owner",
                        })
                if action == "detached_status":
                    return _j(await c.detached_status(handle_id))
                if action == "detached_tail":
                    return _j(await c.detached_tail(handle_id, tail_bytes))
                # detached_kill
                r = await c.detached_kill(handle_id)
                if isinstance(r, dict) and r.get("ok") and ctx.ownership is not None:
                    await ctx.ownership.release(
                        f"exec_detached:{view}", handle_id)
                return _j(r)
            return _unknown_action("exec_manage", action, EXEC_ACTIONS, _EXEC_ACTION_HELP)

        return await _guard(ctx, "exec_manage", action, args, run)
