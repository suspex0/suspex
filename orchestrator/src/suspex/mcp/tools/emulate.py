"""Emulate tool registration for the suspex0 MCP server.

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


# v0.22: module-level so the lazy action-enum annotation resolves.
EMU_ACTIONS = ["create", "load_shellcode", "load_pe", "run", "step",
               "regs", "set_regs", "mem_read", "mem_write",
               "map", "unmap", "hook_add", "hook_remove",
               "snapshot", "restore", "seed_from_target",
               "close", "list", "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``emulate_manage`` tool on *mcp*, using *ctx* for state."""
    # ------------------------------------------------------------ emulate_manage --

    _EMU_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "emulate_manage(action='actions')"},
        "create": {"one_liner": "start an emulation session (speakeasy/"
                                "unicorn)",
                   "key_args": "arch, mode, engine",
                   "example": "emulate_manage(action='create', mode='pe')"},
        "load_shellcode": {"one_liner": "load raw code into the session",
                           "key_args": "session_id, data_hex",
                           "example": "emulate_manage(action='load_shellcode', "
                                      "session_id='e1', data_hex='...')"},
        "load_pe": {"one_liner": "load a PE/module image into the session",
                    "key_args": "session_id, path | module",
                    "example": "emulate_manage(action='load_pe', "
                               "session_id='e1', path='x.sys')"},
        "run": {"one_liner": "run until exit/stop condition",
                "key_args": "session_id, max_insns/timeout",
                "example": "emulate_manage(action='run', session_id='e1')"},
        "step": {"one_liner": "single-step N instructions",
                 "key_args": "session_id, count",
                 "example": "emulate_manage(action='step', session_id='e1', "
                            "count=10)"},
        "regs": {"one_liner": "read the emulated register bank",
                 "key_args": "session_id",
                 "example": "emulate_manage(action='regs', session_id='e1')"},
        "set_regs": {"one_liner": "write emulated registers",
                     "key_args": "session_id, regs_json",
                     "example": "emulate_manage(action='set_regs', "
                                "session_id='e1', regs_json='{\"rsp\":\"0x...\"}')"},
        "mem_read": {"one_liner": "read emulated memory",
                     "key_args": "session_id, address, size",
                     "example": "emulate_manage(action='mem_read', "
                                "session_id='e1', address='0x...', size=64)"},
        "mem_write": {"one_liner": "write emulated memory",
                      "key_args": "session_id, address, data_hex",
                      "example": "emulate_manage(action='mem_write', "
                                 "session_id='e1', address='0x...', "
                                 "data_hex='90')"},
        "map": {"one_liner": "map a region into the emulated address space",
                "key_args": "session_id, address, size, protect",
                "example": "emulate_manage(action='map', session_id='e1', "
                           "address='0x10000', size=0x1000)"},
        "unmap": {"one_liner": "unmap a region",
                  "key_args": "session_id, address, size",
                  "example": "emulate_manage(action='unmap', "
                             "session_id='e1', address='0x10000', "
                             "size=0x1000)"},
        "hook_add": {"one_liner": "add an emulation hook (code/mem/api)",
                     "key_args": "session_id, hook params",
                     "example": "emulate_manage(action='hook_add', "
                                "session_id='e1')"},
        "hook_remove": {"one_liner": "remove a hook",
                        "key_args": "session_id, hook_id",
                        "example": "emulate_manage(action='hook_remove', "
                                   "session_id='e1')"},
        "snapshot": {"one_liner": "capture session state for later restore",
                     "key_args": "session_id",
                     "example": "emulate_manage(action='snapshot', "
                                "session_id='e1')"},
        "restore": {"one_liner": "roll back to a snapshot",
                    "key_args": "session_id",
                    "example": "emulate_manage(action='restore', "
                               "session_id='e1')"},
        "seed_from_target": {"one_liner": "seed emulated memory/regs from "
                                          "the live target",
                             "key_args": "session_id, pid, address, size",
                             "example": "emulate_manage(action='seed_from_target', "
                                        "session_id='e1', pid=1234)"},
        "close": {"one_liner": "tear down a session",
                  "key_args": "session_id",
                  "example": "emulate_manage(action='close', session_id='e1')"},
        "list": {"one_liner": "list emulation sessions",
                 "key_args": "none",
                 "example": "emulate_manage(action='list')"},
    }

    class EmuArgs(BaseModel):
        action: str = Field(description="|".join(EMU_ACTIONS))
        session_id: str = Field(default="", description="from `create`")
        arch: str = Field(default="x64", description="x64|x86")
        mode: str = Field(default="shellcode",
                          description="shellcode|pe|module")
        engine: str = Field(default="speakeasy",
                            description="speakeasy|unicorn")
        flavor: str = Field(default="latest",
                            description="speakeasy OS build flavor (default|latest)")
        # shellcode/pe loading
        bytes_hex: str = Field(default="",
                               description="load_shellcode: raw hex buffer")
        code: str = Field(default="",
                          description="load_shellcode: assembly source "
                                      "(auto-assembled via keystone)")
        path: str = Field(default="",
                          description="load_pe or load_shellcode: local file "
                                      "path (orchestrator side)")
        entry: int | str = Field(default=0,
                                 description="load_shellcode: base VA (default "
                                             "engine-picked)")
        image_base: int | str = Field(default=0,
                                      description="load_pe: preferred image base")
        cmdline: str = Field(default="", description="load_pe: command line")
        # run / step
        until: int | str = Field(default=0, description="run: halt at this VA")
        max_ins: int = Field(default=100_000, description="run: instruction cap")
        timeout_s: float = Field(default=10.0, description="run: wall-clock cap")
        n: int = Field(default=1, description="step: number of instructions")
        # regs / memory
        address: int | str = Field(default=0, description="mem_read/mem_write/map: VA")
        size: int = Field(default=0, description="mem_read/map: byte count")
        prot: str = Field(default="rwx",
                          description="map: r/w/x combo (default rwx)")
        label: str = Field(default="",
                           description="map/snapshot: cosmetic tag")
        regs_json: str = Field(default="{}",
                               description="set_regs: JSON object "
                                           "('{\"rax\": 1, \"rcx\": \"0x1000\"}')")
        include_ext: bool = Field(default=False,
                                  description="regs: include xmm/ymm (currently ignored)")
        # hooks
        kind: str = Field(default="api", description="hook_add: api|addr")
        api: str = Field(default="",
                         description="hook_add(api): 'kernel32!VirtualAlloc'")
        on: str = Field(default="pre", description="hook_add: pre|post")
        hook_action: str = Field(default="log",
                                 description="hook_add: log|skip|return")
        return_value: int | str = Field(default=0,
                                        description="hook_add(action=return): value to return")
        hook_id: str = Field(default="", description="hook_remove")
        # snapshots
        snap_id: str = Field(default="", description="restore")
        # seeding
        view: str = Field(default="user",
                          description="seed_from_target: user|kernel view")
        pid: int = Field(default=0, description="seed_from_target: target pid")
        tid: int = Field(default=0, description="seed_from_target: target tid")
        regions_json: str = Field(default="[]",
                                  description="seed_from_target: JSON list of "
                                              "{address, size, label}")
        target: str = Field(default="",
                            description="seed_from_target: session view to "
                                        "read from (defaults to `view`)")

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def emulate_manage(action: Annotated[str, Field(json_schema_extra={"enum": EMU_ACTIONS})],
                              session_id: str = "",
                              arch: str = "x64",
                              mode: str = "shellcode",
                              engine: str = "speakeasy",
                              flavor: str = "latest",
                              bytes_hex: str = "",
                              code: str = "",
                              path: str = "",
                              entry: int | str = 0,
                              image_base: int | str = 0,
                              cmdline: str = "",
                              until: int | str = 0,
                              max_ins: int = 100_000,
                              timeout_s: float = 10.0,
                              n: int = 1,
                              address: int | str = 0,
                              size: int = 0,
                              prot: str = "rwx",
                              label: str = "",
                              regs_json: str = "{}",
                              include_ext: bool = False,
                              kind: str = "api",
                              api: str = "",
                              on: str = "pre",
                              hook_action: str = "log",
                              return_value: int | str = 0,
                              hook_id: str = "",
                              snap_id: str = "",
                              view: str = "user",
                              pid: int = 0,
                              tid: int = 0,
                              regions_json: str = "[]",
                              target: str = "") -> str:
        """Emulator sessions (Speakeasy Windows veneer by default, Unicorn
        bare-CPU escape hatch): create → load_shellcode/load_pe → run/
        step/regs/mem_*/hook_*/snapshot → close. Codegen extra required.
        Per-verb help: emulate_manage(action='actions')."""
        args = {"action": action, "session_id": session_id,
                "arch": arch, "engine": engine}

        async def run() -> str:
            if action not in EMU_ACTIONS:
                return _unknown_action("emulate_manage", action, EMU_ACTIONS, _EMU_ACTION_HELP)
            if action == "actions":
                return _actions_help("emulate_manage", _EMU_ACTION_HELP)

            # Lazy import so a missing codegen extra doesn't gate the whole
            # tool registration.
            try:
                from ... import emulate as _emu
            except Exception as exc:  # pragma: no cover
                return _j({"ok": False, "kind": "codegen_extra_missing",
                           "error": f"emulate_manage: {exc}",
                           "hint": "pip install 'suspex0[codegen]'"})

            if action == "create":
                try:
                    s = _emu.create_session(arch=arch, mode=mode,
                                             engine=engine, flavor=flavor)
                except _emu.CodegenUnavailable as exc:
                    return _codegen_extra_err(exc)
                except Exception as exc:
                    return _j({"ok": False, "kind": "engine_init_failed",
                               "error": f"emulate_manage create: {exc}",
                               "hint": "try engine='unicorn' if speakeasy is broken"})
                return _j({"ok": True, **s.summary()})

            if action == "list":
                return _j({"ok": True, "sessions": _emu.list_sessions()})

            if action == "close":
                ok = _emu.close_session(session_id)
                if not ok:
                    return _j({"ok": False, "kind": "unknown_session",
                               "error": f"close: no session {session_id!r}",
                               "session_id": session_id, "closed": False})
                return _j({"ok": True, "session_id": session_id,
                           "closed": True})

            # All other actions need a live session.
            try:
                s = _emu.get_session(session_id)
            except KeyError as exc:
                return _j({"ok": False, "kind": "no_session",
                           "error": str(exc),
                           "hint": "create one with emulate_manage(action='create')"})

            if action == "load_shellcode":
                data = b""
                if bytes_hex:
                    try:
                        data = bytes.fromhex(bytes_hex.replace(" ", "").replace(",", ""))
                    except ValueError as exc:
                        return _j({"ok": False, "kind": "bad_arg",
                                   "error": f"bytes_hex: {exc}"})
                elif code:
                    from ...codegen import assemble as _asm, AssembleError
                    try:
                        entry_i = _addr(entry, "entry") if entry else 0
                        data, _cnt, _lbls = _asm(code, arch,
                                                   address=entry_i)
                    except AssembleError as exc:
                        return _j({"ok": False, "kind": exc.kind,
                                   "error": str(exc)})
                    except Exception as exc:
                        return _codegen_extra_err(exc)
                elif path:
                    try:
                        from pathlib import Path
                        data = Path(path).read_bytes()
                    except Exception as exc:
                        return _j({"ok": False, "kind": "read_failed",
                                   "error": f"path: {exc}"})
                else:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "load_shellcode: supply bytes_hex, code, or path"})
                entry_i = _addr(entry, "entry") if entry else 0
                try:
                    ep = s.engine.load_shellcode(data, entry_i)
                except Exception as exc:
                    return _j({"ok": False, "kind": "load_failed",
                               "error": f"load_shellcode: {exc}"})
                s.cursor = ep
                return _j_hex({"ok": True, "entry": ep, "size": len(data)})

            if action == "load_pe":
                if not path:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "load_pe: `path` required"})
                try:
                    ep = s.engine.load_pe(path, cmdline=cmdline,
                                            image_base=_addr(image_base, "image_base"))
                except Exception as exc:
                    return _j({"ok": False, "kind": "load_failed",
                               "error": f"load_pe: {exc}"})
                s.cursor = ep
                return _j_hex({"ok": True, "entry": ep, "path": path})

            if action == "run":
                try:
                    result = await asyncio.to_thread(
                        s.engine.run,
                        until=_addr(until, "until") if until else 0,
                        max_ins=int(max_ins),
                        timeout_s=float(timeout_s),
                    )
                except Exception as exc:
                    return _j({"ok": False, "kind": "run_failed",
                               "error": f"run: {exc}"})
                if "end_ip" in result:
                    s.cursor = int(result["end_ip"])
                # Include the current register snapshot for the LLM to
                # avoid a second round trip.
                try:
                    result["final_regs"] = s.engine.read_regs()
                except Exception:
                    result["final_regs"] = {}
                return _j_hex({"ok": True, **result})

            if action == "step":
                try:
                    result = await asyncio.to_thread(
                        s.engine.step, int(n or 1))
                except Exception as exc:
                    return _j({"ok": False, "kind": "step_failed",
                               "error": f"step: {exc}"})
                if "end_ip" in result:
                    s.cursor = int(result["end_ip"])
                result["final_regs"] = s.engine.read_regs()
                return _j_hex({"ok": True, **result})

            if action == "regs":
                return _j_hex({"ok": True, "regs": s.engine.read_regs()})

            if action == "set_regs":
                try:
                    payload = json.loads(regs_json)
                    if not isinstance(payload, dict):
                        raise ValueError("regs_json must be a JSON object")
                    s.engine.write_regs(payload)
                except Exception as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"set_regs: {exc}"})
                return _j_hex({"ok": True, "regs": s.engine.read_regs()})

            if action == "mem_read":
                addr_i = _addr(address, "address")
                n_bytes = int(size or 16)
                try:
                    blob = s.engine.mem_read(addr_i, n_bytes)
                except Exception as exc:
                    return _j({"ok": False, "kind": "mem_read_failed",
                               "error": f"mem_read: {exc}"})
                return _j_hex({"ok": True, "address": addr_i,
                                "size": len(blob),
                                "bytes_hex": blob.hex()})

            if action == "mem_write":
                addr_i = _addr(address, "address")
                if not bytes_hex:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": "mem_write: bytes_hex required"})
                try:
                    data = bytes.fromhex(bytes_hex.replace(" ", "").replace(",", ""))
                except ValueError as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"bytes_hex: {exc}"})
                try:
                    written = s.engine.mem_write(addr_i, data)
                except Exception as exc:
                    return _j({"ok": False, "kind": "mem_write_failed",
                               "error": f"mem_write: {exc}"})
                return _j_hex({"ok": True, "address": addr_i,
                                "written": written})

            if action == "map":
                addr_i = _addr(address, "address")
                try:
                    s.engine.mem_map(addr_i, int(size or 0x1000),
                                       prot=prot, label=label)
                except Exception as exc:
                    return _j({"ok": False, "kind": "map_failed",
                               "error": f"map: {exc}"})
                return _j_hex({"ok": True, "address": addr_i,
                                "size": int(size or 0x1000),
                                "prot": prot, "label": label})

            if action == "unmap":
                addr_i = _addr(address, "address")
                try:
                    s.engine.mem_unmap(addr_i, int(size or 0x1000))
                except Exception as exc:
                    return _j({"ok": False, "kind": "unmap_failed",
                               "error": f"unmap: {exc}"})
                return _j_hex({"ok": True, "address": addr_i,
                                "size": int(size or 0x1000)})

            if action == "hook_add":
                spec: dict[str, Any] = {"kind": kind, "on": on,
                                          "action": hook_action}
                if kind == "api":
                    spec["api"] = api
                if kind == "addr":
                    spec["address"] = address
                if hook_action == "return":
                    spec["return_value"] = return_value
                try:
                    hid = s.engine.add_hook(spec)
                except Exception as exc:
                    return _j({"ok": False, "kind": "hook_failed",
                               "error": f"hook_add: {exc}"})
                return _j({"ok": True, "hook_id": hid,
                           "spec": {k: (str(v) if not isinstance(v, (int, str, bool)) else v)
                                    for k, v in spec.items()}})

            if action == "hook_remove":
                ok = s.engine.remove_hook(hook_id)
                if not ok:
                    return _j({"ok": False, "kind": "unknown_hook",
                               "error": f"hook_remove: no hook_id {hook_id!r}",
                               "hook_id": hook_id, "removed": False})
                return _j({"ok": True, "hook_id": hook_id, "removed": True})

            if action == "snapshot":
                try:
                    snap = s.engine.snapshot()
                except NotImplementedError as exc:
                    return _j({"ok": False, "kind": "not_supported",
                               "error": str(exc),
                               "hint": "engine=unicorn supports snapshots today"})
                except Exception as exc:
                    return _j({"ok": False, "kind": "snapshot_failed",
                               "error": f"snapshot: {exc}"})
                sid = s.add_snapshot(snap, label=label)
                return _j({"ok": True, "snap_id": sid, "label": label})

            if action == "restore":
                snap = s.snapshots.get(snap_id)
                if snap is None:
                    return _j({"ok": False, "kind": "no_snapshot",
                               "error": f"restore: no snapshot {snap_id!r}"})
                try:
                    s.engine.restore(snap)
                except NotImplementedError as exc:
                    return _j({"ok": False, "kind": "not_supported",
                               "error": str(exc)})
                except Exception as exc:
                    return _j({"ok": False, "kind": "restore_failed",
                               "error": f"restore: {exc}"})
                return _j({"ok": True, "snap_id": snap_id,
                           "regs": s.engine.read_regs()})

            if action == "seed_from_target":
                try:
                    regions = json.loads(regions_json)
                    if not isinstance(regions, list):
                        raise ValueError("regions_json must be a JSON array")
                except Exception as exc:
                    return _j({"ok": False, "kind": "bad_arg",
                               "error": f"regions_json: {exc}"})
                try:
                    c = ctx.session.require_client(target or view)
                except Exception as exc:
                    return _j({"ok": False, "kind": "no_target",
                               "error": f"seed_from_target: {exc}",
                               "hint": "target_manage(action='connect') first"})
                try:
                    result = await _emu.seed_from_target(
                        s, client=c,
                        view=view, pid=pid, tid=tid,
                        regions=regions,
                    )
                except Exception as exc:
                    return _j({"ok": False, "kind": "seed_failed",
                               "error": f"seed_from_target: {exc}"})
                return _j_hex(result)

            return _unknown_action("emulate_manage", action, EMU_ACTIONS, _EMU_ACTION_HELP)

        return await _guard_pure(ctx, "emulate_manage", action, args, run)
