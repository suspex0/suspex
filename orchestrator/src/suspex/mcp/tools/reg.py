"""Reg tool registration for the suspex0 MCP server.

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
REG_ACTIONS = ["get", "set", "enum", "delete", "actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``reg_manage`` tool on *mcp*, using *ctx* for state."""
    # ---------------------------------------------------------------- reg_manage --

    _REG_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "reg_manage(action='actions')"},
        "get": {"one_liner": "read a registry value (shape per REG_ type)",
                "key_args": "hive, subkey, value, wow64_32, raw_hex",
                "example": "reg_manage(action='get', subkey='SYSTEM\\\\"
                           "CurrentControlSet\\\\Services\\\\X', value='Start')"},
        "set": {"one_liner": "write a registry value (string/dword/qword/"
                             "binary/multi_sz)",
                "key_args": "hive, subkey, value, reg_type, data_str/"
                            "data_hex/data_dword, wow64_32, create_subkey",
                "example": "reg_manage(action='set', subkey='...', value='V', "
                           "reg_type='REG_DWORD', data_dword=1)"},
        "enum": {"one_liner": "list child subkeys + value metadata",
                 "key_args": "hive, subkey, recursive, want_subkeys, want_values",
                 "example": "reg_manage(action='enum', subkey='SYSTEM\\\\"
                            "CurrentControlSet\\\\Services')"},
        "delete": {"one_liner": "delete a value (value=) or subkey "
                                "(value='' + recursive for trees)",
                   "key_args": "hive, subkey, value, recursive",
                   "example": "reg_manage(action='delete', subkey='...', "
                              "value='V')"},
    }
    REG_TYPES = {  # names accepted for the `type` field of `set`
        "REG_NONE": 0, "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3,
        "REG_DWORD": 4, "REG_DWORD_BIG_ENDIAN": 5, "REG_LINK": 6,
        "REG_MULTI_SZ": 7, "REG_QWORD": 11,
    }

    @mcp.tool(annotations=READONLY_FALSE, output_schema=None)
    async def reg_manage(action: Annotated[str, Field(json_schema_extra={"enum": REG_ACTIONS})],
                         hive: str = "HKLM", subkey: str = "",
                         value: str = "", reg_type: str = "REG_SZ",
                         data_str: str = "", data_hex: str = "",
                         data_dword: int = 0,
                         wow64_32: bool = False, create_subkey: bool = False,
                         recursive: bool = False,
                         want_subkeys: bool = True, want_values: bool = True,
                         impersonate: str = "",
                         # v0.17 A-3: opt-in wide response for `get`.
                         raw_hex: bool = False,
                         # v0.14 unified paging (Layer 3)
                         limit: int = 0,
                         offset: int = 0,
                         cursor: str = "",
                         verbosity: str = "normal",
                         fields: list[str] | None = None,
                         filter: Any = "",
                         summary: bool = False,
                         name: str = "") -> str:
        """Windows registry read/write via the target agent (get/set/
        delete/enum). hive= HKLM|HKCU|HKCR|HKU|HKCC; wow64_32 for the
        32-bit view; raw_hex=true returns every rendering. Per-verb
        help: reg_manage(action='actions')."""
        args = {"action": action, "hive": hive, "subkey": subkey, "value": value,
                # Forward verbosity so finalize honors it (enum row-collapse
                # opt-out via full/raw).
                "verbosity": verbosity}

        async def run() -> str:
            if action not in REG_ACTIONS:
                return _unknown_action("reg_manage", action, REG_ACTIONS, _REG_ACTION_HELP)
            if action == "actions":
                return _actions_help("reg_manage", _REG_ACTION_HELP)
            c = ctx.session.require_client(name)
            if action == "get":
                return _j(await c.reg_get(hive, subkey, value,
                                           wow64_32=wow64_32,
                                           impersonate=impersonate,
                                           raw_hex=raw_hex))
            if action == "enum":
                res = await c.reg_enum(hive, subkey, wow64_32=wow64_32,
                                        want_subkeys=want_subkeys,
                                        want_values=want_values,
                                        impersonate=impersonate)
                vals = list(res.get("values") or [])
                subs = list(res.get("subkeys") or [])
                return _list_envelope(
                    vals, tool="reg_manage", action="enum", kind="reg_enum",
                    limit=limit, offset=offset,
                    fields=fields or (),
                    filter=filter,
                    summary=summary,
                    global_cap=ctx.cfg.mcp_max_items(),
                    extras={"subkeys": subs},
                )
            if action == "delete":
                return _j(await c.reg_delete(hive, subkey, value=value,
                                              recursive=recursive,
                                              wow64_32=wow64_32,
                                              impersonate=impersonate))
            # set: shape the wire buffer from whichever data_* was set.
            rt_num = REG_TYPES.get(reg_type)
            if rt_num is None:
                try:
                    rt_num = int(reg_type, 0)
                except ValueError:
                    return _j({"ok": False,
                               "error": f"reg_manage set: unknown type {reg_type!r}; "
                                        "expected one of "
                                        + ", ".join(sorted(REG_TYPES))})
            if data_hex:
                payload = bytes.fromhex(data_hex)
            elif rt_num in (4, 5):  # REG_DWORD / REG_DWORD_BE
                payload = int(data_dword).to_bytes(4, "little" if rt_num == 4 else "big")
            elif rt_num == 11:  # REG_QWORD
                payload = int(data_dword).to_bytes(8, "little")
            elif rt_num in (1, 2):  # REG_SZ / REG_EXPAND_SZ -> UTF-16LE + NUL
                payload = (data_str + "\x00").encode("utf-16-le")
            elif rt_num == 7:  # REG_MULTI_SZ -> lines separated by "\n"
                lines = data_str.split("\n") if data_str else []
                joined = "".join(s + "\x00" for s in lines) + "\x00"
                payload = joined.encode("utf-16-le")
            else:
                payload = data_str.encode("utf-8")
            return _j(await c.reg_set(hive, subkey, value, rt_num, payload,
                                       wow64_32=wow64_32,
                                       create_subkey=create_subkey,
                                       impersonate=impersonate))

        return await _guard(ctx, "reg_manage", action, args, run)
