"""Value tool registration for the suspex0 MCP server.

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

from .. import value_ops as _value_ops  # noqa: E402 — after star-import shim

# v0.22: module-level so the lazy action-enum annotation resolves.
VALUE_MANAGE_ACTIONS = list(_value_ops.VALUE_MANAGE_ACTIONS) + ["actions"]


def register(mcp, ctx: Context) -> None:
    """Register the ``value_manage`` tool on *mcp*, using *ctx* for state."""
    # ---------------------------------------------------------- value_manage --
    #
    # Pure-compute cast / encode / hash / decode / err_lookup surface plus
    # the v0.17.1 additions `eval` (safe AST-whitelist expression evaluator
    # for programmer arithmetic) and `constants` (named-constant registry).
    # Was `type_convert` through v0.17.0; the alias was removed in v0.17.1.

    _VALUE_ACTION_HELP = {
        "actions": {"one_liner": "this list — per-verb help",
                    "key_args": "none",
                    "example": "value_manage(action='actions')"},
        "cast": {"one_liner": "reinterpret a value across int/float types "
                              "(width truncate, sign-extend, bitcasts)",
                 "key_args": "value, from_type, to_type",
                 "example": "value_manage(action='cast', value=0xFFFFFFFE, "
                            "from_type='u32', to_type='i32')"},
        "views": {"one_liner": "one value -> dec/hex/bin/bytes/ascii "
                               "renderings + auto err_lookup",
                  "key_args": "value",
                  "example": "value_manage(action='views', value='0xC0000022')"},
        "pack": {"one_liner": "value -> LE/BE hex bytes",
                 "key_args": "value, width, endian",
                 "example": "value_manage(action='pack', value=0x4141, "
                            "width=64)"},
        "unpack": {"one_liner": "hex bytes -> value under type+endian",
                   "key_args": "data_hex, to_type, endian",
                   "example": "value_manage(action='unpack', "
                              "data_hex='4141', to_type='u16')"},
        "swap": {"one_liner": "endian swap a 2/4/8-byte int",
                 "key_args": "value, width",
                 "example": "value_manage(action='swap', value=0xDEADBEEF, "
                            "width=32)"},
        "split": {"one_liner": "QWORD -> {hi,lo}; or bytes -> chunk array",
                  "key_args": "value | data_hex, width",
                  "example": "value_manage(action='split', "
                             "value='0xDEADBEEFCAFEBABE')"},
        "join": {"one_liner": "concatenate parts_json list into one "
                              "int/bytes",
                 "key_args": "parts_json, width",
                 "example": "value_manage(action='join', "
                            "parts_json='[\"0x4141\",\"0x4242\"]', width=32)"},
        "bits": {"one_liner": "decode a bitmask against a preset or "
                              "names_json map",
                 "key_args": "value, preset | names_json",
                 "example": "value_manage(action='bits', value=0x40, "
                            "preset='page_protect')"},
        "err_lookup": {"one_liner": "Win32/NTSTATUS/HRESULT -> symbol + "
                                    "facility decomposition",
                       "key_args": "value, space",
                       "example": "value_manage(action='err_lookup', "
                                  "value='0xC0000022')"},
        "time": {"one_liner": "filetime <-> iso8601 <-> unix_epoch/ms/us "
                              "conversions",
                 "key_args": "value, from_type, to_type",
                 "example": "value_manage(action='time', value=133000000000000000, "
                            "from_type='filetime', to_type='iso8601')"},
        "guid": {"one_liner": "GUID string <-> bytes_le <-> bytes_windows",
                 "key_args": "value, from_type, to_type",
                 "example": "value_manage(action='guid', "
                            "value='{00000000-0000-0000-0000-000000000000}')"},
        "encode": {"one_liner": "bytes -> text encoding (base64, hex, "
                                "c-array, url, rot13, ...)",
                   "key_args": "data_hex, to_type, wrap, pad",
                   "example": "value_manage(action='encode', data_hex='41424344', "
                              "to_type='base64')"},
        "decode": {"one_liner": "encoded text -> bytes + utf8 preview",
                   "key_args": "value, from_type",
                   "example": "value_manage(action='decode', value='QUJD', "
                              "from_type='base64')"},
        "str_convert": {"one_liner": "bytes <-> str across text codecs "
                                     "(utf-8/16/32, mbcs, cp1252, ...)",
                        "key_args": "value|data_hex, from_type, to_type, "
                                    "errors, strip_nul",
                        "example": "value_manage(action='str_convert', "
                                   "data_hex='41004200', from_type='bytes', "
                                   "to_type='utf-16-le')"},
        "hash": {"one_liner": "md5/sha*/sha3/blake2/crc32/adler32 digest "
                              "(hmac_key_hex for HMAC)",
                 "key_args": "data_hex|value, preset",
                 "example": "value_manage(action='hash', data_hex='90', "
                            "preset='sha256')"},
        "eval": {"one_liner": "safe AST-whitelist expression evaluator for "
                              "programmer arithmetic",
                 "key_args": "expr, env_json, width, signed",
                 "example": "value_manage(action='eval', "
                            "expr='align_up(0x1234, 0x1000)')"},
        "constants": {"one_liner": "enumerate the named-constant registry "
                                   "eval resolves",
                      "key_args": "category",
                      "example": "value_manage(action='constants')"},
        "ioctl_decode": {"one_liner": "u32 CTL_CODE -> device_type/"
                                      "function/method/access fields",
                         "key_args": "value",
                         "example": "value_manage(action='ioctl_decode', "
                                    "value='0x222003')"},
        "ioctl_encode": {"one_liner": "device_type/function/method/access "
                                      "-> assembled CTL_CODE",
                         "key_args": "device_type, function, method, access",
                         "example": "value_manage(action='ioctl_encode', "
                                    "device_type='FILE_DEVICE_UNKNOWN', "
                                    "function='0x800', method='METHOD_BUFFERED', "
                                    "access='FILE_ANY_ACCESS')"},
    }

    @mcp.tool(annotations=READONLY_TRUE, output_schema=None)
    async def value_manage(action: Annotated[str, Field(json_schema_extra={"enum": VALUE_MANAGE_ACTIONS})],
                           value: Any = "",
                           from_type: str = "",
                           to_type: str = "",
                           endian: str = "little",
                           width: int = 0,
                           count: int = 0,
                           data_hex: str = "",
                           preset: str = "",
                           names_json: str = "",
                           parts_json: str = "",
                           wrap: int = 0,
                           pad: bool = True,
                           errors: str = "strict",
                           strip_nul: bool = False,
                           hmac_key_hex: str = "",
                           salt_hex: str = "",
                           form: str = "string",
                           space: str = "auto",
                           width_hint: str = "u64",
                           expr: str = "",
                           env_json: str = "",
                           signed: bool = False,
                           as_hex: bool = True,
                           mod_wrap: bool = False,
                           category: str = "",
                           device_type: str = "",
                           function: str = "",
                           method: str = "",
                           access: str = "") -> str:
        """Pure-compute value operations for RE workflows: cast, views,
        pack/unpack, bits, err_lookup, time, guid, encode/decode,
        str_convert, hash, eval, constants, ioctl_decode/encode.
        Target-less: no agent, no driver, no side effects.

        **Never compute values in your head — always delegate to this
        tool.** LLMs mis-carry hex nibbles, drop sign bits, and mis-shift
        often enough that mental math is a reliability liability.

        Per-verb help: value_manage(action='actions')."""
        args = {"action": action, "from_type": from_type, "to_type": to_type}

        async def run() -> Any:
            if action not in VALUE_MANAGE_ACTIONS:
                return _unknown_action(
                    "value_manage", action, VALUE_MANAGE_ACTIONS,
                    _VALUE_ACTION_HELP)
            if action == "actions":
                return _actions_help("value_manage", _VALUE_ACTION_HELP)

            cap_err = _value_ops.check_input_caps(value, data_hex)
            if cap_err is not None:
                return cap_err

            env_map: dict[str, Any] = {}
            if env_json:
                try:
                    parsed = json.loads(env_json)
                except json.JSONDecodeError as exc:
                    from .. import conversions as _cv_err
                    raise _cv_err.ConversionError(
                        "unparseable_value",
                        f"env_json is not valid JSON: {exc}",
                        hint="pass env_json='{\"BASE\": \"0x1000\", \"SIZE\": 4096}'")
                if not isinstance(parsed, dict):
                    from .. import conversions as _cv_err
                    raise _cv_err.ConversionError(
                        "unparseable_value",
                        "env_json must decode to a JSON object",
                        hint="pass env_json='{\"NAME\": value, ...}'")
                env_map = parsed

            from .. import conversions as _cv
            approx = _value_ops.estimate_bytes(value, data_hex)
            heavy = (action in _value_ops.HEAVY_ACTIONS
                     and approx >= _cv.THREAD_OFFLOAD_BYTES)

            def _do() -> Any:
                return _value_ops.dispatch(
                    action,
                    value=value, from_type=from_type, to_type=to_type,
                    endian=endian, width=width, count=count,
                    data_hex=data_hex, preset=preset,
                    names_json=names_json, parts_json=parts_json,
                    wrap=wrap, pad=pad, errors=errors, strip_nul=strip_nul,
                    hmac_key_hex=hmac_key_hex, salt_hex=salt_hex,
                    form=form, space=space, width_hint=width_hint,
                    expr=expr, env=env_map, signed=signed, as_hex=as_hex,
                    mod_wrap=mod_wrap, category=category,
                    device_type=device_type, function=function,
                    method=method, access=access,
                )

            if heavy:
                return await asyncio.to_thread(_do)
            return _do()

        return await _guard_pure(ctx, "value_manage", action, args, run)
