"""Pure conversion primitives — the compute half of the `value_manage`
MCP tool (was `type_convert` through v0.17.0).

Every function here is:
  * pure — no I/O, no globals, no thread state
  * fast — microsecond-scale for typical (<= 4 KiB) inputs
  * total — raises ConversionError with a `kind` on bad input; never asserts
  * lossless-when-possible — announces truncation/sign-change in the notes dict

Async offload is a caller concern (tools.py wraps heavy calls in
asyncio.to_thread). Nothing here touches the event loop.
"""

from __future__ import annotations

from .bits import BIT_PRESETS, decode_bits, lookup_err
from .buffer_decode import (
    _DECODE_ARRAY_RE,
    _DECODE_FMT,
    _expand_spec,
    _find_wstr_term,
    decode_buffer,
    decode_typed_buffer,
)
from .errors import ConversionError
from .floats import (
    cast_float_to_float,
    cast_float_to_int,
    cast_int_to_float,
    parse_float,
)
from .guid import _bytes_from_guid_windows, _guid_windows_from_bytes, guid_convert
from .hashing import THREAD_OFFLOAD_BYTES, hash_bytes
from .ioctl import decode_ctl_code, encode_ctl_code
from .ints import (
    BYTE_ENCODINGS,
    FLOAT_ALIASES,
    FLOAT_TYPES,
    GUID_TYPES,
    HASH_ALGOS,
    INT_ALIASES,
    INT_TYPES,
    TEXT_CODECS,
    TIME_TYPES,
    _BIN_RE,
    _BIN_SUFFIX,
    _HEX_RE,
    _HEX_SUFFIX,
    _OCT_RE,
    _int_bounds,
    _mask,
    _to_signed,
    canonicalize_type,
    cast_int_to_bytes,
    cast_int_to_int,
    parse_int,
)
from .pack import (
    cast_bytes_to_int,
    do_cast,
    do_join,
    do_pack,
    do_split,
    do_swap,
    do_unpack,
    parse_hex_bytes,
    views,
)
from .str_encode import (
    _quopri_decode,
    _quopri_encode,
    _rot13,
    _urldecode,
    _urlencode,
    _wrap,
    decode_text,
    encode_bytes,
    str_convert,
)
from .time_conv import (
    FILETIME_EPOCH,
    UNIX_EPOCH,
    _dt_to_filetime,
    _dt_to_systemtime,
    _filetime_to_dt,
    _systemtime_from_hex,
    time_convert,
)

__all__ = [
    "BIT_PRESETS",
    "BYTE_ENCODINGS",
    "ConversionError",
    "FILETIME_EPOCH",
    "FLOAT_ALIASES",
    "FLOAT_TYPES",
    "GUID_TYPES",
    "HASH_ALGOS",
    "INT_ALIASES",
    "INT_TYPES",
    "TEXT_CODECS",
    "THREAD_OFFLOAD_BYTES",
    "TIME_TYPES",
    "UNIX_EPOCH",
    "canonicalize_type",
    "cast_bytes_to_int",
    "cast_float_to_float",
    "cast_float_to_int",
    "cast_int_to_bytes",
    "cast_int_to_float",
    "cast_int_to_int",
    "decode_bits",
    "decode_buffer",
    "decode_ctl_code",
    "decode_typed_buffer",
    "decode_text",
    "do_cast",
    "do_join",
    "do_pack",
    "do_split",
    "do_swap",
    "do_unpack",
    "encode_bytes",
    "encode_ctl_code",
    "guid_convert",
    "hash_bytes",
    "lookup_err",
    "parse_float",
    "parse_hex_bytes",
    "parse_int",
    "str_convert",
    "time_convert",
    "views",
]
