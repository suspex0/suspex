"""Integer types, aliases, parser, and int-to-int / int-to-bytes casts."""

from __future__ import annotations

import re
from typing import Any

from .errors import ConversionError

# ---------------------------------------------------------------------------
# Type namespace
# ---------------------------------------------------------------------------

# Integer widths in bytes. Two's-complement for i*, unsigned for u*.
INT_TYPES: dict[str, tuple[int, bool]] = {
    "u8": (1, False), "u16": (2, False), "u32": (4, False), "u64": (8, False),
    "i8": (1, True), "i16": (2, True), "i32": (4, True), "i64": (8, True),
}

# Aliases resolve to canonical integer names.
INT_ALIASES: dict[str, str] = {
    "uint8": "u8", "byte": "u8", "sbyte": "i8", "int8": "i8",
    "uint16": "u16", "word": "u16", "short": "i16", "int16": "i16",
    "uint32": "u32", "dword": "u32", "long": "i32", "int32": "i32", "int": "i32",
    "uint64": "u64", "qword": "u64", "longlong": "i64", "int64": "i64",
    "ulong64": "u64",
    "boolean": "bool",
}

FLOAT_TYPES: set[str] = {"f32", "f64"}
FLOAT_ALIASES: dict[str, str] = {"float": "f32", "single": "f32", "double": "f64"}

# Text codecs the parser will accept via `str_convert`. Values are Python's
# canonical codec names.
TEXT_CODECS: dict[str, str] = {
    "utf-8": "utf-8", "utf8": "utf-8",
    "utf-16": "utf-16", "utf16": "utf-16",
    "utf-16-le": "utf-16-le", "utf16le": "utf-16-le", "utf-16le": "utf-16-le",
    "utf-16-be": "utf-16-be", "utf16be": "utf-16-be", "utf-16be": "utf-16-be",
    "utf-32-le": "utf-32-le", "utf32le": "utf-32-le",
    "utf-32-be": "utf-32-be", "utf32be": "utf-32-be",
    "ascii": "ascii",
    "latin-1": "latin-1", "latin1": "latin-1", "iso-8859-1": "latin-1",
    "cp1252": "cp1252", "windows-1252": "cp1252",
    "mbcs": "mbcs", "cp437": "cp437", "cp850": "cp850",
    "shift_jis": "shift_jis", "sjis": "shift_jis",
    "gbk": "gbk", "gb2312": "gb2312",
    "euc-kr": "euc-kr",
    "big5": "big5",
}

# Transfer encodings (bytes <-> printable text).
BYTE_ENCODINGS: set[str] = {
    "base64", "base64url", "base64_url", "b64",
    "base32", "b32", "base32hex",
    "base16", "b16", "hex", "hex-upper", "hex_upper", "hex-spaced", "hex_spaced",
    "hex-c-array", "hex_c_array", "c-array",
    "base85", "b85", "ascii85", "a85",
    "url", "urlsafe", "percent",
    "quoted-printable", "quoted_printable", "qp",
    "rot13",
}

HASH_ALGOS: set[str] = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3-224", "sha3_224", "sha3-256", "sha3_256",
    "sha3-384", "sha3_384", "sha3-512", "sha3_512",
    "blake2b", "blake2s",
    "crc32", "adler32",
    "xxh64", "xxh32",
}

TIME_TYPES: set[str] = {
    "filetime", "unix_epoch", "unix", "unix_ms", "unix_us",
    "systemtime", "iso8601", "iso",
}

GUID_TYPES: set[str] = {"guid_str", "guid_le", "guid_windows", "uuid"}


def canonicalize_type(t: str) -> str:
    """Fold aliases to a canonical name. Case-insensitive."""
    if not isinstance(t, str) or not t:
        raise ConversionError("unknown_type", "type is empty",
                              hint="pass a type from the type namespace, e.g. u32 or utf-8")
    key = t.strip().lower()
    if key in INT_TYPES or key in FLOAT_TYPES:
        return key
    if key in INT_ALIASES:
        return INT_ALIASES[key]
    if key in FLOAT_ALIASES:
        return FLOAT_ALIASES[key]
    if key in TEXT_CODECS:
        return TEXT_CODECS[key]
    if key in BYTE_ENCODINGS:
        # Normalize the encoding names to a single spelling.
        return {
            "b64": "base64", "base64_url": "base64url",
            "b32": "base32", "b16": "base16",
            "hex_upper": "hex-upper", "hex_spaced": "hex-spaced",
            "hex_c_array": "hex-c-array", "c-array": "hex-c-array",
            "b85": "base85", "a85": "ascii85",
            "urlsafe": "url", "percent": "url",
            "quoted_printable": "quoted-printable", "qp": "quoted-printable",
        }.get(key, key)
    if key in HASH_ALGOS:
        return key.replace("_", "-")
    if key in TIME_TYPES:
        return "iso8601" if key == "iso" else ("unix_epoch" if key == "unix" else key)
    if key in GUID_TYPES:
        return "guid_str" if key == "uuid" else key
    if key in {"bool", "bit", "char", "wchar", "bytes", "hex-bytes", "blob"}:
        return "bytes" if key in {"hex-bytes", "blob"} else key
    raise ConversionError(
        "unknown_type",
        f"unknown type {t!r}",
        hint=("expected one of: u8/u16/u32/u64, i8/i16/i32/i64, f32/f64, bytes, "
              "bool, char, wchar, a text codec (utf-8, utf-16-le, cp1252, …), "
              "an encoding (base64, base64url, base32, base85, hex, url, "
              "quoted-printable, rot13), a hash (md5, sha1, sha256, blake2b, "
              "crc32, adler32, xxh64), a time (filetime, unix_epoch, unix_ms, "
              "systemtime, iso8601), or a guid (guid_str, guid_le, guid_windows)"),
    )


# ---------------------------------------------------------------------------
# Value parser
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F_]+$")
_BIN_RE = re.compile(r"^[+-]?0[bB][01_]+$")
_OCT_RE = re.compile(r"^[+-]?0[oO][0-7_]+$")
_HEX_SUFFIX = re.compile(r"^[+-]?[0-9a-fA-F_]+[hH]$")
_BIN_SUFFIX = re.compile(r"^[+-]?[01_]+[bB]$")


def parse_int(value: Any) -> int:
    """Parse an integer from a variety of user-friendly forms.

    Accepts: int, "123", "-42", "0xDEAD", "1_000_000", "1010b", "FFh", "0o777".
    Rejects floats — use parse_float for those.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ConversionError(
            "unparseable_value",
            f"got float {value!r} but expected an integer",
            hint="use from_type=f32/f64 for floats, or pass an integer literal",
        )
    if not isinstance(value, str):
        raise ConversionError(
            "unparseable_value",
            f"cannot parse {type(value).__name__} as integer",
            hint="pass an int or a str like '0xDEAD' / '123' / '1010b'",
        )
    s = value.strip().replace(" ", "")
    if not s:
        return 0
    try:
        if _HEX_RE.match(s):
            return int(s.replace("_", ""), 16)
        if _BIN_RE.match(s):
            return int(s.replace("_", ""), 2)
        if _OCT_RE.match(s):
            return int(s.replace("_", ""), 8)
        if _HEX_SUFFIX.match(s):
            core = s[:-1].replace("_", "")
            sign = 1
            if core.startswith(("+", "-")):
                sign = -1 if core.startswith("-") else 1
                core = core[1:]
            return sign * int(core, 16)
        if _BIN_SUFFIX.match(s):
            core = s[:-1].replace("_", "")
            sign = 1
            if core.startswith(("+", "-")):
                sign = -1 if core.startswith("-") else 1
                core = core[1:]
            return sign * int(core, 2)
        return int(s.replace("_", ""), 10)
    except ValueError as exc:
        raise ConversionError(
            "unparseable_value",
            f"{value!r} is not a valid integer",
            hint="try '0x...' for hex, plain digits for decimal, '0b...' for binary",
        ) from exc


# ---------------------------------------------------------------------------
# Int helpers / int casts
# ---------------------------------------------------------------------------


def _int_bounds(width: int, signed: bool) -> tuple[int, int]:
    if signed:
        n = 1 << (width * 8 - 1)
        return -n, n - 1
    return 0, (1 << (width * 8)) - 1


def _mask(width: int) -> int:
    return (1 << (width * 8)) - 1


def _to_signed(v: int, width: int) -> int:
    m = _mask(width)
    v &= m
    sign = 1 << (width * 8 - 1)
    return v - (m + 1) if v & sign else v


def cast_int_to_int(value: int, from_type: str, to_type: str) -> dict[str, Any]:
    src_w, src_signed = INT_TYPES[from_type]
    dst_w, dst_signed = INT_TYPES[to_type]

    # Normalize the input against its declared type first, so a caller passing
    # -1 as u8 becomes 0xFF (lossless if they truly meant a bit pattern) — with
    # notes.normalized_input reporting the coercion.
    normalized = value & _mask(src_w)
    signed_input = _to_signed(normalized, src_w) if src_signed else normalized
    input_lo, input_hi = _int_bounds(src_w, src_signed)
    fits_input = input_lo <= value <= input_hi
    truncated_bits = 0
    if src_w > dst_w:
        # Truncating: keep the low dst_w bytes.
        low = normalized & _mask(dst_w)
        truncated_bits = (src_w - dst_w) * 8
        out_raw = low
    else:
        # Zero/sign extending: if source was signed, sign-extend; else zero.
        if src_signed:
            out_raw = signed_input & _mask(dst_w)
        else:
            out_raw = normalized  # zero-extend by definition (Python int is unbounded)
    out_value = _to_signed(out_raw, dst_w) if dst_signed else out_raw
    lossless = fits_input and (src_w <= dst_w) and (
        (src_signed == dst_signed)
        or (src_signed and not dst_signed and signed_input >= 0)
        or (not src_signed and dst_signed and normalized <= _int_bounds(dst_w, True)[1])
    )
    return {
        "value": out_value,
        "hex": f"0x{out_raw:0{dst_w*2}X}",
        "type": to_type,
        "notes": {
            "lossless": lossless,
            "truncated_bits": truncated_bits,
            "sign_change": (out_value < 0) != (signed_input < 0),
            "would_be_signed": _to_signed(out_raw, dst_w),
            "would_be_unsigned": out_raw,
            "input_fits_source_type": fits_input,
            "input_normalized": normalized,
        },
    }


def cast_int_to_bytes(value: int, from_type: str, endian: str) -> dict[str, Any]:
    src_w, src_signed = INT_TYPES[from_type]
    normalized = value & _mask(src_w)
    raw = normalized.to_bytes(src_w, "little" if endian == "little" else "big",
                              signed=False)
    return {
        "hex": raw.hex(),
        "value": list(raw),
        "type": "bytes",
        "endian": endian,
        "length": src_w,
        "notes": {"lossless": True},
    }
