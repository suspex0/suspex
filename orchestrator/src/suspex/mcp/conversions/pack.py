"""Byte parsing, packing/unpacking, views, swap, split, join and the
top-level cast dispatcher."""

from __future__ import annotations

import re
import struct
from typing import Any

from ..error_maps import lookup as _err_lookup
from .errors import ConversionError
from .floats import (
    cast_float_to_float,
    cast_float_to_int,
    cast_int_to_float,
    parse_float,
)
from .ints import (
    FLOAT_TYPES,
    INT_TYPES,
    _mask,
    _to_signed,
    canonicalize_type,
    cast_int_to_bytes,
    cast_int_to_int,
    parse_int,
)


def parse_hex_bytes(value: Any) -> bytes:
    """Turn a hex-ish string into bytes. Accepts many separator styles."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise ConversionError(
            "unparseable_value",
            f"cannot parse {type(value).__name__} as byte string",
            hint="pass hex like '4D5A9000' or '4d 5a 90 00' or '0x4d,0x5a'",
        )
    s = value.strip()
    if not s:
        return b""
    # Normalize common separators and \x prefixes.
    s = re.sub(r"\\x", "", s, flags=re.IGNORECASE)
    s = re.sub(r"0x", "", s, flags=re.IGNORECASE)
    s = re.sub(r"[\s,;:_\-]", "", s)
    if len(s) % 2 != 0:
        raise ConversionError(
            "unparseable_value",
            f"hex byte string has odd length after normalization: {len(s)} chars",
            hint="every byte needs two hex digits; check for a truncated last byte",
        )
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ConversionError(
            "unparseable_value",
            f"{value!r} contains non-hex characters after normalization",
            hint="use only 0-9 a-f (case-insensitive), optional separators",
        ) from exc


def cast_bytes_to_int(data: bytes, to_type: str, endian: str) -> dict[str, Any]:
    dst_w, dst_signed = INT_TYPES[to_type]
    if len(data) < dst_w:
        # Zero-pad on the low end for the requested endian.
        pad = dst_w - len(data)
        if endian == "big":
            data = (b"\x00" * pad) + data
        else:
            data = data + (b"\x00" * pad)
    truncated = 0
    if len(data) > dst_w:
        truncated = (len(data) - dst_w) * 8
        data = data[:dst_w] if endian == "little" else data[-dst_w:]
    raw = int.from_bytes(data, "little" if endian == "little" else "big",
                         signed=False)
    out = _to_signed(raw, dst_w) if dst_signed else raw
    return {
        "value": out,
        "hex": f"0x{raw:0{dst_w*2}X}",
        "type": to_type,
        "endian": endian,
        "notes": {"lossless": truncated == 0, "truncated_bits": truncated},
    }


def do_cast(value: Any, from_type: str, to_type: str,
            endian: str = "little") -> dict[str, Any]:
    """Top-level cast dispatcher: handles every from/to combination."""
    endian = (endian or "little").lower()
    if endian not in {"little", "big"}:
        raise ConversionError("unknown_type", f"endian={endian!r} unrecognized",
                              hint="pass endian='little' or endian='big'")
    from_c = canonicalize_type(from_type)
    to_c = canonicalize_type(to_type)

    # int -> ...
    if from_c in INT_TYPES:
        ivalue = parse_int(value)
        if to_c in INT_TYPES:
            return cast_int_to_int(ivalue, from_c, to_c)
        if to_c in FLOAT_TYPES:
            return cast_int_to_float(ivalue, from_c, to_c)
        if to_c == "bytes":
            return cast_int_to_bytes(ivalue, from_c, endian)
        if to_c == "bool":
            return {"value": bool(ivalue), "type": "bool",
                    "notes": {"lossless": ivalue in (0, 1)}}
        raise ConversionError(
            "unknown_type",
            f"cannot cast int -> {to_type}",
            hint="int can cast to int / float / bytes / bool",
        )

    # float -> ...
    if from_c in FLOAT_TYPES:
        fvalue = parse_float(value)
        if to_c in INT_TYPES:
            return cast_float_to_int(fvalue, from_c, to_c)
        if to_c in FLOAT_TYPES:
            return cast_float_to_float(fvalue, from_c, to_c)
        if to_c == "bytes":
            fmt = "<f" if from_c == "f32" else "<d"
            if endian == "big":
                fmt = ">f" if from_c == "f32" else ">d"
            raw = struct.pack(fmt, fvalue)
            return {"hex": raw.hex(), "type": "bytes", "endian": endian,
                    "length": len(raw), "notes": {"lossless": True}}
        raise ConversionError(
            "unknown_type",
            f"cannot cast float -> {to_type}",
            hint="float can cast to int / float / bytes",
        )

    # bytes -> ...
    if from_c == "bytes":
        data = parse_hex_bytes(value)
        if to_c in INT_TYPES:
            return cast_bytes_to_int(data, to_c, endian)
        if to_c in FLOAT_TYPES:
            width = 4 if to_c == "f32" else 8
            if len(data) < width:
                data = data + (b"\x00" * (width - len(data))) if endian == "little" \
                    else (b"\x00" * (width - len(data))) + data
            if len(data) > width:
                data = data[:width] if endian == "little" else data[-width:]
            fmt = ("<f" if to_c == "f32" else "<d") if endian == "little" \
                else (">f" if to_c == "f32" else ">d")
            (fv,) = struct.unpack(fmt, data)
            return {"value": fv, "type": to_c, "endian": endian,
                    "notes": {"lossless": True, "kind": "bitcast"}}
        if to_c == "bytes":
            return {"hex": data.hex(), "type": "bytes", "length": len(data),
                    "notes": {"lossless": True, "kind": "identity"}}
        raise ConversionError(
            "unknown_type",
            f"cannot cast bytes -> {to_type}",
            hint="bytes cast to int/float bitcasts; text codecs live under str_convert",
        )

    if from_c == "bool":
        ivalue = 1 if parse_int(value) != 0 else 0
        return do_cast(ivalue, "u8", to_type, endian)

    raise ConversionError(
        "unknown_type",
        f"cannot cast from type {from_type!r}",
        hint="from_type must be an int/float/bytes/bool; for text or encodings "
             "use str_convert / encode / decode",
    )


def views(value: Any, width_hint: str = "u64") -> dict[str, Any]:
    """Turn a single value into every reasonable interpretation at once."""
    width_hint = canonicalize_type(width_hint)
    if width_hint not in INT_TYPES:
        raise ConversionError(
            "unknown_type",
            f"width_hint={width_hint!r} must be an integer type",
            hint="try width_hint='u32' or 'u64'",
        )
    width, _ = INT_TYPES[width_hint]
    iv = parse_int(value)
    normalized = iv & _mask(width)
    signed = _to_signed(normalized, width)
    packed_le = normalized.to_bytes(width, "little")
    packed_be = normalized.to_bytes(width, "big")

    def _size_iec(n: int) -> str:
        units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")
        f = float(n)
        i = 0
        while abs(f) >= 1024 and i < len(units) - 1:
            f /= 1024.0
            i += 1
        return f"{f:.3f} {units[i]}" if i > 0 else f"{n} B"

    def _size_si(n: int) -> str:
        units = ("B", "KB", "MB", "GB", "TB", "PB", "EB")
        f = float(n)
        i = 0
        while abs(f) >= 1000 and i < len(units) - 1:
            f /= 1000.0
            i += 1
        return f"{f:.3f} {units[i]}" if i > 0 else f"{n} B"

    def _printable(b: bytes) -> str:
        return "".join(chr(x) if 0x20 <= x < 0x7F else "." for x in b)

    def _int_forms(pack: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, (w, sg) in INT_TYPES.items():
            if w > len(pack):
                continue
            slc = pack[:w]
            n = int.from_bytes(slc, "little", signed=sg)
            out[name] = n
        return out

    result: dict[str, Any] = {
        "value": iv,
        "width_hint": width_hint,
        "dec": iv,
        "unsigned": normalized,
        "signed": signed,
        "hex": f"0x{normalized:0{width*2}X}",
        "hex_lower": f"0x{normalized:0{width*2}x}",
        "bin": f"0b{normalized:0{width*8}b}",
        "oct": f"0o{normalized:0{width*8//3}o}",
        "size_iec": _size_iec(normalized) if normalized >= 0 else _size_iec(-normalized),
        "size_si": _size_si(normalized) if normalized >= 0 else _size_si(-normalized),
        "bytes_le": packed_le.hex(),
        "bytes_be": packed_be.hex(),
        "ascii_le": _printable(packed_le),
        "ascii_be": _printable(packed_be),
        "as_int_le": _int_forms(packed_le),
        "as_int_be": _int_forms(packed_be),
    }
    # Float interpretations only make sense at 4/8 bytes.
    if width >= 4:
        (f32_le,) = struct.unpack("<f", packed_le[:4])
        (f32_be,) = struct.unpack(">f", packed_be[-4:])
        result["as_f32_le"] = f32_le
        result["as_f32_be"] = f32_be
    if width >= 8:
        (f64_le,) = struct.unpack("<d", packed_le[:8])
        (f64_be,) = struct.unpack(">d", packed_be[-8:])
        result["as_f64_le"] = f64_le
        result["as_f64_be"] = f64_be
    # Cheap error-symbol probe — the LLM sees the symbol without a follow-up call.
    err = _err_lookup(normalized, space="auto")
    if err.get("symbol") or err.get("ntstatus") or err.get("hresult"):
        result["error_lookup"] = err
    return result


def do_pack(value: Any, from_type: str, endian: str = "little") -> dict[str, Any]:
    endian = (endian or "little").lower()
    from_c = canonicalize_type(from_type)
    if from_c in INT_TYPES:
        return cast_int_to_bytes(parse_int(value), from_c, endian)
    if from_c in FLOAT_TYPES:
        fvalue = parse_float(value)
        fmt = ("<f" if from_c == "f32" else "<d") if endian == "little" \
            else (">f" if from_c == "f32" else ">d")
        raw = struct.pack(fmt, fvalue)
        return {"hex": raw.hex(), "type": "bytes", "endian": endian,
                "length": len(raw), "notes": {"lossless": True}}
    raise ConversionError(
        "unknown_type", f"cannot pack from {from_type!r}",
        hint="pack accepts int and float source types",
    )


def do_unpack(data_hex: str, to_type: str,
              endian: str = "little") -> dict[str, Any]:
    endian = (endian or "little").lower()
    to_c = canonicalize_type(to_type)
    data = parse_hex_bytes(data_hex)
    if to_c in INT_TYPES:
        return cast_bytes_to_int(data, to_c, endian)
    if to_c in FLOAT_TYPES:
        width = 4 if to_c == "f32" else 8
        if len(data) < width:
            data = data + (b"\x00" * (width - len(data))) if endian == "little" \
                else (b"\x00" * (width - len(data))) + data
        if len(data) > width:
            data = data[:width] if endian == "little" else data[-width:]
        fmt = ("<f" if to_c == "f32" else "<d") if endian == "little" \
            else (">f" if to_c == "f32" else ">d")
        (fv,) = struct.unpack(fmt, data)
        return {"value": fv, "type": to_c, "endian": endian,
                "notes": {"lossless": True, "kind": "bitcast"}}
    raise ConversionError(
        "unknown_type", f"cannot unpack into {to_type!r}",
        hint="unpack accepts int and float destination types",
    )


def do_swap(value: Any, width: int) -> dict[str, Any]:
    if width not in (2, 4, 8):
        raise ConversionError(
            "width_mismatch", f"swap width must be 2, 4, or 8; got {width}",
            hint="swap operates on u16/u32/u64",
        )
    iv = parse_int(value) & _mask(width)
    swapped = int.from_bytes(iv.to_bytes(width, "little"), "big", signed=False)
    return {
        "input": {"value": iv, "hex": f"0x{iv:0{width*2}X}"},
        "output": {"value": swapped, "hex": f"0x{swapped:0{width*2}X}"},
        "width": width,
    }


def do_split(value: Any, width: int, count: int = 0,
             data_hex: str = "") -> dict[str, Any]:
    if data_hex:
        data = parse_hex_bytes(data_hex)
        chunk = width
        if chunk <= 0:
            raise ConversionError("width_mismatch", "width must be > 0 for split",
                                  hint="pass width=4 for DWORDs, width=8 for QWORDs")
        parts = [data[i:i+chunk].ljust(chunk, b"\x00")
                 for i in range(0, len(data), chunk)]
        if count and len(parts) > count:
            parts = parts[:count]
        return {
            "chunks": [{"hex": p.hex(),
                        "u_le": int.from_bytes(p, "little", signed=False),
                        "u_be": int.from_bytes(p, "big", signed=False)}
                       for p in parts],
            "chunk_width": chunk,
            "count": len(parts),
        }
    # int split into halves
    if width not in (2, 4, 8):
        raise ConversionError("width_mismatch",
                              f"integer split width must be 2/4/8; got {width}",
                              hint="width is the SOURCE width; halves are width/2")
    iv = parse_int(value) & _mask(width)
    half = width // 2
    lo = iv & _mask(half)
    hi = (iv >> (half * 8)) & _mask(half)
    return {
        "input": {"value": iv, "hex": f"0x{iv:0{width*2}X}", "width": width},
        "hi": {"value": hi, "hex": f"0x{hi:0{half*2}X}", "width": half},
        "lo": {"value": lo, "hex": f"0x{lo:0{half*2}X}", "width": half},
    }


def do_join(parts: list[Any], width: int, endian: str = "little") -> dict[str, Any]:
    if not isinstance(parts, list) or not parts:
        raise ConversionError("unparseable_value", "parts must be a non-empty list",
                              hint="pass parts_json='[\"0xDEAD\", \"0xBEEF\"]'")
    if width not in (1, 2, 4, 8):
        raise ConversionError("width_mismatch", f"join part width must be 1/2/4/8; got {width}",
                              hint="every part gets this many bytes")
    endian = (endian or "little").lower()
    chunks: list[bytes] = []
    for p in parts:
        iv = parse_int(p) & _mask(width)
        chunks.append(iv.to_bytes(width, "little" if endian == "little" else "big"))
    raw = b"".join(chunks)
    combined = int.from_bytes(raw, "little" if endian == "little" else "big",
                              signed=False)
    return {
        "hex": raw.hex(),
        "length": len(raw),
        "combined_unsigned": combined,
        "endian": endian,
        "parts": len(parts),
        "part_width": width,
    }
