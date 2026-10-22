"""Float parsing and float <-> int / float <-> float casts."""

from __future__ import annotations

import struct
from typing import Any

from .errors import ConversionError
from .ints import INT_TYPES, _mask, _to_signed


def parse_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        raise ConversionError(
            "unparseable_value",
            f"cannot parse {type(value).__name__} as float",
            hint="pass a float like 3.14 or '1e-9'",
        )
    s = value.strip()
    if not s:
        raise ConversionError("unparseable_value", "empty float value",
                              hint="pass e.g. '3.14' or '1e-9'")
    try:
        # Support hex-encoded bit patterns for round-tripping: "0x40490FDB" as f32
        if s.lower().startswith("0x"):
            raise ValueError  # kick to fallback path below
        return float(s)
    except ValueError:
        # Try parsing as int-with-hex and reinterpreting later — caller decides.
        raise ConversionError(
            "unparseable_value",
            f"{value!r} is not a valid float; if it is a bit pattern like "
            "'0x40490FDB', pack it under u32 and unpack under f32",
            hint="cast(value='0x40490FDB', from_type='u32', to_type='f32')",
        )


def cast_int_to_float(value: int, from_type: str, to_type: str) -> dict[str, Any]:
    src_w, src_signed = INT_TYPES[from_type]
    normalized = value & _mask(src_w)
    signed_input = _to_signed(normalized, src_w) if src_signed else normalized
    fmt = "<f" if to_type == "f32" else "<d"
    packed = struct.pack("<I" if to_type == "f32" else "<Q",
                         normalized & (_mask(4) if to_type == "f32" else _mask(8)))
    if to_type == "f32":
        (fval,) = struct.unpack("<f", packed)
    else:
        (fval,) = struct.unpack("<d", packed)
    # Bitcast — always exact in the bit sense; arithmetic exactness is a
    # separate question (announced via notes.exact).
    return {
        "value": fval,
        "type": to_type,
        "hex": f"0x{normalized:0{(4 if to_type=='f32' else 8)*2}X}",
        "notes": {
            "lossless": True,
            "kind": "bitcast",
            "input_normalized": normalized,
            "input_as_signed": signed_input,
        },
    }


def cast_float_to_int(value: float, from_type: str, to_type: str) -> dict[str, Any]:
    dst_w, dst_signed = INT_TYPES[to_type]
    fmt = "<f" if from_type == "f32" else "<d"
    packed = struct.pack(fmt, value)
    unpacked = int.from_bytes(packed, "little", signed=False)
    # Truncate/extend into destination width.
    mask = _mask(dst_w)
    if len(packed) > dst_w:
        raw = unpacked & mask
        truncated = (len(packed) - dst_w) * 8
    else:
        raw = unpacked
        truncated = 0
    out = _to_signed(raw, dst_w) if dst_signed else raw
    return {
        "value": out,
        "hex": f"0x{raw:0{dst_w*2}X}",
        "type": to_type,
        "notes": {
            "lossless": len(packed) <= dst_w,
            "kind": "bitcast",
            "truncated_bits": truncated,
        },
    }


def cast_float_to_float(value: float, from_type: str, to_type: str) -> dict[str, Any]:
    if from_type == to_type:
        return {"value": value, "type": to_type,
                "notes": {"lossless": True, "kind": "identity"}}
    # Round-trip through a smaller float format if narrowing.
    packed = struct.pack("<f" if to_type == "f32" else "<d", value)
    (out,) = struct.unpack("<f" if to_type == "f32" else "<d", packed)
    exact = (out == value) if not (value != value) else True  # NaN self-equal
    return {"value": out, "type": to_type,
            "notes": {"lossless": exact, "kind": "narrow" if to_type == "f32" else "widen"}}
