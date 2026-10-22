"""GUID / UUID string / bytes_le / Windows-binary conversions."""

from __future__ import annotations

import uuid
from typing import Any

from .errors import ConversionError
from .pack import parse_hex_bytes

# ---------------------------------------------------------------------------
# GUID
# ---------------------------------------------------------------------------


def _guid_windows_from_bytes(b: bytes) -> uuid.UUID:
    # Windows binary GUID: first 3 groups are LE, last 2 groups raw.
    if len(b) != 16:
        raise ConversionError("width_mismatch",
                              f"GUID is 16 bytes; got {len(b)}",
                              hint="pass exactly 32 hex chars")
    d1 = int.from_bytes(b[0:4], "little")
    d2 = int.from_bytes(b[4:6], "little")
    d3 = int.from_bytes(b[6:8], "little")
    d4 = b[8:16]
    ints = (d1, d2, d3, d4[0], d4[1],
            int.from_bytes(d4[2:], "big"))
    return uuid.UUID(fields=ints)


def _bytes_from_guid_windows(u: uuid.UUID) -> bytes:
    return (u.fields[0].to_bytes(4, "little")
            + u.fields[1].to_bytes(2, "little")
            + u.fields[2].to_bytes(2, "little")
            + bytes([u.fields[3], u.fields[4]])
            + u.fields[5].to_bytes(6, "big"))


def guid_convert(value: Any, form: str = "string",
                 data_hex: str = "") -> dict[str, Any]:
    """Convert between GUID string, raw LE bytes, and Windows binary GUID."""
    form = (form or "string").lower()
    if form in ("string", "str", "guid_str"):
        try:
            u = uuid.UUID(str(value).strip("{}").strip())
        except ValueError as exc:
            raise ConversionError(
                "unparseable_value", f"not a valid GUID string: {value!r}",
                hint="pass e.g. '{DEADBEEF-1234-5678-9ABC-DEF012345678}'",
            ) from exc
    elif form in ("bytes_le", "guid_le"):
        data = parse_hex_bytes(data_hex or (value if isinstance(value, str) else ""))
        if len(data) != 16:
            raise ConversionError("width_mismatch",
                                  f"GUID is 16 bytes; got {len(data)}",
                                  hint="pass exactly 32 hex chars")
        u = uuid.UUID(bytes=data)  # network/BE order
    elif form in ("bytes_windows", "guid_windows"):
        data = parse_hex_bytes(data_hex or (value if isinstance(value, str) else ""))
        u = _guid_windows_from_bytes(data)
    else:
        raise ConversionError(
            "unknown_type", f"unknown GUID form {form!r}",
            hint="form must be string, bytes_le, or bytes_windows",
        )
    windows_bytes = _bytes_from_guid_windows(u)
    return {
        "string": f"{{{str(u).upper()}}}",
        "hex_lower": str(u),
        "bytes_be": u.bytes.hex(),
        "bytes_le": u.bytes_le.hex(),
        "bytes_windows": windows_bytes.hex(),
        "version": u.version,
        "variant": u.variant,
    }
