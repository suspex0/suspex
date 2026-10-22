"""FILETIME / SYSTEMTIME / unix epoch / ISO 8601 conversions."""

from __future__ import annotations

import datetime as _dt
import struct
from typing import Any

from .errors import ConversionError
from .ints import canonicalize_type, parse_int
from .pack import parse_hex_bytes

# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
UNIX_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


def _filetime_to_dt(ft: int) -> _dt.datetime:
    # 100-ns ticks since 1601-01-01 UTC
    return FILETIME_EPOCH + _dt.timedelta(microseconds=ft // 10)


def _dt_to_filetime(dt: _dt.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    delta = dt - FILETIME_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _systemtime_from_hex(data: bytes) -> _dt.datetime:
    if len(data) < 16:
        raise ConversionError(
            "width_mismatch",
            f"SYSTEMTIME is 16 bytes; got {len(data)}",
            hint="pass all 16 bytes: wYear,wMonth,wDayOfWeek,wDay,wHour,wMinute,wSecond,wMilliseconds (each u16 LE)",
        )
    fields = struct.unpack("<8H", data[:16])
    year, month, _dow, day, hour, minute, second, ms = fields
    return _dt.datetime(year, month, day, hour, minute, second, ms * 1000,
                        tzinfo=_dt.timezone.utc)


def _dt_to_systemtime(dt: _dt.datetime) -> bytes:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    dow = (dt.weekday() + 1) % 7  # Windows: 0=Sunday
    return struct.pack("<8H", dt.year, dt.month, dow, dt.day,
                       dt.hour, dt.minute, dt.second, dt.microsecond // 1000)


def time_convert(value: Any, from_type: str, to_type: str,
                 data_hex: str = "") -> dict[str, Any]:
    from_c = canonicalize_type(from_type)
    to_c = canonicalize_type(to_type)

    # Parse source into a UTC datetime.
    if from_c == "filetime":
        ft = parse_int(value) if value not in (None, "") else \
            int.from_bytes(parse_hex_bytes(data_hex or "").ljust(8, b"\x00")[:8],
                           "little")
        dt = _filetime_to_dt(ft)
        input_view: Any = {"filetime": ft, "hex": f"0x{ft:016X}"}
    elif from_c in ("unix_epoch",):
        secs = parse_int(value)
        dt = UNIX_EPOCH + _dt.timedelta(seconds=secs)
        input_view = {"unix_epoch": secs}
    elif from_c == "unix_ms":
        ms = parse_int(value)
        dt = UNIX_EPOCH + _dt.timedelta(milliseconds=ms)
        input_view = {"unix_ms": ms}
    elif from_c == "unix_us":
        us = parse_int(value)
        dt = UNIX_EPOCH + _dt.timedelta(microseconds=us)
        input_view = {"unix_us": us}
    elif from_c == "systemtime":
        data = parse_hex_bytes(data_hex or (value if isinstance(value, str) else ""))
        dt = _systemtime_from_hex(data)
        input_view = {"systemtime_hex": data.hex()}
    elif from_c == "iso8601":
        s = str(value).strip()
        # Accept trailing Z and space separator.
        s = s.replace("Z", "+00:00")
        try:
            dt = _dt.datetime.fromisoformat(s)
        except ValueError as exc:
            raise ConversionError(
                "unparseable_value",
                f"iso8601 parse failed: {exc}",
                hint="pass e.g. '2026-09-09T12:34:56Z' or '2026-09-09 12:34:56+00:00'",
            ) from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        input_view = {"iso8601": dt.isoformat()}
    else:
        raise ConversionError(
            "unknown_type",
            f"from_type={from_type!r} is not a time type",
            hint="use filetime, unix_epoch, unix_ms, unix_us, systemtime, or iso8601",
        )

    dt_utc = dt.astimezone(_dt.timezone.utc)

    # Render into destination.
    if to_c == "iso8601":
        out: Any = dt_utc.isoformat().replace("+00:00", "Z")
        return {"input": input_view, "output": {"iso8601": out},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    if to_c == "filetime":
        ft = _dt_to_filetime(dt_utc)
        return {"input": input_view,
                "output": {"filetime": ft, "hex": f"0x{ft:016X}",
                           "bytes_le": ft.to_bytes(8, "little").hex()},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    if to_c == "unix_epoch":
        return {"input": input_view,
                "output": {"unix_epoch": int((dt_utc - UNIX_EPOCH).total_seconds())},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    if to_c == "unix_ms":
        delta = dt_utc - UNIX_EPOCH
        return {"input": input_view,
                "output": {"unix_ms": delta.days * 86400_000
                           + delta.seconds * 1000 + delta.microseconds // 1000},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    if to_c == "unix_us":
        delta = dt_utc - UNIX_EPOCH
        return {"input": input_view,
                "output": {"unix_us": (delta.days * 86400
                                       + delta.seconds) * 1_000_000
                           + delta.microseconds},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    if to_c == "systemtime":
        raw = _dt_to_systemtime(dt_utc)
        return {"input": input_view,
                "output": {"systemtime_hex": raw.hex()},
                "utc": dt_utc.isoformat().replace("+00:00", "Z")}
    raise ConversionError(
        "unknown_type",
        f"to_type={to_type!r} is not a time type",
        hint="use filetime, unix_epoch, unix_ms, unix_us, systemtime, or iso8601",
    )
