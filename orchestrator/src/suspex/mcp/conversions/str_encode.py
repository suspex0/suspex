"""Text / byte-encoding conversions: url, rot13, quopri, base64/32/16/85,
hex variants, and the cross-codec `str_convert`."""

from __future__ import annotations

import base64
import binascii
import codecs
from typing import Any

from .errors import ConversionError
from .ints import TEXT_CODECS, canonicalize_type
from .pack import parse_hex_bytes

# ---------------------------------------------------------------------------
# Encoding / decoding / str_convert
# ---------------------------------------------------------------------------


def _urlencode(b: bytes) -> str:
    from urllib.parse import quote
    return quote(b, safe="")


def _urldecode(s: str) -> bytes:
    from urllib.parse import unquote_to_bytes
    return unquote_to_bytes(s)


def _rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def _quopri_encode(b: bytes) -> str:
    import quopri
    return quopri.encodestring(b, quotetabs=False).decode("ascii")


def _quopri_decode(s: str) -> bytes:
    import quopri
    return quopri.decodestring(s.encode("ascii"))


def _wrap(s: str, col: int) -> str:
    if not col or col <= 0:
        return s
    return "\n".join(s[i:i+col] for i in range(0, len(s), col))


def encode_bytes(data_hex: str, to_type: str,
                 wrap: int = 0, pad: bool = True) -> dict[str, Any]:
    data = parse_hex_bytes(data_hex)
    to_c = canonicalize_type(to_type)
    if to_c == "base64":
        out = base64.b64encode(data).decode("ascii")
        if not pad:
            out = out.rstrip("=")
    elif to_c == "base64url":
        out = base64.urlsafe_b64encode(data).decode("ascii")
        if not pad:
            out = out.rstrip("=")
    elif to_c == "base32":
        out = base64.b32encode(data).decode("ascii")
        if not pad:
            out = out.rstrip("=")
    elif to_c == "base32hex":
        out = base64.b32hexencode(data).decode("ascii")
        if not pad:
            out = out.rstrip("=")
    elif to_c == "base16":
        out = base64.b16encode(data).decode("ascii")
    elif to_c == "base85":
        out = base64.b85encode(data).decode("ascii")
    elif to_c == "ascii85":
        out = base64.a85encode(data).decode("ascii")
    elif to_c == "hex":
        out = data.hex()
    elif to_c == "hex-upper":
        out = data.hex().upper()
    elif to_c == "hex-spaced":
        out = " ".join(f"{b:02x}" for b in data)
    elif to_c == "hex-c-array":
        out = "{ " + ", ".join(f"0x{b:02X}" for b in data) + " }"
    elif to_c == "url":
        out = _urlencode(data)
    elif to_c == "quoted-printable":
        out = _quopri_encode(data)
    elif to_c == "rot13":
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConversionError(
                "encoding_error", "rot13 needs ASCII input",
                hint="pass ASCII bytes (rot13 only rotates letters)",
            ) from exc
        out = _rot13(text)
    else:
        raise ConversionError(
            "unsupported_encoding", f"unknown target encoding {to_type!r}",
            hint="known encodings: base64, base64url, base32, base32hex, base16, "
                 "base85, ascii85, hex, hex-upper, hex-spaced, hex-c-array, url, "
                 "quoted-printable, rot13",
        )
    return {
        "input_bytes": len(data),
        "encoding": to_c,
        "output": _wrap(out, wrap),
        "output_len": len(out),
        "pad": pad,
    }


def decode_text(value: str, from_type: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise ConversionError("unparseable_value",
                              f"decode value must be str; got {type(value).__name__}",
                              hint="pass the encoded text as `value`")
    from_c = canonicalize_type(from_type)
    s = value
    try:
        if from_c == "base64":
            # Fix missing padding gracefully.
            s2 = s + "=" * ((4 - len(s) % 4) % 4)
            data = base64.b64decode(s2, validate=False)
        elif from_c == "base64url":
            s2 = s + "=" * ((4 - len(s) % 4) % 4)
            data = base64.urlsafe_b64decode(s2)
        elif from_c == "base32":
            s2 = s + "=" * ((8 - len(s) % 8) % 8)
            data = base64.b32decode(s2, casefold=True)
        elif from_c == "base32hex":
            s2 = s + "=" * ((8 - len(s) % 8) % 8)
            data = base64.b32hexdecode(s2, casefold=True)
        elif from_c == "base16":
            data = base64.b16decode(s, casefold=True)
        elif from_c == "base85":
            data = base64.b85decode(s)
        elif from_c == "ascii85":
            data = base64.a85decode(s)
        elif from_c in ("hex", "hex-upper", "hex-spaced", "hex-c-array"):
            data = parse_hex_bytes(s)
        elif from_c == "url":
            data = _urldecode(s)
        elif from_c == "quoted-printable":
            data = _quopri_decode(s)
        elif from_c == "rot13":
            data = _rot13(s).encode("ascii", errors="replace")
        else:
            raise ConversionError(
                "unsupported_encoding", f"unknown source encoding {from_type!r}",
                hint="known encodings: base64, base64url, base32, base32hex, base16, "
                     "base85, ascii85, hex, url, quoted-printable, rot13",
            )
    except (binascii.Error, ValueError) as exc:
        raise ConversionError(
            "encoding_error", f"{from_c} decode failed: {exc}",
            hint="check padding, alphabet, and case",
        ) from exc
    utf8_preview: str | None = None
    try:
        utf8_preview = data.decode("utf-8")
    except UnicodeDecodeError:
        utf8_preview = None
    return {
        "encoding": from_c,
        "hex": data.hex(),
        "length": len(data),
        "utf8_preview": utf8_preview,
    }


def str_convert(value: Any = None, data_hex: str = "",
                from_type: str = "utf-8", to_type: str = "bytes",
                errors: str = "strict",
                strip_nul: bool = False) -> dict[str, Any]:
    """Cross-codec text conversion. Either `value` (str) or `data_hex` (bytes).

    - bytes -> str: from_type is a text codec, to_type is 'str'.
    - str -> bytes: from_type='str', to_type is a text codec.
    - bytes -> bytes: transcoding between codecs.
    """
    from_c = canonicalize_type(from_type) if from_type != "str" else "str"
    to_c = canonicalize_type(to_type) if to_type != "str" else "str"
    if errors not in ("strict", "replace", "ignore"):
        raise ConversionError(
            "unknown_type", f"errors={errors!r} unrecognized",
            hint="use errors='strict' (default), 'replace', or 'ignore'",
        )

    def _get_bytes() -> bytes:
        if data_hex:
            return parse_hex_bytes(data_hex)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str) and from_c not in ("str", "bytes"):
            # Interpret `value` as text of `from_c` codec.
            try:
                return value.encode(from_c, errors=errors)
            except (LookupError, UnicodeError) as exc:
                raise ConversionError(
                    "encoding_error", f"encode failed under {from_c}: {exc}",
                    hint="try errors='replace' or a different from_type",
                ) from exc
        raise ConversionError(
            "unparseable_value",
            "need data_hex or value for str_convert",
            hint="pass data_hex='4d5a…' for bytes, or value='hello' for a string",
        )

    # bytes -> str
    if from_c in TEXT_CODECS.values() and to_c == "str":
        data = parse_hex_bytes(data_hex) if data_hex else (
            value.encode(from_c) if isinstance(value, str) else _get_bytes())
        if strip_nul:
            # Strip trailing NUL(s) — critical for UNICODE_STRING dumps.
            if from_c in ("utf-16-le", "utf-16", "utf-16-be"):
                while data.endswith(b"\x00\x00"):
                    data = data[:-2]
            else:
                data = data.rstrip(b"\x00")
        try:
            out = data.decode(from_c, errors=errors)
        except (LookupError, UnicodeError) as exc:
            raise ConversionError(
                "encoding_error", f"decode failed under {from_c}: {exc}",
                hint=f"try errors='replace' or a different from_type; "
                     f"the byte at offset {getattr(exc, 'start', '?')} was bad",
            ) from exc
        return {"str": out, "length_chars": len(out), "input_bytes": len(data),
                "from": from_c, "to": "str", "errors": errors,
                "strip_nul": strip_nul}
    # str -> bytes
    if from_c == "str" and to_c in TEXT_CODECS.values():
        if not isinstance(value, str):
            raise ConversionError(
                "unparseable_value", "value must be str for str->bytes",
                hint="pass value='hello' with from_type='str'",
            )
        try:
            data = value.encode(to_c, errors=errors)
        except (LookupError, UnicodeError) as exc:
            raise ConversionError(
                "encoding_error", f"encode failed under {to_c}: {exc}",
                hint="try errors='replace' or a different to_type",
            ) from exc
        return {"hex": data.hex(), "length": len(data), "input_chars": len(value),
                "from": "str", "to": to_c, "errors": errors}
    # bytes -> bytes (transcode)
    if from_c in TEXT_CODECS.values() and to_c in TEXT_CODECS.values():
        data = parse_hex_bytes(data_hex) if data_hex else _get_bytes()
        try:
            text = data.decode(from_c, errors=errors)
        except (LookupError, UnicodeError) as exc:
            raise ConversionError(
                "encoding_error", f"decode failed under {from_c}: {exc}",
                hint="check from_type; try errors='replace'",
            ) from exc
        try:
            out = text.encode(to_c, errors=errors)
        except (LookupError, UnicodeError) as exc:
            raise ConversionError(
                "encoding_error", f"encode failed under {to_c}: {exc}",
                hint="check to_type",
            ) from exc
        return {"hex": out.hex(), "length": len(out), "input_bytes": len(data),
                "from": from_c, "to": to_c, "errors": errors, "text_len": len(text)}
    raise ConversionError(
        "unknown_type",
        f"unsupported str_convert combination {from_type!r} -> {to_type!r}",
        hint="use text codecs (utf-8/utf-16-le/cp1252/…) or 'str' on one side",
    )
