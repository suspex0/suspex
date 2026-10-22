"""Structured buffer decode — turn ``bytes`` into a list of typed values."""

from __future__ import annotations

import re
import struct
from typing import Any

from .errors import ConversionError

# ---------------------------------------------------------------------------
# v0.17 B-1a — structured buffer decode
#
# Turn a raw ``bytes`` buffer into a list of typed values without a
# call-site loop. Accepts a shorthand string ("u64[4]", "u32[]"), a list of
# type tokens (["u32", "u32", "u64"]), or a mixed string with comma
# separators ("u32,u32,cstr"). Never raises on a short buffer — sets
# ``truncated:true`` and returns what parsed.
#
# Consumed by ``mem_rw read`` (`decode=`), ``mem_rw walk_list`` (per-node
# `decode=`), and the read_qwords / read_unicode_string / read_ansi_string
# convenience wrappers.
# ---------------------------------------------------------------------------

# Struct format + width table for the fixed-width tokens.
_DECODE_FMT: dict[str, tuple[str, int]] = {
    "u8":  ("<B", 1), "i8":  ("<b", 1),
    "u16": ("<H", 2), "i16": ("<h", 2),
    "u32": ("<I", 4), "i32": ("<i", 4),
    "u64": ("<Q", 8), "i64": ("<q", 8),
    "ptr": ("<Q", 8),  # x64 pointer; explicit x86 would need `ptr32`
    "f32": ("<f", 4), "f64": ("<d", 8),
}

_DECODE_ARRAY_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*\[\s*(\d*)\s*\]\s*$")


def _expand_spec(spec: str | list[str], buflen: int) -> list[str]:
    """Normalize a decode spec into a flat list of type tokens.

    Accepts:
      * ``list[str]`` — used verbatim after per-token trim.
      * bare token string ``"u64"`` — wrapped as a single element.
      * comma / semicolon / whitespace-separated string ``"u32,u32,cstr"``.
      * array shorthand ``"u64[]"`` (as many as fit) / ``"u64[16]"`` (N).
    """
    if isinstance(spec, list):
        return [str(t).strip() for t in spec if str(t).strip()]
    if not isinstance(spec, str):
        raise ConversionError(
            "unparseable_value",
            f"decode spec must be a str or list; got {type(spec).__name__}",
            hint="pass decode=['u64','u64'] or decode='u64[4]'",
        )
    s = spec.strip()
    if not s:
        return []
    # Array shorthand — expand into `count` tokens (or "fill to end").
    m = _DECODE_ARRAY_RE.match(s)
    if m:
        base = m.group(1).strip()
        raw_count = m.group(2)
        if base not in _DECODE_FMT:
            # Only fixed-width primitives support array shorthand.
            raise ConversionError(
                "unknown_type",
                f"decode array shorthand needs a fixed-width type, got {base!r}",
                hint="use decode='u64[4]' or decode=['cstr','u64'] for variable widths",
            )
        elem_size = _DECODE_FMT[base][1]
        if raw_count:
            n = int(raw_count)
        else:
            n = max(0, buflen // elem_size)
        return [base] * n
    # Delimited list.
    parts = re.split(r"[,\s;]+", s)
    return [p for p in parts if p]


def _find_wstr_term(data: bytes, off: int) -> int:
    """Find the byte offset of the UTF-16-LE NUL terminator starting at
    ``off`` — the position where the *first* ``\\x00\\x00`` pair begins on
    an even alignment. Returns ``len(data)`` if none found (caller handles
    short buffer)."""
    i = off
    end = len(data) - 1
    while i < end:
        if data[i] == 0 and data[i + 1] == 0 and (i - off) % 2 == 0:
            return i
        i += 1
    return len(data)


def decode_buffer(data: bytes, spec: str | list[str]) -> dict[str, Any]:
    """Decode ``data`` under the type list ``spec``.

    Returns a dict with:
      * ``values``: list of decoded values, one per token that parsed.
      * ``layout``: per-token ``{offset, type, size}`` records — the shape
        the LLM needs to correlate a value back to its slot.
      * ``consumed_bytes``: total bytes decoded (may be < len(data) when
        the buffer has a remainder).
      * ``remainder_hex``: hex-string of the unparsed tail; empty when
        the whole buffer was consumed.
      * ``truncated``: True when the spec called for more bytes than
        ``data`` supplied — the layout stops at the last complete token.

    Recognized tokens:
      * ``u8``/``i8``/``u16``/``i16``/``u32``/``i32``/``u64``/``i64``
      * ``ptr`` (alias for x64 ``u64``)
      * ``f32``/``f64``
      * ``cstr`` — read up to the first NUL byte as UTF-8.
      * ``wstr`` — read up to the first UTF-16-LE NUL as UTF-16-LE.
      * ``utf8`` / ``utf16le`` — read the REMAINDER of the buffer under
        that codec (terminates the spec — later tokens are ignored).
    """
    if data is None:
        raise ConversionError(
            "unparseable_value", "decode_buffer: data is None",
            hint="pass a bytes buffer",
        )
    if not isinstance(data, (bytes, bytearray)):
        raise ConversionError(
            "unparseable_value",
            f"decode_buffer: data must be bytes; got {type(data).__name__}",
            hint="hex-parse first if you have a string",
        )
    data = bytes(data)
    tokens = _expand_spec(spec, len(data))
    values: list[Any] = []
    layout: list[dict[str, Any]] = []
    off = 0
    truncated = False
    for tok in tokens:
        tk = tok.strip().lower()
        if tk in _DECODE_FMT:
            fmt, sz = _DECODE_FMT[tk]
            if off + sz > len(data):
                truncated = True
                break
            (v,) = struct.unpack_from(fmt, data, off)
            values.append(v)
            layout.append({"offset": off, "type": tk, "size": sz})
            off += sz
        elif tk == "cstr":
            end = data.find(b"\x00", off)
            if end < 0:
                # No terminator — take everything left as best-effort.
                s = data[off:].decode("utf-8", errors="replace")
                values.append(s)
                layout.append({"offset": off, "type": "cstr",
                               "size": len(data) - off, "terminated": False})
                off = len(data)
                truncated = True
                break
            s = data[off:end].decode("utf-8", errors="replace")
            values.append(s)
            layout.append({"offset": off, "type": "cstr",
                           "size": end - off + 1, "terminated": True})
            off = end + 1
        elif tk == "wstr":
            end = _find_wstr_term(data, off)
            if end >= len(data):
                raw = data[off:]
                values.append(raw.decode("utf-16-le", errors="replace"))
                layout.append({"offset": off, "type": "wstr",
                               "size": len(raw), "terminated": False})
                off = len(data)
                truncated = True
                break
            raw = data[off:end]
            values.append(raw.decode("utf-16-le", errors="replace"))
            layout.append({"offset": off, "type": "wstr",
                           "size": end - off + 2, "terminated": True})
            off = end + 2
        elif tk == "utf8":
            values.append(data[off:].decode("utf-8", errors="replace"))
            layout.append({"offset": off, "type": "utf8",
                           "size": len(data) - off, "terminated": False})
            off = len(data)
            break
        elif tk == "utf16le":
            values.append(data[off:].decode("utf-16-le", errors="replace"))
            layout.append({"offset": off, "type": "utf16le",
                           "size": len(data) - off, "terminated": False})
            off = len(data)
            break
        else:
            raise ConversionError(
                "unknown_type",
                f"decode_buffer: unknown token {tok!r}",
                hint="tokens: u8/i8/u16/i16/u32/i32/u64/i64, ptr, f32/f64, "
                     "cstr, wstr, utf8, utf16le. Array shorthand: 'u64[4]', "
                     "'u32[]'",
            )
    remainder = data[off:]
    return {
        "values": values,
        "layout": layout,
        "consumed_bytes": off,
        "remainder_hex": remainder.hex() if remainder else "",
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# v0.22 B-1e — named-type (PDB layout) decode
#
# ``decode_typed_buffer`` walks a real type layout — either the IDA-dumped
# ``pdb_layout_cache`` shape (``types[name].members``) or the dbghelp
# ``symbols.type_layout`` shape (``members`` with inline ``children``) —
# and decodes ``data`` into a ``{member_name: value}`` dict plus a flat
# ``layout`` table with dotted paths for nested UDTs.
#
# Pure compute: the caller (mem_rw read) resolves the layout first. A
# buffer that runs out mid-type sets ``truncated`` instead of raising —
# same contract as ``decode_buffer``.
# ---------------------------------------------------------------------------

# Normalized C type name -> (struct fmt, width). Keys are lowercase with
# single spaces; covers the spellings dbghelp + IDA dump for kernel PDBs.
_CTYPE_FMT: dict[str, tuple[str, int]] = {
    "unsigned __int64": ("<Q", 8), "__int64": ("<q", 8),
    "unsigned long long": ("<Q", 8), "long long": ("<q", 8),
    "uint64": ("<Q", 8), "int64": ("<q", 8), "ulonglong": ("<Q", 8),
    "longlong": ("<q", 8), "qword": ("<Q", 8),
    "unsigned long": ("<L", 4), "long": ("<l", 4), "ulong": ("<L", 4),
    "unsigned int": ("<I", 4), "int": ("<i", 4), "uint": ("<I", 4),
    "uint32": ("<I", 4), "int32": ("<i", 4), "dword": ("<I", 4),
    "unsigned short": ("<H", 2), "short": ("<h", 2), "ushort": ("<H", 2),
    "word": ("<H", 2), "wchar_t": ("<H", 2),
    "unsigned char": ("<B", 1), "char": ("<b", 1), "uchar": ("<B", 1),
    "byte": ("<B", 1), "bool": ("<B", 1), "boolean": ("<B", 1),
    "float": ("<f", 4), "double": ("<d", 8),
    "ntstatus": ("<l", 4), "hresult": ("<l", 4),
    # x64 pointer-width aliases.
    "size_t": ("<Q", 8), "ptrdiff_t": ("<q", 8), "handle": ("<Q", 8),
    "pvoid": ("<Q", 8), "void *": ("<Q", 8),
}

_TYPE_ARRAY_RE = re.compile(r"^\s*(.+?)\s*\[\s*(\d+)\s*\]\s*$")


def _norm_ctype(t: str) -> str:
    """Normalize a C type spelling: drop struct/union/enum keywords,
    collapse whitespace, lowercase. `const`/`volatile` are qualifiers —
    stripped too."""
    t = re.sub(r"\s+", " ", (t or "").strip().lower())
    for kw in ("struct ", "union ", "enum ", "const ", "volatile "):
        if t.startswith(kw):
            t = t[len(kw):]
    return t


def _decode_one(data: bytes, off: int, tname: str, size: int,
                types: dict, depth: int, path: str,
                values: dict, layout: list, children: list | None,
                bit_position: int | None = None,
                bit_length: int | None = None) -> tuple[bool, int]:
    """Decode a single member. Returns (truncated, bytes_consumed_from_off).

    ``values``/``layout`` are mutated in place — nested UDTs land in
    ``values[path]`` as a dict; primitives land as ints/floats; anything
    unresolvable lands as a hex blob with ``opaque: true`` in the layout.
    """
    name = path.rsplit(".", 1)[-1]
    nt = _norm_ctype(tname)
    # Bitfield: decode the container then shift/mask. Container offset is
    # the member offset — consecutive bitfields share it.
    if bit_position is not None and bit_length:
        csz = max(size, 1)
        if off + csz > len(data):
            return True, 0
        container = int.from_bytes(data[off:off + csz], "little")
        val = (container >> bit_position) & ((1 << bit_length) - 1)
        values[name] = val
        layout.append({"path": path, "offset": off, "size": csz,
                       "type": tname, "bit_position": bit_position,
                       "bit_length": bit_length})
        return False, 0  # bitfields don't advance the cursor
    # Array member: `T[n]` — decode each element (primitives inline,
    # UDTs recurse per element when the type is known).
    m = _TYPE_ARRAY_RE.match(nt)
    if m:
        elem_t, cnt = m.group(1), int(m.group(2))
        elem = _norm_ctype(elem_t)
        fmt_sz = _CTYPE_FMT.get(elem)
        if fmt_sz:
            fmt, esz = fmt_sz
            total = esz * cnt
            if off + total > len(data):
                return True, 0
            arr = [struct.unpack_from(fmt, data, off + i * esz)[0]
                   for i in range(cnt)]
            values[name] = arr
            layout.append({"path": path, "offset": off, "size": total,
                           "type": f"{elem}[{cnt}]"})
            return False, total
        # Non-primitive element array — opaque unless the UDT is known.
        elem_layout = (types or {}).get(elem, {})
        elem_members = elem_layout.get("members")
        esz = int(elem_layout.get("size", 0))
        if elem_members and esz and depth > 0:
            arr = []
            for i in range(cnt):
                sub: dict[str, Any] = {}
                sub_layout: list[dict[str, Any]] = []
                trunc = _decode_members(
                    data, off + i * esz, elem_members, types,
                    depth - 1, f"{path}[{i}]", sub, sub_layout)
                arr.append(sub)
                layout.extend(sub_layout)
                if trunc:
                    return True, i * esz
            values[name] = arr
            return False, esz * cnt
        # Opaque array blob.
        if off + size > len(data):
            return True, 0
        values[name] = data[off:off + size].hex()
        layout.append({"path": path, "offset": off, "size": size,
                       "type": tname, "opaque": True})
        return False, size
    # Pointer (any `T *` spelling) — always 8 bytes on x64.
    if nt.endswith("*") or nt in ("pvoid", "handle"):
        if off + 8 > len(data):
            return True, 0
        (v,) = struct.unpack_from("<Q", data, off)
        values[name] = v
        layout.append({"path": path, "offset": off, "size": 8,
                       "type": tname, "pointer": True})
        return False, 8
    # Primitive.
    fmt_sz = _CTYPE_FMT.get(nt)
    if fmt_sz:
        fmt, sz = fmt_sz
        if off + sz > len(data):
            return True, 0
        (v,) = struct.unpack_from(fmt, data, off)
        values[name] = v
        layout.append({"path": path, "offset": off, "size": sz,
                       "type": nt})
        return False, sz
    # Nested UDT — dbghelp `children` inline, or the cache `types` map.
    sub_members = children
    if sub_members is None and types:
        sub = types.get(nt) or types.get(tname)
        if isinstance(sub, dict):
            sub_members = sub.get("members")
    if sub_members and depth > 0:
        sub: dict[str, Any] = {}
        trunc = _decode_members(data, off, sub_members, types,
                                depth - 1, path, sub, layout)
        values[name] = sub
        return trunc, size
    # Opaque: a UDT we can't expand, or an unrecognized type — emit raw
    # bytes so nothing is silently dropped.
    if off + size > len(data):
        return True, 0
    values[name] = data[off:off + size].hex()
    layout.append({"path": path, "offset": off, "size": size,
                   "type": tname or "?", "opaque": True})
    return False, size


def _decode_members(data: bytes, base: int, members: list[dict],
                    types: dict | None, depth: int, prefix: str,
                    values: dict, layout: list) -> bool:
    """Walk a member list at ``base``. Members are sorted by offset;
    the first member that doesn't fit sets truncated and stops the walk
    (everything after it is guaranteed out-of-bounds too)."""
    ordered = sorted(members, key=lambda m: int(m.get("offset", 0)))
    for m in ordered:
        off = base + int(m.get("offset", 0))
        size = int(m.get("size", 0))
        name = str(m.get("name", ""))
        path = f"{prefix}.{name}" if prefix else name
        trunc, _ = _decode_one(
            data, off, str(m.get("type", "")), size,
            types or {}, depth, path, values, layout,
            m.get("children"),
            bit_position=m.get("bit_position"),
            bit_length=m.get("bit_length"))
        if trunc:
            layout.append({"path": path, "offset": off, "size": size,
                           "type": str(m.get("type", "")), "truncated": True})
            return True
    return False


def decode_typed_buffer(data: bytes, members: list[dict], *,
                        type_name: str = "", size: int = 0,
                        types: dict | None = None,
                        max_depth: int = 2) -> dict[str, Any]:
    """Decode ``data`` under a named-type member layout.

    ``members`` is the member list — either a ``dump_layout`` JSON row
    (``{name, offset, size, type}``) or a dbghelp ``type_layout`` row
    (adds ``children``/``bit_position``/``bit_length``). ``types`` is the
    cache-level ``{type_name: {members, size}}`` map used to recurse into
    nested UDTs that aren't inlined as ``children``.

    Returns ``{values, layout, consumed_bytes, truncated,
    remainder_hex, type}`` — ``values`` is a ``{member: value}`` dict
    (nested UDTs produce nested dicts, arrays produce lists, unresolvable
    members produce hex blobs flagged ``opaque`` in the layout)."""
    if not isinstance(data, (bytes, bytearray)):
        raise ConversionError(
            "unparseable_value",
            f"decode_typed_buffer: data must be bytes; got "
            f"{type(data).__name__}",
            hint="read the bytes first, then decode",
        )
    data = bytes(data)
    values: dict[str, Any] = {}
    layout: list[dict[str, Any]] = []
    truncated = _decode_members(data, 0, members or [], types,
                                max_depth, "", values, layout)
    consumed = max((int(m.get("offset", 0)) + int(m.get("size", 0))
                    for m in (members or [])), default=0)
    if size and size > consumed:
        consumed = size
    if consumed > len(data):
        truncated = True
        consumed = len(data)
    remainder = data[consumed:]
    return {
        "ok": True,
        "type": type_name,
        "values": values,
        "layout": layout,
        "consumed_bytes": consumed,
        "remainder_hex": remainder.hex() if remainder else "",
        "truncated": truncated,
    }
