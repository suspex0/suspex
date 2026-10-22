"""v0.22 B-1e — ``conversions.decode_typed_buffer``: named-type decode.

Pure-compute tests over the member-walk decoder that backs
``mem_rw read decode={'type':'_EPROCESS','module':...}``. Member lists
are exercised in both producer shapes:

  * ``dump_layout`` cache rows — ``{name, offset, size, type}`` with
    nested UDTs resolved through the ``types`` map.
  * dbghelp ``type_layout`` rows — nested UDTs inline as ``children``,
    bitfields as ``bit_position``/``bit_length``.
"""
from __future__ import annotations

import struct

import pytest

from suspex.mcp.conversions import decode_typed_buffer


_MEMBERS = [
    {"name": "Pcb", "offset": 0x0, "size": 0x10, "type": "_KPROCESS"},
    {"name": "UniqueProcessId", "offset": 0x10, "size": 0x8,
     "type": "void *"},
    {"name": "Flags", "offset": 0x18, "size": 0x4,
     "type": "unsigned long"},
]

_TYPES = {
    "_KPROCESS": {"size": 0x10, "members": [
        {"name": "Header", "offset": 0x0, "size": 0x8,
         "type": "unsigned __int64"},
        {"name": "DirectoryTableBase", "offset": 0x8, "size": 0x8,
         "type": "unsigned __int64"},
    ]},
}


def test_typed_decode_primitives_and_pointer() -> None:
    raw = b"\x00" * 0x10 + struct.pack("<Q", 0xDEADBEEF) + struct.pack(
        "<I", 0x4141)
    out = decode_typed_buffer(raw, _MEMBERS, type_name="_EPROCESS",
                              types=_TYPES)
    assert out["truncated"] is False
    assert out["type"] == "_EPROCESS"
    vals = out["values"]
    assert vals["UniqueProcessId"] == 0xDEADBEEF
    assert vals["Flags"] == 0x4141
    # _KPROCESS IS in `types` -> nested dict, not a blob.
    assert isinstance(vals["Pcb"], dict)


def test_typed_decode_nested_udt_via_types_map() -> None:
    inner = struct.pack("<QQ", 0xAAAA, 0xBBBB)
    raw = inner + b"\x00" * 0x10
    out = decode_typed_buffer(raw, _MEMBERS, types=_TYPES)
    assert out["values"]["Pcb"] == {"Header": 0xAAAA,
                                    "DirectoryTableBase": 0xBBBB}
    # flat layout carries dotted paths for the nested walk.
    paths = {row["path"] for row in out["layout"]}
    assert "Pcb.Header" in paths
    assert "Pcb.DirectoryTableBase" in paths


def test_typed_decode_nested_udt_via_children() -> None:
    """dbghelp's inline ``children`` shape — no ``types`` map needed."""
    members = [
        {"name": "Pcb", "offset": 0x0, "size": 0x10, "type": "_KPROCESS",
         "children": [
             {"name": "Header", "offset": 0x0, "size": 8,
              "type": "unsigned __int64"},
             {"name": "Dtb", "offset": 0x8, "size": 8,
              "type": "unsigned __int64"}]},
    ]
    raw = struct.pack("<QQ", 0x1111, 0x2222)
    out = decode_typed_buffer(raw, members)
    assert out["values"]["Pcb"] == {"Header": 0x1111, "Dtb": 0x2222}


def test_typed_decode_opaque_when_type_unknown() -> None:
    """A UDT not in `types` and without children -> hex blob + opaque."""
    raw = b"\x01\x02\x03\x04" + b"\x05" * 0x1c
    members = [{"name": "Mystery", "offset": 0, "size": 4,
                "type": "_UNDOCUMENTED"},
               {"name": "X", "offset": 4, "size": 4,
                "type": "unsigned long"}]
    out = decode_typed_buffer(raw, members)
    assert out["values"]["Mystery"] == "01020304"
    row = next(r for r in out["layout"] if r["path"] == "Mystery")
    assert row["opaque"] is True
    # Decoding still continues past the opaque member.
    assert out["values"]["X"] == 0x05050505


def test_typed_decode_primitive_array_member() -> None:
    members = [{"name": "Tbl", "offset": 0, "size": 0x10,
                "type": "unsigned long[4]"}]
    raw = struct.pack("<4I", 1, 2, 3, 4)
    out = decode_typed_buffer(raw, members)
    assert out["values"]["Tbl"] == [1, 2, 3, 4]


def test_typed_decode_bitfield() -> None:
    """Dbghelp bitfield row: container u32 at offset 0, extract 4 bits
    at bit_position 8."""
    members = [
        {"name": "Container", "offset": 0, "size": 4,
         "type": "unsigned long"},
        {"name": "Nibble", "offset": 0, "size": 4,
         "type": "unsigned long", "bit_position": 8, "bit_length": 4},
    ]
    raw = struct.pack("<I", 0xABCD)
    out = decode_typed_buffer(raw, members)
    assert out["values"]["Container"] == 0xABCD
    assert out["values"]["Nibble"] == 0xB


def test_typed_decode_truncation_short_buffer() -> None:
    """Buffer ends mid-type: parsed members stay, truncated=True,
    no exception."""
    raw = b"\x00" * 0x10 + struct.pack("<Q", 0xDEADBEEF)
    # Flags at 0x18 doesn't fit — Pcb+UniqueProcessId decode anyway.
    out = decode_typed_buffer(raw, _MEMBERS, types=_TYPES)
    assert out["truncated"] is True
    assert out["values"]["UniqueProcessId"] == 0xDEADBEEF
    assert "Flags" not in out["values"]
    last = out["layout"][-1]
    assert last["path"] == "Flags"
    assert last["truncated"] is True


def test_typed_decode_remainder_and_consumed() -> None:
    raw = struct.pack("<I", 7) + b"TAIL"
    members = [{"name": "X", "offset": 0, "size": 4,
                "type": "unsigned long"}]
    out = decode_typed_buffer(raw, members, size=4)
    assert out["consumed_bytes"] == 4
    assert out["remainder_hex"] == b"TAIL".hex()


def test_typed_decode_unsigned_signed_wideness() -> None:
    members = [{"name": "N", "offset": 0, "size": 4, "type": "int"}]
    out = decode_typed_buffer(struct.pack("<i", -5), members)
    assert out["values"]["N"] == -5
