"""PDB symbol resolution helpers: GUID formatting, debug-dir parsing, caching."""

from __future__ import annotations

import pytest

from suspex.symbols import SymbolError, ensure_pdb, format_guid, read_pdb_info


def test_format_guid_mixed_endian() -> None:
    raw = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    assert format_guid(raw) == "0403020106050807090A0B0C0D0E0F10"
    with pytest.raises(SymbolError):
        format_guid(b"\x01\x02")


def _write_minipe(path, guid: bytes, age: int, pdb_name: bytes) -> None:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    buf[0x44:0x46] = (0x8664).to_bytes(2, "little")  # machine
    buf[0x46:0x48] = (1).to_bytes(2, "little")  # num sections
    buf[0x54:0x56] = (0xF0).to_bytes(2, "little")  # opt header size
    opt = 0x58
    buf[opt : opt + 2] = (0x20B).to_bytes(2, "little")  # PE32+
    dd = opt + 112
    dbg_rva = 0x1000
    buf[dd + 48 : dd + 52] = dbg_rva.to_bytes(4, "little")  # debug dir RVA
    buf[dd + 52 : dd + 56] = 28 .to_bytes(4, "little")  # debug dir size
    sec = opt + 0xF0
    buf[sec + 12 : sec + 16] = (0x1000).to_bytes(4, "little")  # VA
    buf[sec + 16 : sec + 20] = (0x1000).to_bytes(4, "little")  # raw size
    buf[sec + 20 : sec + 24] = (0x200).to_bytes(4, "little")  # raw ptr

    entry = bytearray(28)
    entry[12:16] = (2).to_bytes(4, "little")  # IMAGE_DEBUG_TYPE_CODEVIEW
    entry[16:20] = (0x40).to_bytes(4, "little")  # SizeOfData
    entry[24:28] = (0x240).to_bytes(4, "little")  # PointerToRawData
    blob_off = 0x240
    rsds = b"RSDS" + guid + age.to_bytes(4, "little") + pdb_name + b"\0"
    buf[0x200 : 0x200 + 28] = entry
    buf[blob_off : blob_off + len(rsds)] = rsds
    path.write_bytes(bytes(buf))


def test_read_pdb_info(tmp_path) -> None:
    guid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    pe = tmp_path / "ci.dll"
    _write_minipe(pe, guid, 3, b"ci.pdb")
    info = read_pdb_info(pe)
    assert info.name == "ci.pdb"
    assert info.age == 3
    assert info.guid == format_guid(guid)
    assert info.store_rel == "ci.pdb/0403020106050807090A0B0C0D0E0F103/ci.pdb"


def test_read_pdb_info_rejects_nonpe(tmp_path) -> None:
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a pe")
    with pytest.raises(SymbolError):
        read_pdb_info(p)


def test_ensure_pdb_cache_hit_no_download(tmp_path) -> None:
    guid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    pe = tmp_path / "ci.dll"
    _write_minipe(pe, guid, 3, b"ci.pdb")

    cache = tmp_path / "cache"
    rel = "ci.pdb/0403020106050807090A0B0C0D0E0F103/ci.pdb"
    cached = cache / rel
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"fake pdb bytes")

    got = ensure_pdb(str(pe), str(cache), allow_download=False)
    assert got == cached
    assert got.read_bytes() == b"fake pdb bytes"


def test_ensure_pdb_offline_missing_raises(tmp_path) -> None:
    guid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    pe = tmp_path / "ci.dll"
    _write_minipe(pe, guid, 3, b"ci.pdb")
    with pytest.raises(SymbolError, match="download disabled"):
        ensure_pdb(str(pe), str(tmp_path / "cache"), allow_download=False)
