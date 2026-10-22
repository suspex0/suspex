"""Tests for _decode_enums — Windows constant decoders that attach
human-readable text next to raw integer fields.
"""
from __future__ import annotations

from suspex.mcp._decode_enums import (
    attach_decoded,
    attach_decoded_list,
    decode_granted_access,
    decode_mem_state,
    decode_mem_type,
    decode_pool_tag,
    decode_protect,
    decode_service_start,
    decode_service_type,
    decode_vad_type,
)


def test_decode_protect_basic():
    assert decode_protect(0x02) == "PAGE_READONLY"
    assert decode_protect(0x04) == "PAGE_READWRITE"
    assert decode_protect(0x20) == "PAGE_EXECUTE_READ"
    assert decode_protect(0x40) == "PAGE_EXECUTE_READWRITE"


def test_decode_protect_with_modifiers():
    assert decode_protect(0x120) == "PAGE_EXECUTE_READ | PAGE_GUARD"
    assert decode_protect(0x204) == "PAGE_READWRITE | PAGE_NOCACHE"


def test_decode_protect_string_input():
    assert decode_protect("0x20") == "PAGE_EXECUTE_READ"
    assert decode_protect("32") == "PAGE_EXECUTE_READ"


def test_decode_protect_unknown_returns_placeholder():
    # 0x03 is not a valid base protect value; base falls through to UNKNOWN
    r = decode_protect(0x03)
    assert r.startswith("UNKNOWN")


def test_decode_vad_type():
    assert decode_vad_type(0) == "VadNone"
    assert decode_vad_type(2) == "VadImageMap"
    assert decode_vad_type("2") == "VadImageMap"
    assert decode_vad_type(99).startswith("UNKNOWN")


def test_decode_service_start():
    assert decode_service_start(0) == "SERVICE_BOOT_START"
    assert decode_service_start(2) == "SERVICE_AUTO_START"
    assert decode_service_start(4) == "SERVICE_DISABLED"


def test_decode_service_type():
    assert decode_service_type(0x001) == "SERVICE_KERNEL_DRIVER"
    assert decode_service_type(0x010) == "SERVICE_WIN32_OWN_PROCESS"
    # With interactive bit
    assert "INTERACTIVE" in decode_service_type(0x110)


def test_decode_pool_tag_ascii():
    # "Spsx" packed LE: S=0x53, p=0x70, s=0x73, x=0x78
    # little-endian bytes: [0x53, 0x70, 0x73, 0x78] -> uint32 0x78737053
    assert decode_pool_tag(0x78737053) == "Spsx"


def test_decode_pool_tag_nonprintable_falls_back_to_hex():
    r = decode_pool_tag(0x01020304)
    assert r.startswith("0x")


def test_decode_granted_access_composed():
    r = decode_granted_access(0x00120089)
    assert "READ_CONTROL" in r
    assert "SYNCHRONIZE" in r


def test_decode_granted_access_generic_read():
    r = decode_granted_access(0x80000000)
    assert "GENERIC_READ" in r


def test_decode_mem_state_and_type():
    assert decode_mem_state(0x1000) == "MEM_COMMIT"
    assert decode_mem_state(0x2000) == "MEM_RESERVE"
    assert decode_mem_state(0x10000) == "MEM_FREE"
    assert decode_mem_type(0x20000) == "MEM_PRIVATE"
    assert decode_mem_type(0x40000) == "MEM_MAPPED"
    assert decode_mem_type(0x1000000) == "MEM_IMAGE"


def test_attach_decoded_vad_context():
    row = {"start": 0x1000, "end": 0x2000, "protect": 0x40, "vad_type": 2}
    out = attach_decoded(row, context="vad")
    assert out["protect"] == 0x40
    assert out["protect_decoded"] == "PAGE_EXECUTE_READWRITE"
    assert out["vad_type_decoded"] == "VadImageMap"
    # `start` is NOT a service field in vad context; no service_start decode
    assert "start_decoded" not in out


def test_attach_decoded_service_context():
    row = {"name": "foo", "start": 2, "type": 0x001, "image_path": "..."}
    out = attach_decoded(row, context="service")
    assert out["start_decoded"] == "SERVICE_AUTO_START"
    assert out["type_decoded"] == "SERVICE_KERNEL_DRIVER"


def test_attach_decoded_list_forces_context():
    rows = [{"start": 0x1000, "end": 0x2000, "protect": 0x20, "vad_type": 1},
            {"start": 0x3000, "end": 0x4000, "protect": 0x04, "vad_type": 2}]
    out = attach_decoded_list(rows, "vad")
    assert out[0]["protect_decoded"] == "PAGE_EXECUTE_READ"
    assert out[1]["vad_type_decoded"] == "VadImageMap"


def test_attach_decoded_leaves_unknown_fields_alone():
    row = {"custom_field": 0x1234, "protect": 0x20}
    out = attach_decoded(row, context="region")
    assert out["custom_field"] == 0x1234
    assert out["protect_decoded"] == "PAGE_EXECUTE_READ"


def test_decode_functions_never_raise_on_garbage():
    for fn in (decode_protect, decode_vad_type, decode_service_start,
                decode_service_type, decode_pool_tag, decode_granted_access,
                decode_mem_state, decode_mem_type):
        assert isinstance(fn("not-a-number"), str)
        assert isinstance(fn(None), str)
