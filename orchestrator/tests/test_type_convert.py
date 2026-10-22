"""Unit tests for the pure-compute type_convert primitives.

Every assertion documents an invariant the LLM will rely on. Tests are
sync (functions in conversions.py are pure) but pytest-asyncio auto-mode
is fine with that. No fixtures needed — no I/O, no network, no target.
"""
from __future__ import annotations

import base64
import hashlib
import struct

import pytest

from suspex.mcp import conversions as cv


# ---------------------------------------------------------------------------
# Type namespace / parser
# ---------------------------------------------------------------------------


class TestTypeNamespace:
    def test_int_aliases_resolve(self) -> None:
        for alias, canonical in [("uint32", "u32"), ("dword", "u32"),
                                 ("byte", "u8"), ("qword", "u64"),
                                 ("int", "i32"), ("long", "i32")]:
            assert cv.canonicalize_type(alias) == canonical

    def test_float_aliases(self) -> None:
        assert cv.canonicalize_type("float") == "f32"
        assert cv.canonicalize_type("double") == "f64"

    def test_case_insensitive(self) -> None:
        assert cv.canonicalize_type("U32") == "u32"
        assert cv.canonicalize_type("Base64") == "base64"

    def test_encoding_normalization(self) -> None:
        assert cv.canonicalize_type("b64") == "base64"
        assert cv.canonicalize_type("qp") == "quoted-printable"
        assert cv.canonicalize_type("hex_upper") == "hex-upper"

    def test_unknown_type_raises_with_hint(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.canonicalize_type("nonsense")
        assert exc.value.kind == "unknown_type"
        assert "u8" in exc.value.hint  # hint lists valid types


class TestValueParser:
    def test_hex_forms(self) -> None:
        assert cv.parse_int("0xDEAD") == 0xDEAD
        assert cv.parse_int("0X1234") == 0x1234
        assert cv.parse_int("FFh") == 0xFF
        assert cv.parse_int("-0x10") == -0x10

    def test_underscore_separators(self) -> None:
        assert cv.parse_int("1_000_000") == 1000000
        assert cv.parse_int("0xDEAD_BEEF") == 0xDEADBEEF

    def test_binary_and_octal(self) -> None:
        assert cv.parse_int("0b1010") == 10
        assert cv.parse_int("1010b") == 10
        assert cv.parse_int("0o777") == 511

    def test_int_passthrough(self) -> None:
        assert cv.parse_int(42) == 42
        assert cv.parse_int(True) == 1

    def test_float_rejected_as_int(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.parse_int(3.14)
        assert exc.value.kind == "unparseable_value"

    def test_hex_bytes_variants(self) -> None:
        assert cv.parse_hex_bytes("4d5a9000") == b"\x4d\x5a\x90\x00"
        assert cv.parse_hex_bytes("4D 5A 90 00") == b"\x4d\x5a\x90\x00"
        assert cv.parse_hex_bytes("0x4d,0x5a,0x90,0x00") == b"\x4d\x5a\x90\x00"
        assert cv.parse_hex_bytes(r"\x4d\x5a\x90\x00") == b"\x4d\x5a\x90\x00"

    def test_odd_length_hex_error(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.parse_hex_bytes("4D5")
        assert exc.value.kind == "unparseable_value"


# ---------------------------------------------------------------------------
# Cast — the workhorse
# ---------------------------------------------------------------------------


class TestCastInt:
    def test_u64_to_u32_truncates(self) -> None:
        r = cv.do_cast("0xFFFFFFFF00000001", "u64", "u32")
        assert r["value"] == 1
        assert r["hex"] == "0x00000001"
        assert r["notes"]["truncated_bits"] == 32
        assert r["notes"]["lossless"] is False

    def test_u32_to_u64_widens_lossless(self) -> None:
        r = cv.do_cast("0xDEADBEEF", "u32", "u64")
        assert r["value"] == 0xDEADBEEF
        assert r["notes"]["lossless"] is True
        assert r["notes"]["truncated_bits"] == 0

    def test_uint_to_int_sign_change(self) -> None:
        r = cv.do_cast("0xFFFFFFFF", "u32", "i32")
        assert r["value"] == -1
        assert r["notes"]["sign_change"] is True

    def test_int_to_uint_negative_becomes_bit_pattern(self) -> None:
        r = cv.do_cast(-1, "i32", "u32")
        assert r["value"] == 0xFFFFFFFF

    def test_i8_to_i32_sign_extends(self) -> None:
        r = cv.do_cast("0xFF", "i8", "i32")
        assert r["value"] == -1  # 0xFF as i8 = -1, sign-extended to i32

    def test_u8_to_u32_zero_extends(self) -> None:
        r = cv.do_cast("0xFF", "u8", "u32")
        assert r["value"] == 0xFF

    def test_ntstatus_to_u32(self) -> None:
        r = cv.do_cast("0xC0000005", "u32", "u32")
        assert r["value"] == 0xC0000005
        # views (called separately) surfaces the symbol; cast keeps compact


class TestCastFloat:
    def test_u32_to_f32_bitcast(self) -> None:
        # 0x40490FDB is pi in IEEE 754 single
        r = cv.do_cast("0x40490FDB", "u32", "f32")
        assert abs(r["value"] - 3.1415927) < 1e-6

    def test_f32_to_u32_roundtrip(self) -> None:
        packed = cv.do_cast(3.1415927, "f32", "u32")
        assert packed["value"] == 0x40490FDB

    def test_f64_to_u64_roundtrip(self) -> None:
        r = cv.do_cast(2.718281828459045, "f64", "u64")
        (back,) = struct.unpack("<d", r["value"].to_bytes(8, "little"))
        assert abs(back - 2.718281828459045) < 1e-15


class TestCastBytes:
    def test_bytes_to_u32_le(self) -> None:
        r = cv.do_cast("4d5a9000", "bytes", "u32", "little")
        assert r["value"] == 0x00905A4D  # DOS "MZ\x90\x00" as LE u32

    def test_bytes_to_u32_be(self) -> None:
        r = cv.do_cast("4d5a9000", "bytes", "u32", "big")
        assert r["value"] == 0x4D5A9000

    def test_int_to_bytes_le(self) -> None:
        r = cv.do_cast("0xDEADBEEF", "u32", "bytes", "little")
        assert r["hex"] == "efbeadde"

    def test_int_to_bytes_be(self) -> None:
        r = cv.do_cast("0xDEADBEEF", "u32", "bytes", "big")
        assert r["hex"] == "deadbeef"


class TestCastErrors:
    def test_unknown_from_type(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.do_cast(1, "bogus", "u32")
        assert exc.value.kind == "unknown_type"

    def test_unknown_endian(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.do_cast(1, "u32", "bytes", "middle")
        assert exc.value.kind == "unknown_type"


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


class TestViews:
    def test_views_returns_every_form(self) -> None:
        r = cv.views(0xDEADBEEF, "u32")
        assert r["hex"] == "0xDEADBEEF"
        assert r["bin"].startswith("0b")
        assert r["oct"].startswith("0o")
        assert r["signed"] == -559038737  # -0x21524111
        assert r["unsigned"] == 0xDEADBEEF
        assert "bytes_le" in r and "bytes_be" in r
        assert "as_f32_le" in r

    def test_views_auto_err_lookup(self) -> None:
        r = cv.views(0xC0000005, "u32")
        assert "error_lookup" in r
        assert r["error_lookup"]["symbol"] == "STATUS_ACCESS_VIOLATION"

    def test_views_size_iec_readable(self) -> None:
        r = cv.views(1024 * 1024, "u64")
        assert r["size_iec"] == "1.000 MiB"


# ---------------------------------------------------------------------------
# Pack / unpack / swap / split / join
# ---------------------------------------------------------------------------


class TestPackUnpack:
    def test_pack_unpack_roundtrip_int(self) -> None:
        for tp in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"):
            for endian in ("little", "big"):
                p = cv.do_pack(0x12, tp, endian)
                u = cv.do_unpack(p["hex"], tp, endian)
                assert u["value"] == 0x12

    def test_pack_unpack_roundtrip_float(self) -> None:
        for tp in ("f32", "f64"):
            p = cv.do_pack(3.14, tp, "little")
            u = cv.do_unpack(p["hex"], tp, "little")
            # f32 loses precision; assert closeness scaled to type
            tol = 1e-6 if tp == "f32" else 1e-15
            assert abs(u["value"] - 3.14) < tol


class TestSwap:
    def test_swap_16(self) -> None:
        r = cv.do_swap("0x1234", 2)
        assert r["output"]["value"] == 0x3412

    def test_swap_32(self) -> None:
        r = cv.do_swap("0xDEADBEEF", 4)
        assert r["output"]["value"] == 0xEFBEADDE

    def test_swap_64(self) -> None:
        r = cv.do_swap("0x0102030405060708", 8)
        assert r["output"]["value"] == 0x0807060504030201

    def test_swap_invalid_width(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.do_swap(1, 3)
        assert exc.value.kind == "width_mismatch"


class TestSplitJoin:
    def test_split_qword_into_dwords(self) -> None:
        r = cv.do_split("0xDEADBEEFCAFEBABE", 8)
        assert r["hi"]["value"] == 0xDEADBEEF
        assert r["lo"]["value"] == 0xCAFEBABE

    def test_split_dword_into_words(self) -> None:
        r = cv.do_split("0xDEADBEEF", 4)
        assert r["hi"]["value"] == 0xDEAD
        assert r["lo"]["value"] == 0xBEEF

    def test_split_bytes_into_chunks(self) -> None:
        r = cv.do_split(0, 4, data_hex="deadbeefcafebabe")
        assert r["count"] == 2
        assert r["chunks"][0]["u_le"] == 0xEFBEADDE

    def test_join_reverses_split(self) -> None:
        r = cv.do_join(["0xCAFEBABE", "0xDEADBEEF"], 4, "little")
        # join concatenates in order: lo || hi as raw bytes
        assert r["combined_unsigned"] == 0xDEADBEEFCAFEBABE


# ---------------------------------------------------------------------------
# Bits presets
# ---------------------------------------------------------------------------


class TestBits:
    def test_page_execute_readwrite(self) -> None:
        r = cv.decode_bits(0x40, preset="page_protect")
        assert "PAGE_EXECUTE_READWRITE" in r["set"]

    def test_process_all_access_matches_composite(self) -> None:
        r = cv.decode_bits(0x001FFFFF, preset="process_access")
        # 0x001FFFFF is PROCESS_ALL_ACCESS (composite) plus sub-flags
        assert "PROCESS_ALL_ACCESS" in r["set"]

    def test_bits_custom_names(self) -> None:
        r = cv.decode_bits(0x5, names={"0x1": "A", "0x2": "B", "0x4": "C"})
        assert set(r["set"]) == {"A", "C"}
        assert "B" in r["clear"]

    def test_bits_unknown_bits_surfaced(self) -> None:
        r = cv.decode_bits(0xFF, names={"0x1": "A"})
        assert r["unknown_bits"] == 0xFE


# ---------------------------------------------------------------------------
# err_lookup
# ---------------------------------------------------------------------------


class TestErrLookup:
    def test_win32_lookup(self) -> None:
        r = cv.lookup_err(5)
        assert r["symbol"] == "ACCESS_DENIED"

    def test_ntstatus_decompose(self) -> None:
        r = cv.lookup_err(0xC0000005)
        assert r["symbol"] == "STATUS_ACCESS_VIOLATION"
        assert r["ntstatus"]["severity"] == "ERROR"

    def test_hresult_decompose(self) -> None:
        r = cv.lookup_err(0x80070005, space="hresult")
        assert r["hresult"]["severity"] == "FAILURE"
        assert r["hresult"]["facility_name"] == "WIN32"
        assert r["hresult"]["code"] == 5  # ERROR_ACCESS_DENIED


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


class TestTime:
    def test_filetime_iso_roundtrip(self) -> None:
        # Pick a canonical FILETIME (Unix epoch itself: 1970-01-01Z)
        ft = 116_444_736_000_000_000  # documented Windows FILETIME for 1970-01-01
        r = cv.time_convert(ft, "filetime", "iso8601")
        assert r["output"]["iso8601"].startswith("1970-01-01T00:00:00")
        back = cv.time_convert(r["output"]["iso8601"], "iso8601", "filetime")
        assert back["output"]["filetime"] == ft

    def test_unix_epoch_roundtrip(self) -> None:
        ts = 1_788_004_800  # arbitrary future timestamp
        r = cv.time_convert(ts, "unix_epoch", "iso8601")
        back = cv.time_convert(r["output"]["iso8601"], "iso8601", "unix_epoch")
        assert back["output"]["unix_epoch"] == ts

    def test_filetime_at_unix_epoch(self) -> None:
        r = cv.time_convert("1970-01-01T00:00:00Z", "iso8601", "unix_epoch")
        assert r["output"]["unix_epoch"] == 0

    def test_systemtime_roundtrip(self) -> None:
        r = cv.time_convert("2026-09-09T12:34:56Z", "iso8601", "systemtime")
        back = cv.time_convert(None, "systemtime", "iso8601",
                               data_hex=r["output"]["systemtime_hex"])
        assert back["output"]["iso8601"].startswith("2026-09-09T12:34:56")


# ---------------------------------------------------------------------------
# GUID
# ---------------------------------------------------------------------------


class TestGuid:
    STRING = "{DEADBEEF-1234-5678-9ABC-DEF012345678}"

    def test_guid_string_to_windows_bytes(self) -> None:
        r = cv.guid_convert(self.STRING, form="string")
        assert r["string"] == self.STRING
        # Windows binary form: first three groups byteswapped
        assert r["bytes_windows"].startswith("efbeadde")  # DEADBEEF LE
        assert r["bytes_windows"][8:12] == "3412"          # 1234 LE

    def test_guid_windows_roundtrip(self) -> None:
        r1 = cv.guid_convert(self.STRING, form="string")
        r2 = cv.guid_convert(None, form="bytes_windows",
                             data_hex=r1["bytes_windows"])
        assert r2["string"] == self.STRING


# ---------------------------------------------------------------------------
# Encoding — the user-requested category
# ---------------------------------------------------------------------------


class TestEncode:
    PLAIN = b"Hello, suspex0!"

    def test_base64_roundtrip(self) -> None:
        enc = cv.encode_bytes(self.PLAIN.hex(), "base64")
        assert enc["output"] == base64.b64encode(self.PLAIN).decode()
        dec = cv.decode_text(enc["output"], "base64")
        assert dec["hex"] == self.PLAIN.hex()

    def test_base64url_no_pad(self) -> None:
        enc = cv.encode_bytes(self.PLAIN.hex(), "base64url", pad=False)
        assert "=" not in enc["output"]
        dec = cv.decode_text(enc["output"], "base64url")
        assert dec["hex"] == self.PLAIN.hex()

    def test_base32_roundtrip(self) -> None:
        enc = cv.encode_bytes(self.PLAIN.hex(), "base32")
        dec = cv.decode_text(enc["output"], "base32")
        assert dec["hex"] == self.PLAIN.hex()

    def test_base85_roundtrip(self) -> None:
        enc = cv.encode_bytes(self.PLAIN.hex(), "base85")
        dec = cv.decode_text(enc["output"], "base85")
        assert dec["hex"] == self.PLAIN.hex()

    def test_hex_spaced_output(self) -> None:
        enc = cv.encode_bytes("48656c6c6f", "hex-spaced")
        assert enc["output"] == "48 65 6c 6c 6f"

    def test_hex_c_array_output(self) -> None:
        enc = cv.encode_bytes("48656c6c6f", "hex-c-array")
        assert enc["output"] == "{ 0x48, 0x65, 0x6C, 0x6C, 0x6F }"

    def test_url_roundtrip(self) -> None:
        enc = cv.encode_bytes("48656c6c6f2c20776f726c6421", "url")
        dec = cv.decode_text(enc["output"], "url")
        assert bytes.fromhex(dec["hex"]) == b"Hello, world!"

    def test_rot13(self) -> None:
        enc = cv.encode_bytes("48656c6c6f", "rot13")
        assert enc["output"] == "Uryyb"

    def test_wrap_output(self) -> None:
        long = b"A" * 200
        enc = cv.encode_bytes(long.hex(), "base64", wrap=64)
        assert "\n" in enc["output"]
        # Roundtrip after stripping wrap
        joined = enc["output"].replace("\n", "")
        dec = cv.decode_text(joined, "base64")
        assert dec["hex"] == long.hex()

    def test_unsupported_encoding_raises(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.encode_bytes("48", "morse")
        assert exc.value.kind == "unknown_type"


# ---------------------------------------------------------------------------
# str_convert
# ---------------------------------------------------------------------------


class TestStrConvert:
    def test_utf8_bytes_to_str(self) -> None:
        r = cv.str_convert(data_hex="48656c6c6f", from_type="utf-8", to_type="str")
        assert r["str"] == "Hello"

    def test_utf16le_strip_nul(self) -> None:
        # "Hi" as UTF-16-LE with NUL terminator: 48 00 69 00 00 00
        r = cv.str_convert(data_hex="480069000000", from_type="utf-16-le",
                           to_type="str", strip_nul=True)
        assert r["str"] == "Hi"

    def test_str_to_utf16le(self) -> None:
        r = cv.str_convert(value="Hi", from_type="str", to_type="utf-16-le")
        assert r["hex"] == "48006900"

    def test_transcode_utf8_to_cp1252(self) -> None:
        # "café" in utf-8 → cp1252
        r = cv.str_convert(data_hex="636166c3a9",
                           from_type="utf-8", to_type="cp1252")
        assert bytes.fromhex(r["hex"]) == "café".encode("cp1252")

    def test_strict_error_reported(self) -> None:
        # 0xC3 alone is invalid utf-8; strict must surface it
        with pytest.raises(cv.ConversionError) as exc:
            cv.str_convert(data_hex="c3", from_type="utf-8", to_type="str")
        assert exc.value.kind == "encoding_error"

    def test_replace_errors_completes(self) -> None:
        r = cv.str_convert(data_hex="c3", from_type="utf-8", to_type="str",
                           errors="replace")
        assert "�" in r["str"]


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


class TestHash:
    PLAIN_HEX = b"Hello".hex()

    def test_sha256_matches_hashlib(self) -> None:
        r = cv.hash_bytes(self.PLAIN_HEX, "sha256")
        assert r["hex"] == hashlib.sha256(b"Hello").hexdigest()

    def test_md5_matches_hashlib(self) -> None:
        r = cv.hash_bytes(self.PLAIN_HEX, "md5")
        assert r["hex"] == hashlib.md5(b"Hello").hexdigest()

    def test_crc32(self) -> None:
        import zlib
        r = cv.hash_bytes(self.PLAIN_HEX, "crc32")
        assert int(r["hex"], 16) == zlib.crc32(b"Hello")

    def test_hmac(self) -> None:
        import hmac
        key = b"secret"
        r = cv.hash_bytes(self.PLAIN_HEX, "sha256", hmac_key_hex=key.hex())
        assert r["hex"] == hmac.new(key, b"Hello", "sha256").hexdigest()

    def test_salt_prepended(self) -> None:
        r_salted = cv.hash_bytes(self.PLAIN_HEX, "sha256", salt_hex="abcd")
        r_manual = cv.hash_bytes((bytes.fromhex("abcd") + b"Hello").hex(),
                                 "sha256")
        assert r_salted["hex"] == r_manual["hex"]

    def test_unknown_algo_error(self) -> None:
        with pytest.raises(cv.ConversionError) as exc:
            cv.hash_bytes(self.PLAIN_HEX, "sha999")
        assert exc.value.kind == "hash_unavailable"


# ---------------------------------------------------------------------------
# Round-trip invariants — the "trust me" tests
# ---------------------------------------------------------------------------


class TestRoundTripInvariants:
    @pytest.mark.parametrize("v", [0, 1, 0xFF, 0x1234, 0xDEADBEEF,
                                    0xDEADBEEFCAFEBABE])
    def test_widen_narrow_uint_roundtrips(self, v: int) -> None:
        # u32 ↔ u64 must round-trip when v fits in u32
        if v > 0xFFFFFFFF:
            return
        widened = cv.do_cast(v, "u32", "u64")["value"]
        back = cv.do_cast(widened, "u64", "u32")["value"]
        assert back == v

    @pytest.mark.parametrize("encoding", ["base64", "base64url", "base32",
                                          "base32hex", "base16", "base85",
                                          "ascii85", "hex", "hex-upper",
                                          "url", "quoted-printable"])
    def test_encoding_roundtrip(self, encoding: str) -> None:
        payload = bytes(range(256))
        enc = cv.encode_bytes(payload.hex(), encoding)
        dec = cv.decode_text(enc["output"], encoding)
        assert dec["hex"] == payload.hex()

    def test_int_pack_unpack_roundtrip_all_widths(self) -> None:
        for tp, val in [("u8", 0xAB), ("u16", 0x1234), ("u32", 0xDEADBEEF),
                        ("u64", 0xCAFEBABEDEADBEEF),
                        ("i8", -50), ("i16", -30000), ("i32", -1_000_000)]:
            for endian in ("little", "big"):
                p = cv.do_pack(val, tp, endian)
                u = cv.do_unpack(p["hex"], tp, endian)
                assert u["value"] == val, f"{tp}/{endian} @ {val}"

    def test_swap_double_is_identity(self) -> None:
        for width in (2, 4, 8):
            val = 0xDEADBEEFCAFEBABE & cv._mask(width)
            once = cv.do_swap(val, width)["output"]["value"]
            twice = cv.do_swap(once, width)["output"]["value"]
            assert twice == val


# ---------------------------------------------------------------------------
# Sanity: the tool constants agree with the module surface
# ---------------------------------------------------------------------------


def test_all_hash_algos_reachable() -> None:
    """Every algorithm listed in HASH_ALGOS either resolves or reports a
    clean hash_unavailable — no other kind, no bare exception."""
    for algo in cv.HASH_ALGOS:
        try:
            cv.hash_bytes("00", algo)
        except cv.ConversionError as exc:
            assert exc.kind == "hash_unavailable", f"{algo}: {exc.kind}"
