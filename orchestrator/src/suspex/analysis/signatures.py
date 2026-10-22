"""Constant scanning — crypto tables, packer markers, embedded formats.

Ported from knife's ``signatures`` pass: constants are *generated* at
import time (AES S-box via GF(2^8), SHA-256 K from cube roots of primes,
MD5 K from sine, CRC32 IEEE table) rather than stored, so the source of
truth is the algorithm, not a hex blob that could rot.
"""

from __future__ import annotations

import math
import struct

MAX_HITS = 4096


def _aes_sbox() -> bytes:
    """Generate the AES S-box: multiplicative inverse in GF(2^8) then the
    affine transform — the same bytes, never stored."""
    # GF(2^8) with polynomial 0x11B.
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1) & 0xFF if not (x & 0x80) else ((x << 1) ^ 0x11B) & 0xFF
        x &= 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    def gmul(a: int, b: int) -> int:
        return exp[log[a] + log[b]] if a and b else 0

    def ginv(a: int) -> int:
        return 0 if a == 0 else exp[255 - log[a]]

    def rotl(v: int, n: int) -> int:
        return ((v << n) | (v >> (8 - n))) & 0xFF

    out = bytearray()
    for i in range(256):
        inv = ginv(i)
        out.append((inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3)
                    ^ rotl(inv, 4) ^ 0x63) & 0xFF)
    return bytes(out)


def _sha256_k() -> bytes:
    """SHA-256 round constants: frac bits of cube roots of the first 64 primes."""
    primes: list[int] = []
    c = 2
    while len(primes) < 64:
        if all(c % p for p in primes):
            primes.append(c)
        c += 1
    out = bytearray()
    for p in primes:
        frac = (p ** (1.0 / 3.0)) % 1.0
        out += struct.pack(">I", int(frac * (1 << 32)))
    return bytes(out)


def _md5_k() -> bytes:
    """MD5 K table: floor(abs(sin(i+1)) * 2^32), little-endian words."""
    out = bytearray()
    for i in range(64):
        out += struct.pack("<I", int(abs(math.sin(i + 1)) * (1 << 32)))
    return bytes(out)


def _crc32_table() -> bytes:
    """IEEE CRC32 lookup table (poly 0xEDB88320), first 256 dwords."""
    out = bytearray()
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        out += struct.pack("<I", c)
    return bytes(out)


def _build_signatures() -> list[dict]:
    sbox = _aes_sbox()
    inv = bytearray(256)
    for i, v in enumerate(sbox):
        inv[v] = i
    sigs = [
        {"name": "aes_sbox", "category": "crypto",
         "bytes": sbox, "note": "AES substitution box (rijndael)"},
        {"name": "aes_inv_sbox", "category": "crypto",
         "bytes": bytes(inv), "note": "AES inverse S-box"},
        {"name": "aes_sbox_head", "category": "crypto",
         "bytes": sbox[:16], "note": "AES S-box prefix (16B)"},
        {"name": "sha256_k", "category": "crypto",
         "bytes": _sha256_k(), "note": "SHA-256 round constants"},
        {"name": "md5_k", "category": "crypto",
         "bytes": _md5_k(), "note": "MD5 sine-derived K table"},
        {"name": "crc32_ieee", "category": "crypto",
         "bytes": _crc32_table(), "note": "CRC32 (IEEE 802.3) lookup table"},
        {"name": "base64_alphabet", "category": "encoding",
         "bytes": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
         "note": "standard base64 alphabet"},
    ]
    # Packer / protector markers — short unique byte strings.
    for name, marker, note in (
        ("upx_marker", b"UPX!", "UPX packer magic"),
        ("aspack", b"ASPack", "ASPack protector"),
        ("pec2", b"PEC2", "PECompact marker"),
        ("themida", b"Themida", "Themida/WinLicense"),
        ("mpress", b"MPRESS", "MPRESS packer"),
        ("petite", b"petite", "Petite packer"),
        ("enigma", b"Enigma protector", "Enigma Virtual Box / protector"),
        ("vmp", b"VMProtect", "VMProtect"),
        ("dotnet_meta", b"BSJB", ".NET metadata root signature"),
    ):
        sigs.append({"name": name, "category": "packer_marker",
                     "bytes": marker, "note": note})
    return sigs


_SIGNATURES = _build_signatures()

# Known packer section names (checked on the PE's section table, not bytes).
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", "upx!": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".nsp0": "NsPack",
    ".nsp1": "NsPack", ".petite": "Petite", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".obsidium": "Obsidium",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".packed": "generic-packer",
    "pec2": "PECompact", ".perplex": "Perplex", ".rsrc!": "custom-packed",
}


def scan(data: bytes, *, cap: int = MAX_HITS) -> list[dict]:
    """Scan *data* for every known constant block + embedded PEs.

    Returns ``[{name, category, offset, note}]`` capped at *cap*. Embedded
    PE detection validates MZ → e_lfanew → 'PE\\0\\0' so raw 'MZ' text
    doesn't produce hits.
    """
    hits: list[dict] = []
    for sig in _SIGNATURES:
        needle = sig["bytes"]
        start = 0
        while len(hits) < cap:
            pos = data.find(needle, start)
            if pos < 0:
                break
            hits.append({"name": sig["name"], "category": sig["category"],
                         "offset": pos, "note": sig["note"]})
            start = pos + 1
    # Embedded PE images — validated, not just the two magic bytes.
    start = 0
    while len(hits) < cap:
        pos = data.find(b"MZ", start)
        if pos < 0:
            break
        start = pos + 1
        if pos == 0 or pos + 0x40 > len(data):
            continue
        e_lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
        if not (0 < e_lfanew < 0x400):
            continue
        sig_off = pos + e_lfanew
        if sig_off + 4 > len(data):
            continue
        if data[sig_off:sig_off + 4] == b"PE\0\0":
            hits.append({"name": "embedded_pe", "category": "embedded",
                         "offset": pos,
                         "note": "embedded PE image (validated header)"})
    hits.sort(key=lambda h: h["offset"])
    return hits[:cap]
