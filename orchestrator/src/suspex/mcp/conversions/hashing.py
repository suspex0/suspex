"""Hashing / HMAC / CRC / xxhash primitives, and the async-offload threshold."""

from __future__ import annotations

import hashlib
import hmac
import zlib
from typing import Any

from .errors import ConversionError
from .pack import parse_hex_bytes

# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def hash_bytes(data_hex: str, algorithm: str = "sha256",
               hmac_key_hex: str = "", salt_hex: str = "") -> dict[str, Any]:
    algo = algorithm.strip().lower().replace("_", "-")
    salt = parse_hex_bytes(salt_hex) if salt_hex else b""
    data = salt + parse_hex_bytes(data_hex)

    if hmac_key_hex:
        key = parse_hex_bytes(hmac_key_hex)
        try:
            digest = hmac.new(key, data,
                              algo.replace("-", "_") if "sha3" in algo else algo)
        except (ValueError, TypeError) as exc:
            raise ConversionError(
                "hash_unavailable", f"hmac with {algorithm!r} not available: {exc}",
                hint="pick a hashlib-supported algorithm (md5, sha1, sha256, …)",
            ) from exc
        return {"algorithm": f"hmac-{algo}", "hex": digest.hexdigest(),
                "length_bytes": digest.digest_size,
                "input_bytes": len(data), "keyed": True}

    if algo == "crc32":
        v = zlib.crc32(data) & 0xFFFFFFFF
        return {"algorithm": "crc32", "hex": f"{v:08x}", "value": v,
                "length_bytes": 4, "input_bytes": len(data)}
    if algo == "adler32":
        v = zlib.adler32(data) & 0xFFFFFFFF
        return {"algorithm": "adler32", "hex": f"{v:08x}", "value": v,
                "length_bytes": 4, "input_bytes": len(data)}
    if algo in ("xxh64", "xxh32"):
        try:
            import xxhash  # type: ignore
        except ImportError as exc:
            raise ConversionError(
                "hash_unavailable",
                f"{algo} needs the optional 'xxhash' package",
                hint="install it: uv add xxhash (or pip install xxhash)",
            ) from exc
        h = xxhash.xxh64() if algo == "xxh64" else xxhash.xxh32()
        h.update(data)
        return {"algorithm": algo, "hex": h.hexdigest(),
                "length_bytes": h.digest_size, "input_bytes": len(data)}
    # Everything else goes through hashlib.
    hashlib_name = algo.replace("-", "_") if algo.startswith("sha3") else algo
    try:
        h = hashlib.new(hashlib_name)
    except ValueError as exc:
        raise ConversionError(
            "hash_unavailable", f"algorithm {algorithm!r} not supported",
            hint="hashlib knows: " + ", ".join(sorted(hashlib.algorithms_available)),
        ) from exc
    h.update(data)
    return {"algorithm": algo, "hex": h.hexdigest(),
            "length_bytes": h.digest_size, "input_bytes": len(data)}


# Threshold above which the tools.py caller should route through
# asyncio.to_thread. Keep the fast path in the event loop for typical
# small conversions.
THREAD_OFFLOAD_BYTES = 64 * 1024
