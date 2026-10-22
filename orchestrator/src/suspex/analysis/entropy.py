"""Shannon entropy — whole-buffer score and bucketed maps.

Used by ``bin_manage entropy`` (artifacts) and ``mem_rw entropy`` (live
ranges). A score near 8.0 is dense random/encrypted/compressed data;
near 0 is uniform. Packer detection leans on the bucket map, not the
single score.
"""

from __future__ import annotations

import math

MAX_BUCKETS = 256


def shannon(data: bytes) -> float:
    """Shannon entropy of *data* in bits-per-byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


def bucket_map(data: bytes, buckets: int = 64) -> list[dict]:
    """Split *data* into *buckets* equal parts, entropy per bucket.

    Returns ``[{index, offset, size, entropy, suspicious}]`` — a bucket is
    flagged ``suspicious`` at entropy >= 7.2, the usual packed/encrypted
    threshold. Bucket count is capped at MAX_BUCKETS; tiny inputs collapse
    to a single bucket.
    """
    n = len(data)
    if n == 0:
        return []
    buckets = max(1, min(int(buckets or 64), MAX_BUCKETS, n))
    step = n / buckets
    out = []
    for i in range(buckets):
        lo = int(i * step)
        hi = int((i + 1) * step) if i < buckets - 1 else n
        chunk = data[lo:hi]
        e = shannon(chunk)
        out.append({
            "index": i,
            "offset": lo,
            "size": len(chunk),
            "entropy": round(e, 4),
            "suspicious": e >= 7.2,
        })
    return out


def entropy_map(data: bytes, buckets: int = 64) -> dict:
    """Whole-buffer entropy + bucket map + packed verdict in one call.

    ``packed`` is true when the mean exceeds 7.2 OR more than half the
    buckets are individually suspicious — a uniform-compressed blob and a
    blob that's half-packed both trip it.
    """
    bm = bucket_map(data, buckets)
    mean = shannon(data)
    peak = max((b["entropy"] for b in bm), default=0.0)
    susp = sum(1 for b in bm if b["suspicious"])
    packed = mean >= 7.2 or (bm and susp * 2 >= len(bm))
    return {
        "size": len(data),
        "mean_entropy": round(mean, 4),
        "max_entropy": peak,
        "suspicious_buckets": susp,
        "packed": bool(packed),
        "buckets": bm,
    }
