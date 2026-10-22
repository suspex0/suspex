"""String and IOC extraction over raw byte buffers.

Pure compute — usable on an artifact on disk (``bin_manage``) or a live
memory read result (``mem_rw strings``). All limits are hard caps: a
hostile blob cannot grow output unboundedly.
"""

from __future__ import annotations

import re

MAX_STRINGS = 20_000
MAX_IOCS = 4_096
MIN_LEN_FLOOR = 3
MIN_LEN_CAP = 256

_ASCII_MIN_RUN = 3  # internal floor regardless of caller min_len


def find_strings(data: bytes, *, min_len: int = 5,
                 utf16: bool = True, cap: int = MAX_STRINGS,
                 base_va: int = 0) -> list[dict]:
    """Extract ASCII and aligned UTF-16LE strings with file offsets.

    Returns ``[{offset, kind:"ascii"|"utf16", value}]`` sorted by offset,
    capped at *cap* entries. ``truncated`` is implied by len == cap.
    When *base_va* is non-zero each row also gets ``va`` = base_va+offset
    (live-range scans).
    """
    min_len = max(MIN_LEN_FLOOR, min(int(min_len or 5), MIN_LEN_CAP))
    out: list[dict] = []
    n = len(data)
    i = 0
    while i < n and len(out) < cap:
        b = data[i]
        if 0x20 <= b < 0x7F:
            start = i
            while i < n and 0x20 <= data[i] < 0x7F:
                i += 1
            run = i - start
            if run >= min_len:
                out.append({"offset": start, "kind": "ascii",
                            "value": data[start:i].decode("ascii")})
            continue
        i += 1
    if utf16 and len(out) < cap:
        # UTF-16LE ASCII range: printable byte followed by NUL, aligned on
        # even offsets (the PE/loader convention knife follows).
        i = 0
        while i + 3 < n and len(out) < cap:
            if (0x20 <= data[i] < 0x7F and data[i + 1] == 0
                    and 0x20 <= data[i + 2] < 0x7F and data[i + 3] == 0):
                start = i
                chars = bytearray()
                while (i + 1 < n and 0x20 <= data[i] < 0x7F
                       and data[i + 1] == 0):
                    chars.append(data[i])
                    i += 2
                if len(chars) >= min_len:
                    out.append({"offset": start, "kind": "utf16",
                                "value": chars.decode("ascii")})
                continue
            i += 2  # even-aligned scan only (loader convention)
    out.sort(key=lambda r: r["offset"])
    if base_va:
        for r in out:
            r["va"] = base_va + r["offset"]
    return out


# ---------------------------------------------------------------------------
# IOC extraction — patterns are deliberately conservative; a plausible-shape
# match beats a permissive one (knife's plausibility-filtered approach).
# ---------------------------------------------------------------------------

_RE_URL = re.compile(
    r"\b(?:https?|ftp|socks[45]?)://[^\s\"'<>\)\]]{4,}", re.I)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|info|biz|ru|cn|su|cc|pw|top|xyz|onion|"
    r"co|uk|de|jp|br|in|me|tv|ws|name|pro|gov|mil|edu)\b", re.I)
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# Registry keys — both hive-letter and full-hive spellings.
_RE_REGKEY = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
    r"(?:\\[^\s\"'<>|]{1,200})+")
# Win paths: drive-letter or UNC with at least one directory component.
_RE_WINPATH = re.compile(
    r"(?:\b[A-Za-z]:\\|\\\\[^\s\"'<>|]{1,64}\\)[^\s\"'<>|]{1,200}")
# Unix paths: absolute, >= 2 components, common roots only (noise floor).
_RE_UNIXPATH = re.compile(
    r"\b(?:/(?:etc|usr|var|tmp|opt|home|root|bin|sbin|lib|proc|sys|dev|run|mnt)"
    r"(?:/[^\s\"'<>|]{0,120}){1,4})")
_RE_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b")


def _plausible_ipv4(ip: str) -> bool:
    if ip in ("0.0.0.0", "255.255.255.255"):
        return False
    parts = ip.split(".")
    # 127.* loopback and link-local are uninteresting as IOCs; version-
    # shaped strings (e.g. "4.0.30319.1" sneaking past) get filtered by the
    # regex already, but reject the all-zeros and broadcast edges here.
    if parts[0] == "0" or parts[0] == "255":
        return False
    return True


def defang(value: str) -> str:
    """Make an indicator safe to paste: hxxp://, [.], @→[at]."""
    out = re.sub(r"^https?", lambda m: m.group(0).replace("ttp", "xxp"),
                 value, flags=re.I)
    out = out.replace(".", "[.]").replace("@", "[at]")
    return out


def find_iocs(data: bytes, *, cap: int = MAX_IOCS,
              include_strings_scan: bool = True,
              base_va: int = 0) -> list[dict]:
    """Extract indicators of compromise from *data*.

    Scans the decoded string surface (ASCII + UTF-16) rather than raw
    bytes so wide-char payloads are covered. Returns
    ``[{kind, value, defanged, offset, count}]`` — duplicates collapse
    into ``count``. Order: first-seen.
    """
    strings = find_strings(data, min_len=4) if include_strings_scan else []
    seen: dict[tuple[str, str], dict] = {}
    for s in strings:
        text = s["value"]
        for kind, rx in (
            ("url", _RE_URL), ("ipv4", _RE_IPV4), ("domain", _RE_DOMAIN),
            ("email", _RE_EMAIL), ("btc_wallet", _RE_BTC),
            ("registry_key", _RE_REGKEY), ("win_path", _RE_WINPATH),
            ("unix_path", _RE_UNIXPATH), ("guid", _RE_GUID),
        ):
            for m in rx.finditer(text):
                val = m.group(0)
                if kind == "ipv4" and not _plausible_ipv4(val):
                    continue
                if kind == "domain" and val.lower().endswith(
                        (".dll", ".exe", ".sys")):
                    continue  # filenames, not domains
                key = (kind, val)
                row = seen.get(key)
                if row is None:
                    if len(seen) >= cap:
                        return list(seen.values())
                    row = {"kind": kind, "value": val,
                           "defanged": defang(val), "offset": s["offset"],
                           "count": 0}
                    seen[key] = row
                row["count"] += 1
    rows = list(seen.values())
    if base_va:
        for r in rows:
            r["va"] = base_va + r["offset"]
    return rows
