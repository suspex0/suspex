"""Optional YARA integration (extra: `pip install suspex0[yara]`).

Scans local artifacts or remote files (streamed into a cache dir first) with
inline rule sources or rule files. Kept dependency-free at import time so the
core stack works without yara-python installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:  # optional dependency
    import yara as _yara  # type: ignore
except ImportError:  # pragma: no cover - exercised only without the extra
    _yara = None


def yara_available() -> bool:
    return _yara is not None


def compile_source(rule_src: str):
    if _yara is None:
        raise RuntimeError("yara-python not installed (pip install suspex0[yara])")
    return _yara.compile(source=rule_src)


def _match_dict(m) -> dict[str, Any]:
    return {
        "rule": m.rule,
        "namespace": m.namespace,
        "tags": list(m.tags),
        "meta": dict(m.meta),
        "strings": [{"offset": s.instances[0].offset if s.instances else -1,
                     "identifier": s.identifier,
                     "data": bytes(s.instances[0].matched_data)[:64].hex()
                     if s.instances else ""} for s in m.strings],
    }


def yara_scan_blob(data: bytes, rule_src: str) -> list[dict[str, Any]]:
    rules = compile_source(rule_src)
    return [_match_dict(m) for m in rules.match(data=bytes(data))]


def yara_scan_file(path: str | Path, rule_src: str) -> list[dict[str, Any]]:
    return yara_scan_blob(Path(path).read_bytes(), rule_src)


async def yara_scan_remote_file(client: Any, remote_path: str, rule_src: str,
                                cache_dir: Path) -> tuple[list[dict[str, Any]], str]:
    """Downloads the remote file into artifacts/yara/ and scans it locally.

    Returns (matches, error) — error is "" on success.
    """
    try:
        cache = Path(cache_dir) / "yara"
        cache.mkdir(parents=True, exist_ok=True)
        name = remote_path.replace("\\", "/").split("/")[-1] or "remote.bin"
        local = cache / name
        info = await client.file_download(remote_path, str(local))
        matches = yara_scan_file(local, rule_src)
        return matches, ""
    except Exception as exc:  # download or scan failure
        return [], f"{type(exc).__name__}: {exc}"


async def yara_scan_module(client: Any, pid: int, module: str, rule_src: str,
                           max_bytes: int = 256 * 1024 * 1024) -> tuple[list[dict[str, Any]], str]:
    """Pulls a module image from pid through the connected view and scans it."""
    try:
        mods = await client.mem_modules(pid)
        want = module.lower()
        base = size = 0
        for m in mods:
            n = str(m.get("name", "")).lower()
            if n == want or n.endswith("\\" + want):
                base = int(m.get("base", 0), 0) if isinstance(m.get("base"), str) else int(m.get("base", 0))
                size = int(m.get("size", 0), 0) if isinstance(m.get("size"), str) else int(m.get("size", 0))
                break
        if not base:
            return [], f"module {module!r} not found in pid {pid}"
        size = min(size, max_bytes)
        blob = bytearray()
        chunk = 0x100000
        off = 0
        while off < size:
            n = min(chunk, size - off)
            blob.extend(await client.mem_read(pid, base + off, n, "user"))
            off += n
        return yara_scan_blob(bytes(blob), rule_src), ""
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"
