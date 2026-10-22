"""MemApi: view-dispatching memory primitives plus a local chunked
scanner that handles kernel ranges too."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..reader import PAGE_READWRITE, PRIMARY_VIEW, SuspexError
from ..scan import _scan_range_impl
from ..view import MemoryView

if TYPE_CHECKING:
    from ..sdk import SuspexSDK


class MemApi:
    """Memory primitives with view dispatch plus a local chunked scanner
    that works for kernel ranges too (the agent Scan RPC is user-only)."""

    def __init__(self, sdk: "SuspexSDK") -> None:
        self._sdk = sdk

    def view(self, name: str = "") -> MemoryView:
        n = name or PRIMARY_VIEW
        client = self._sdk.clients.get(n)
        if client is None:
            raise SuspexError(f"view {n!r} not connected (have: {sorted(self._sdk.clients)})")
        return MemoryView(n, client)

    async def read(self, pid: int, address: int, size: int, space: str = "user",
                   view: str = "", allow_fault: bool = False) -> bytes:
        return await self.view(view).read(pid, address, size, space,
                                          allow_fault=allow_fault)

    async def write(self, pid: int, address: int, data: bytes, space: str = "user",
                    view: str = "") -> int:
        return await self.view(view).write(pid, address, data, space)

    async def alloc(self, pid: int, size: int, protect: int = PAGE_READWRITE,
                    kernel: bool = False, view: str = "") -> int:
        return await self.view(view).alloc(pid, size, protect, kernel)

    async def free(self, pid: int, address: int, kernel: bool = False, view: str = "") -> dict:
        return await self.view(view).free(pid, address, kernel)

    async def protect(self, pid: int, address: int, size: int, protect: int,
                      view: str = "") -> dict:
        return await self.view(view).protect(pid, address, size, protect)

    async def regions(self, pid: int, view: str = "") -> list[dict[str, Any]]:
        return await self.view(view).regions(pid)

    async def heaps(self, pid: int, want_blocks: bool = False, max_blocks: int = 0,
                    view: str = "") -> list[dict[str, Any]]:
        return await self.view(view).heaps(pid, want_blocks, max_blocks)

    # ------------------------------------------------- snapshot / diff ----

    async def snapshot(self, pid: int, ranges: list[tuple[int, int]] | None = None,
                       view: str = "", space: str = "user",
                       inline_max: int = 0x100000) -> dict[str, Any]:
        """Capture {sha256(+bytes when small)} of each [addr, size) range.

        Snapshot keys are "addr:size" strings; ranges omitted -> all committed
        regions of pid (region walk through the chosen view).
        """
        import hashlib

        v = self.view(view)
        if ranges is None:
            ranges = []
            for r in await v.regions(pid):
                base = int(r.get("base", 0), 0) if isinstance(r.get("base"), str) else r.get("base", 0)
                size = int(r.get("size", 0), 0) if isinstance(r.get("size"), str) else r.get("size", 0)
                state = int(r.get("state", 0), 0) if isinstance(r.get("state"), str) else r.get("state", 0)
                prot = int(r.get("protect", 0), 0) if isinstance(r.get("protect"), str) else r.get("protect", 0)
                if state == 0x1000 and prot not in (0x01, 0x100 | 0x01):
                    ranges.append((base, size))
        snap: dict[str, Any] = {}
        for base, size in ranges:
            h = hashlib.sha256()
            blob = bytearray() if size <= inline_max else None
            off = 0
            while off < size:
                n = min(0x100000, size - off)
                try:
                    data = await v.read(pid, base + off, n, space)
                except Exception:
                    break
                if not data:
                    break
                h.update(data)
                if blob is not None:
                    blob.extend(data)
                off += len(data)
            snap[f"{base:#x}:{size:#x}"] = {"sha256": h.hexdigest(), "bytes": bytes(blob) if blob is not None else None}
        return snap

    async def diff(self, snapshot: dict[str, Any], pid: int, view: str = "",
                   space: str = "user") -> list[dict[str, Any]]:
        """Re-read each snapshotted range; report changed ranges with first offsets."""
        import hashlib

        v = self.view(view)
        changes: list[dict[str, Any]] = []
        for key, entry in snapshot.items():
            base_s, size_s = key.split(":")
            base, size = int(base_s, 16), int(size_s, 16)
            h = hashlib.sha256()
            off = 0
            read = 0
            while off < size:
                n = min(0x100000, size - off)
                try:
                    data = await v.read(pid, base + off, n, space)
                except Exception:
                    break
                if not data:
                    break
                h.update(data)
                off += len(data)
                read += len(data)
            after = h.hexdigest()
            if after != entry["sha256"]:
                item: dict[str, Any] = {"range": key, "before": entry["sha256"], "after": after}
                if entry.get("bytes") is not None and read:
                    off2 = 0
                    diffs: list[int] = []
                    while off2 < min(len(entry["bytes"]), size):
                        n = min(0x100000, size - off2)
                        try:
                            data = await v.read(pid, base + off2, n, space)
                        except Exception:
                            break
                        before_chunk = entry["bytes"][off2:off2 + len(data)]
                        diffs.extend(off2 + i for i in range(min(len(data), len(before_chunk)))
                                     if data[i] != before_chunk[i])
                        if len(diffs) >= 64:
                            break
                        off2 += len(data)
                    item["changed_offsets"] = [hex(d) for d in diffs[:64]]
                changes.append(item)
        return changes

    async def scan_range(self, pid: int, address: int, size: int, pattern: bytes | str,
                         mask: str = "", view: str = "", space: str = "user",
                         chunk: int = 0x100000, max_results: int = 64) -> list[int]:
        hits, _telem = await _scan_range_impl(self.view(view), pid, address, size,
                                              pattern, mask, space, chunk, max_results)
        return hits
