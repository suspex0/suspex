"""MemoryView: one named target view exposing the memory / module /
process primitives on top of an AgentClient."""

from __future__ import annotations

from typing import Any

from ..agent_client import AgentClient
from .reader import PAGE_READWRITE


# ------------------------------------------------------------------ APIs ----

class MemoryView:
    """One named target view: typed memory/module/process primitives."""

    def __init__(self, name: str, client: AgentClient) -> None:
        self.name = name
        self.client = client

    async def read(self, pid: int, address: int, size: int, space: str = "user",
                   allow_fault: bool = False) -> bytes:
        return await self.client.mem_read(pid, address, size, space,
                                          allow_fault=allow_fault)

    async def write(self, pid: int, address: int, data: bytes, space: str = "user") -> int:
        # v12: mem_write returns {"written_bytes", "write_path"} — the SDK
        # view keeps its int contract; write_path detail is available via
        # client.mem_write directly.
        return (await self.client.mem_write(pid, address, data, space))["written_bytes"]

    async def alloc(self, pid: int, size: int, protect: int = PAGE_READWRITE,
                    kernel: bool = False) -> int:
        return await self.client.mem_alloc(pid, size, protect, kernel)

    async def free(self, pid: int, address: int, kernel: bool = False) -> dict[str, Any]:
        return await self.client.mem_free(pid, address, kernel)

    async def protect(self, pid: int, address: int, size: int, protect: int) -> dict[str, Any]:
        return await self.client.mem_protect(pid, address, size, protect)

    async def regions(self, pid: int) -> list[dict[str, Any]]:
        return await self.client.debug_regions(pid)

    async def modules(self, pid: int = 0, kernel: bool = False) -> list[dict[str, Any]]:
        return await self.client.mem_modules(pid, kernel)

    async def imports(self, pid: int, module: str, kernel: bool = False) -> list[dict[str, Any]]:
        return await self.client.mem_imports(pid, module, kernel)

    async def exports(self, pid: int, module: str, kernel: bool = False) -> list[dict[str, Any]]:
        return await self.client.mem_exports(pid, module, kernel)

    async def heaps(self, pid: int, want_blocks: bool = False,
                    max_blocks: int = 0) -> list[dict[str, Any]]:
        return await self.client.mem_heaps(pid, want_blocks, max_blocks)

    async def processes(self) -> list[dict[str, Any]]:
        return await self.client.mem_processes()

    async def scan(self, pid: int, pattern: bytes, mask: str = "", base: int = 0,
                   size: int = 0, max_results: int = 64) -> list[int]:
        # 'H'/'L' nibble masks (parse_mask for '6?'/'?F') can't cross the
        # wire — the agent is byte-granular — so sdk.scan downgrades them
        # and post-verifies candidates via mem_read.
        from .scan import agent_pattern_scan
        return await agent_pattern_scan(
            self.client, pid, pattern, mask, base, size, max_results,
            "user")
