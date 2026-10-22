"""Reader primitive: typed reads over any ``read(addr, size) -> bytes``
callable, plus shared module-level constants (view name, page protection
flags) and the SDK error type."""

from __future__ import annotations

from typing import Awaitable, Callable

ReadFn = Callable[[int, int], Awaitable[bytes]]

PAGE_READWRITE = 0x04

PRIMARY_VIEW = "kernel"


class SuspexError(RuntimeError):
    pass


# ---------------------------------------------------------------- Reader ----

class Reader:
    """Reads typed fields through a ``read(addr, size) -> bytes`` callable.
    Works over remote memory (sdk.mem.read) and local buffers alike."""

    def __init__(self, read: ReadFn) -> None:
        self._read = read

    async def read(self, addr: int, size: int) -> bytes:
        return await self._read(addr, size)

    async def u8(self, addr: int) -> int:
        data = await self._read(addr, 1)
        if len(data) < 1:
            raise SuspexError(f"short read at {hex(addr)}")
        return data[0]

    async def u16(self, addr: int) -> int:
        data = await self._read(addr, 2)
        if len(data) < 2:
            raise SuspexError(f"short read at {hex(addr)}")
        return int.from_bytes(data, "little")

    async def u32(self, addr: int) -> int:
        data = await self._read(addr, 4)
        if len(data) < 4:
            raise SuspexError(f"short read at {hex(addr)}")
        return int.from_bytes(data, "little")

    async def u64(self, addr: int) -> int:
        data = await self._read(addr, 8)
        if len(data) < 8:
            raise SuspexError(f"short read at {hex(addr)}")
        return int.from_bytes(data, "little")

    async def cstr(self, addr: int, max_len: int = 260) -> str:
        out = bytearray()
        while len(out) < max_len:
            try:
                chunk = await self._read(addr + len(out), 32)
            except Exception:
                break  # buffer/PTE end: settle for what we decoded
            if not chunk:
                break
            if 0 in chunk:
                out += chunk[: chunk.index(0)]
                break
            out += chunk
        return bytes(out).decode("utf-8", "replace")

    async def wstr(self, addr: int, max_chars: int = 260) -> str:
        out = bytearray()
        while len(out) < max_chars * 2:
            try:
                chunk = await self._read(addr + len(out), 64)
            except Exception:
                # Buffer/pool-page end: settle for what we decoded. The
                # agent surface raises bare RuntimeError for driver-level
                # read failures (gle=998 on an unmapped next page), not
                # SuspexError — catching only SuspexError here used to
                # crash whole walks on the last pool-page entry.
                break
            if not chunk:
                break
            for i in range(0, len(chunk) - 1, 2):
                if chunk[i] == 0 and chunk[i + 1] == 0:
                    out += chunk[:i]
                    return bytes(out).decode("utf-16-le", "replace")
            out += chunk[: len(chunk) // 2 * 2]
        return bytes(out).decode("utf-16-le", "replace")

def buffer_reader(data: bytes, base: int = 0) -> Reader:
    """A Reader over a local buffer addressed by absolute address ``base+off``.
    Reads past the end clamp to the buffer (string walks settle for the tail)."""

    async def read(addr: int, size: int) -> bytes:
        off = addr - base
        if off < 0 or off >= len(data):
            raise SuspexError(f"buffer read out of range: {hex(addr)} +{size}")
        return data[off : off + size]

    return Reader(read)
