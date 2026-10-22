"""ModsApi: module listing / lookup / IAT & export table."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..sdk import SuspexSDK


class ModsApi:
    def __init__(self, sdk: "SuspexSDK") -> None:
        self._sdk = sdk

    async def list(self, pid: int = 0, kernel: bool = False, view: str = "") -> list[dict]:
        return await self._sdk.mem.view(view).modules(pid, kernel)

    async def find(self, name: str, pid: int = 0, kernel: bool = False,
                   view: str = "") -> dict[str, Any] | None:
        want = name.lower()
        for m in await self.list(pid, kernel, view):
            n = str(m.get("name", "")).lower()
            if n == want or n.endswith("\\" + want) or n.startswith(want):
                out = dict(m)
                # normalize proto3-JSON 64-bit fields to ints for arithmetic
                for k in ("base", "size"):
                    v = out.get(k, 0)
                    out[k] = int(v, 0) if isinstance(v, str) else int(v)
                return out
        return None

    async def imports(self, pid: int, module: str, *, kernel: bool = False,
                      view: str = "") -> list[dict[str, Any]]:
        """Live IAT of `module` in `pid`. Each row includes resolved pointer,
        the module currently owning it, and a `hooked` flag (resolved outside
        the declared source DLL)."""
        return await self._sdk.mem.view(view).imports(pid, module, kernel)

    async def exports(self, pid: int, module: str, *, kernel: bool = False,
                      view: str = "") -> list[dict[str, Any]]:
        """Export table of `module` in `pid`, incl. forwarders."""
        return await self._sdk.mem.view(view).exports(pid, module, kernel)
