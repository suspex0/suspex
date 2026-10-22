"""DbgApi: thin wrapper over the debug_manage RPCs on the primary view."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...agent_client import AgentClient
from ..reader import PRIMARY_VIEW

if TYPE_CHECKING:
    from ..sdk import SuspexSDK


class DbgApi:
    """Thin wrapper over the debug_manage actions on the primary view."""

    def __init__(self, sdk: "SuspexSDK") -> None:
        self._sdk = sdk

    def _client(self) -> AgentClient:
        return self._sdk.mem.view(PRIMARY_VIEW).client

    async def launch(self, cmdline: str, workdir: str = "", break_on_entry: bool = True) -> dict:
        return await self._client().debug_launch(cmdline, workdir, break_on_entry)

    async def attach(self, pid: int) -> dict:
        return await self._client().debug_attach(pid)

    async def detach(self, kill: bool = False) -> dict:
        return await self._client().debug_detach(kill)

    async def cont(self) -> dict:
        return await self._client().debug_continue()

    async def step(self, over: bool = False, count: int = 1) -> dict:
        return await self._client().debug_step(over, count)

    async def regs(self) -> dict:
        return await self._client().debug_regs()

    async def set_regs(self, **kwargs: Any) -> dict:
        return await self._client().debug_set_regs(**kwargs)

    async def threads(self) -> dict:
        return await self._client().debug_threads()

    async def stack(self, max_frames: int = 32) -> list[dict]:
        return await self._client().debug_stacktrace(max_frames)

    async def read(self, address: int, size: int) -> bytes:
        return await self._client().debug_read(address, size)

    async def write(self, address: int, data: bytes) -> dict:
        return await self._client().debug_write(address, data)
