"""ProcsApi: process listing and image-name lookup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..sdk import SuspexSDK


class ProcsApi:
    def __init__(self, sdk: "SuspexSDK") -> None:
        self._sdk = sdk

    async def list(self, view: str = "") -> list[dict[str, Any]]:
        return await self._sdk.mem.view(view).processes()

    async def find(self, image: str, view: str = "") -> list[dict[str, Any]]:
        want = image.lower()
        return [p for p in await self.list(view)
                if want in str(p.get("image_name", "")).lower()]
