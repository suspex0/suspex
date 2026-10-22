"""YaraApi: optional YARA scanning; no-op when yara-python is absent."""

from __future__ import annotations

from typing import Any

from ..reader import SuspexError


class YaraApi:
    """Optional YARA scanning (no-op error surfaces when yara-python is absent)."""

    def __init__(self) -> None:
        self._client = None

    def _mod(self):
        from ... import yara as yara_mod
        return yara_mod

    def available(self) -> bool:
        return self._mod().yara_available()

    def scan_bytes(self, data: bytes, rule_src: str) -> list[dict]:
        return self._mod().yara_scan_blob(data, rule_src)

    async def scan_module(self, pid: int, module: str, rule_src: str) -> list[dict]:
        if self._client is None:
            raise SuspexError("yara.scan_module requires the kernel view client")
        matches, err = await self._mod().yara_scan_module(self._client, pid, module, rule_src)
        if err:
            raise SuspexError(err)
        return matches

    def bind(self, client: Any) -> None:
        self._client = client
