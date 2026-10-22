"""SuspexSDK: façade handed to plugins; composes the per-domain API
objects on top of the connected view clients."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent_client import AgentClient
from .apis.codegen import CodegenApi
from .apis.dbg import DbgApi
from .apis.emu import EmuApi
from .apis.findings import FindingsApi
from .apis.mem import MemApi
from .apis.mods import ModsApi
from .apis.procs import ProcsApi
from .apis.symbols import SymbolsApi
from .apis.yara import YaraApi
from .reader import PRIMARY_VIEW, SuspexError


class SuspexSDK:
    """Facade handed to plugins. Holds the connected view clients plus the
    findings ledger; APIs are plain attributes so scripts stay flat."""

    def __init__(self, clients: dict[str, AgentClient] | None = None, ledger: Any = None,
                 session_id: str = "", nt_build: int = 0,
                 symbols: SymbolsApi | None = None,
                 artifacts_dir: str = "") -> None:
        self.clients: dict[str, AgentClient] = clients or {}
        self.nt_build = nt_build
        self.symbols = symbols or SymbolsApi()
        # Canonical artifact root passed down from the orchestrator config.
        # Falls back to cwd-relative so ad-hoc SDK use still lands somewhere
        # predictable — plugins must prefer this over Path.cwd()/artifacts.
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir \
            else Path.cwd() / "artifacts"
        self.mem = MemApi(self)
        self.mods = ModsApi(self)
        self.procs = ProcsApi(self)
        self.dbg = DbgApi(self)
        self.findings = FindingsApi(ledger, session_id)
        self.yara = YaraApi()
        self.codegen = CodegenApi()
        self.emu = EmuApi()
        kernel = self.clients.get(PRIMARY_VIEW)
        if kernel is not None:
            self.yara.bind(kernel)

    async def close(self) -> None:
        for c in self.clients.values():
            await c.close()

    async def parity(self, pid: int, samples: int = 16, read_bytes: int = 4096,
                     seed: int = 0) -> dict[str, Any]:
        from ..parity import run_parity

        k = self.clients.get(PRIMARY_VIEW)
        u = self.clients.get("user")
        if k is None or u is None:
            raise SuspexError("parity needs both the kernel and user views connected")
        return await run_parity(k, u, pid, samples=samples, read_bytes=read_bytes, seed=seed)
