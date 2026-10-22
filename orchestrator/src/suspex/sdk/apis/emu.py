"""EmuApi: thin wrapper over :mod:`suspex.emulate` for plugin use."""

from __future__ import annotations

from typing import Any


class EmuApi:
    """Thin wrapper over :mod:`suspex.emulate` for plugin use.

    Sessions are stored in the module-level registry; the caller owns
    the session id and passes it back on each method. ``close()``
    releases the emulator; a plugin should always close what it opens.
    """

    def create(self, *, arch: str = "x64", mode: str = "shellcode",
                engine: str = "speakeasy", flavor: str = "latest"):
        from ... import emulate as _emu
        return _emu.create_session(arch=arch, mode=mode, engine=engine,
                                    flavor=flavor)

    def get(self, session_id: str):
        from ... import emulate as _emu
        return _emu.get_session(session_id)

    def close(self, session_id: str) -> bool:
        from ... import emulate as _emu
        return _emu.close_session(session_id)

    def list(self) -> list[dict[str, Any]]:
        from ... import emulate as _emu
        return _emu.list_sessions()
