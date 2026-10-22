"""CodegenApi: thin wrapper over :mod:`suspex.codegen` for plugin use."""

from __future__ import annotations

from typing import Any


class CodegenApi:
    """Thin wrapper over :mod:`suspex.codegen` for plugin use.

    Every method raises :class:`suspex.codegen.CodegenUnavailable` on the
    first call when the ``codegen`` extra isn't installed. Nothing here
    talks to a target — all pure-compute over capstone / keystone.
    """

    def disasm(self, data: bytes, arch: str = "x64", *,
               syntax: str = "intel", address: int = 0,
               count: int = 64, detail: bool = False) -> list[dict[str, Any]]:
        from ...codegen import disasm as _disasm
        return _disasm(data, arch, syntax=syntax, address=address,
                        count=count, detail=detail)

    def assemble(self, code: str, arch: str = "x64", *,
                 address: int = 0) -> tuple[bytes, int, dict[str, int]]:
        from ...codegen import assemble as _assemble
        return _assemble(code, arch, address=address)
